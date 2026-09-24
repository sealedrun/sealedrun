import json
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sealedrun import VerificationError, verify_run
from sealedrun_recorder.db import RecordRow, RunRow, make_engine, session_factory
from sealedrun_recorder.keystore import load_identity
from sealedrun_recorder.live import LiveRunError, LiveRuns
from sealedrun_recorder.main import create_app
from sealedrun_recorder.settings import Settings
from sqlalchemy import select


def _live(tmp_path: Path) -> LiveRuns:
    sessions = session_factory(make_engine(f"sqlite:///{tmp_path / 'db.sqlite'}"))
    return LiveRuns(sessions, load_identity(tmp_path))


def _records(live: LiveRuns, run_id: str) -> list[dict]:  # type: ignore[type-arg]
    with live._sessions() as session:
        rows = session.scalars(
            select(RecordRow).where(RecordRow.run_id == run_id).order_by(RecordRow.seq)
        )
        return [r.document for r in rows]


def _verify(live: LiveRuns, run_id: str) -> None:
    delegation = live.identity.delegation
    verify_run(_records(live, run_id), {delegation["delegation_id"]: delegation})


def test_keys_created_once_with_private_modes(tmp_path: Path) -> None:
    first = load_identity(tmp_path)
    key_dir = tmp_path / "keys"
    assert stat.S_IMODE(os.stat(key_dir).st_mode) == 0o700
    for name in ("principal.json", "agent.json", "delegation.json"):
        assert stat.S_IMODE(os.stat(key_dir / name).st_mode) == 0o600
    second = load_identity(tmp_path)
    assert second.agent_id == first.agent_id
    assert second.principal_id == first.principal_id
    assert second.delegation == first.delegation


def test_expired_delegation_is_reissued(tmp_path: Path) -> None:
    first = load_identity(tmp_path)
    path = tmp_path / "keys" / "delegation.json"
    doc = json.loads(path.read_text())
    doc["not_after"] = "2000-01-01T00:00:00.000Z"
    path.write_text(json.dumps(doc))
    second = load_identity(tmp_path)
    assert second.delegation["delegation_id"] != first.delegation["delegation_id"]
    assert second.agent_id == first.agent_id


def test_concurrent_appends_keep_a_valid_chain(tmp_path: Path) -> None:
    live = _live(tmp_path)
    run_id = live.start()["run_id"]

    def call(i: int) -> None:
        live.append(
            run_id,
            "llm_call",
            target={"type": "model", "name": f"m{i}", "location": "cloud"},
            request=f"req {i}".encode(),
            response=f"res {i}".encode(),
            data_labels=["internal"],
        )

    with ThreadPoolExecutor(8) as pool:
        list(pool.map(call, range(40)))
    live.end(run_id)
    records = _records(live, run_id)
    assert [r["seq"] for r in records] == list(range(42))
    _verify(live, run_id)
    with live._sessions() as session:
        run = session.get(RunRow, run_id)
        assert run is not None
        assert run.record_count == 42
        assert run.complete is True
        assert run.last_hash == records[-1]["hash"]
        assert run.labels_sent_to_cloud == {"internal": 40}


def test_restart_continues_the_chain(tmp_path: Path) -> None:
    live = _live(tmp_path)
    run_id = live.start()["run_id"]
    live.append(run_id, "tool_call", target={"type": "tool", "name": "read"})
    resumed = _live(tmp_path)
    assert run_id not in resumed._writers
    resumed.append(run_id, "tool_call", target={"type": "tool", "name": "write"})
    resumed.end(run_id)
    records = _records(resumed, run_id)
    assert [r["seq"] for r in records] == [0, 1, 2, 3]
    assert records[2]["prev_hash"] == records[1]["hash"]
    _verify(resumed, run_id)
    with pytest.raises(LiveRunError):
        resumed.append(run_id, "tool_call", target={"type": "tool", "name": "late"})


def test_tampered_row_fails_verification(tmp_path: Path) -> None:
    live = _live(tmp_path)
    run_id = live.start()["run_id"]
    live.append(run_id, "tool_call", target={"type": "tool", "name": "read"})
    live.end(run_id)
    with live._sessions() as session:
        row = session.scalars(
            select(RecordRow).where(RecordRow.run_id == run_id, RecordRow.seq == 1)
        ).one()
        doc = dict(row.document)
        doc["target"] = {"type": "tool", "name": "delete"}
        row.document = doc
        session.commit()
    with pytest.raises(VerificationError):
        _verify(live, run_id)


def test_identity_endpoint_and_live_runs_listed(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path, ui_dir=tmp_path / "no-ui")
    with TestClient(create_app(settings), base_url="http://localhost") as client:
        identity = client.get("/api/identity").json()
        assert identity["delegation"]["agent_id"] == identity["agent_id"]
        assert "seed" not in json.dumps(identity)
        run_id = client.app.state.live.start()["run_id"]  # type: ignore[attr-defined]
        run = client.get(f"/api/runs/{run_id}").json()
        assert run["source"] == "live"
        assert run["bundle_id"] is None
        assert run["complete"] is False
