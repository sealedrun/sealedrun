import json
import time
from collections.abc import Callable, Iterator
from datetime import UTC, timedelta
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sealedrun import read_bundle, verify_bundle
from sealedrun.timeutil import format_timestamp, parse_timestamp
from sealedrun_recorder import api, export
from sealedrun_recorder.db import RunRow

from .conftest import PROXY_TOKEN

CONFIG = "upstreams: []\n"
AUTH = {"Authorization": f"Bearer {PROXY_TOKEN}"}
STEP = {
    "kind": "tool_call",
    "target": {"type": "tool", "name": "add", "location": "local"},
    "outcome": "success",
    "request": json.dumps({"a": 1, "b": 2}),
    "response": json.dumps({"sum": 3}),
    "request_media_type": "application/json",
    "response_media_type": "application/json",
}


@pytest.fixture
def recorder(make_proxy: Callable[..., TestClient]) -> Iterator[TestClient]:
    with make_proxy(CONFIG) as client:
        yield client


def _step(client: TestClient, label: str) -> str:
    """Record one step in the run labelled `label` and return that run's id."""
    reply = client.post("/api/steps", json=STEP, headers={**AUTH, "X-SealedRun-Run": label})
    assert reply.status_code == 201, reply.text
    return str(reply.json()["run_id"])


def _records(client: TestClient, run_id: str) -> list[dict[str, Any]]:
    return list(client.get(f"/api/runs/{run_id}/records", headers=AUTH).json())


def _later(stamp: str, **delta: float) -> str:
    return format_timestamp(parse_timestamp(stamp) + timedelta(**delta))


def _three_runs(client: TestClient) -> tuple[str, str, str, dict[str, str]]:
    """Record a run closed before the window, one that crosses its start and one inside it."""
    before = _step(client, "old-agent")
    client.app.state.live.end(before)  # type: ignore[attr-defined]
    crossing = _step(client, "crossing-agent")
    time.sleep(0.01)
    assert _step(client, "crossing-agent") == crossing
    inside = _step(client, "billing-agent")
    _step(client, "billing-agent")
    since = _records(client, crossing)[2]["occurred_at"]
    return before, crossing, inside, {"since": since, "until": _later(since, hours=1)}


def test_window_export_holds_every_run_with_a_record_inside(recorder: TestClient) -> None:
    before, crossing, inside, window = _three_runs(recorder)
    reply = recorder.post("/api/export", params=window, headers=AUTH)
    assert reply.status_code == 200, reply.text
    assert reply.headers["content-type"] == "application/zip"
    assert reply.headers["content-disposition"].startswith(
        'attachment; filename="sealedrun-window-'
    )
    principal = recorder.get("/api/identity", headers=AUTH).json()["principal_id"]
    bundle = read_bundle(reply.content)
    report = verify_bundle(bundle, [principal])
    assert [run.run_id for run in report.runs] == [crossing, inside]
    assert before not in bundle.runs
    assert report.query == window
    assert report.outside_window == {crossing: 2, inside: 0}
    assert [run.complete for run in report.runs] == [False, False]
    assert bundle.runs[crossing] == _records(recorder, crossing)
    assert len(bundle.payloads) == 2
    assert len(bundle.delegations) == 1


def test_window_export_by_label_with_a_note(recorder: TestClient) -> None:
    _, _, inside, window = _three_runs(recorder)
    asked = {**window, "label": "billing-agent", "note": "INC-42, asked by on-call"}
    reply = recorder.post("/api/export", params=asked, headers=AUTH)
    assert reply.status_code == 200, reply.text
    report = verify_bundle(read_bundle(reply.content))
    assert [run.run_id for run in report.runs] == [inside]
    assert report.query == asked
    none = recorder.post("/api/export", params={**window, "label": "no-such"}, headers=AUTH)
    assert none.status_code == 404
    part = recorder.post("/api/export", params={**window, "label": "billing"}, headers=AUTH)
    assert part.status_code == 404


def test_window_bounds_are_since_inclusive_until_exclusive(recorder: TestClient) -> None:
    run_id = _step(recorder, "billing-agent")
    first, last = (r["occurred_at"] for r in _records(recorder, run_id)[:2])
    exact = {"since": last, "until": _later(last, milliseconds=1)}
    assert recorder.post("/api/export", params=exact, headers=AUTH).status_code == 200
    ends_at_first = {"since": _later(first, hours=-1), "until": first}
    assert recorder.post("/api/export", params=ends_at_first, headers=AUTH).status_code == 404
    after = {"since": _later(last, milliseconds=1), "until": _later(last, hours=1)}
    assert recorder.post("/api/export", params=after, headers=AUTH).status_code == 404


def test_window_accepts_any_time_zone_and_signs_utc(recorder: TestClient) -> None:
    run_id = _step(recorder, "billing-agent")
    start = parse_timestamp(_records(recorder, run_id)[0]["occurred_at"])
    asked = {
        "since": (start - timedelta(minutes=1)).astimezone(UTC).strftime("%Y-%m-%dT%H:%MZ"),
        "until": (start + timedelta(hours=3)).isoformat().replace("+00:00", "+02:00"),
    }
    reply = recorder.post("/api/export", params=asked, headers=AUTH)
    assert reply.status_code == 200, reply.text
    query = verify_bundle(read_bundle(reply.content)).query
    assert query is not None
    assert query["since"] == format_timestamp(
        (start - timedelta(minutes=1)).replace(second=0, microsecond=0)
    )
    assert query["until"] == format_timestamp(start + timedelta(hours=1))


@pytest.mark.parametrize(
    "params",
    [
        {"since": "2026-11-11T06:00:00Z"},
        {"since": "2026-11-11T06:00:00", "until": "2026-11-11T07:00:00Z"},
        {"since": "2026-11-11T07:00:00Z", "until": "2026-11-11T07:00:00Z"},
        {"since": "2026-11-11T08:00:00Z", "until": "2026-11-11T07:00:00Z"},
        {"since": "2026-11-11T06:00:00Z", "until": "2026-11-11T07:00:00Z", "label": "a b"},
        {"since": "2026-11-11T06:00:00Z", "until": "2026-11-11T07:00:00Z", "note": "a\x1b[2Kb"},
        {"since": "2026-11-11T06:00:00Z", "until": "2026-11-11T07:00:00Z", "note": "x" * 257},
        {"since": "2026-11-11T06:00:00Z", "until": "2026-11-11T07:00:00Z", "payloads": "all"},
    ],
)
def test_window_export_refuses_bad_parameters(recorder: TestClient, params: dict[str, str]) -> None:
    _step(recorder, "billing-agent")
    assert recorder.post("/api/export", params=params, headers=AUTH).status_code == 422


def test_window_export_needs_the_token(recorder: TestClient) -> None:
    _, _, _, window = _three_runs(recorder)
    assert recorder.post("/api/export", params=window).status_code == 401


def test_window_export_without_payloads(recorder: TestClient) -> None:
    _, _, _, window = _three_runs(recorder)
    reply = recorder.post("/api/export", params={**window, "payloads": "omit"}, headers=AUTH)
    assert reply.status_code == 200, reply.text
    assert reply.headers["content-disposition"].endswith('-records.zip"')
    bundle = read_bundle(reply.content)
    assert bundle.payloads == {}
    report = verify_bundle(bundle)
    assert report.payloads_omitted is True
    assert len(report.runs) == 2


def test_imported_runs_are_not_exported(recorder: TestClient, valid_zip: bytes) -> None:
    stored = recorder.post(
        "/api/bundles", files={"file": ("b.zip", valid_zip, "application/zip")}, headers=AUTH
    )
    assert stored.status_code == 201, stored.text
    day = {"since": "2026-09-16T00:00:00Z", "until": "2026-09-17T00:00:00Z"}
    assert recorder.post("/api/export", params=day, headers=AUTH).status_code == 404


def test_more_runs_than_a_bundle_holds_is_refused(
    recorder: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    _, _, _, window = _three_runs(recorder)
    monkeypatch.setattr(export, "MAX_RUNS", 1)
    monkeypatch.setattr(api, "MAX_RUNS", 1)
    reply = recorder.post("/api/export", params=window, headers=AUTH)
    assert reply.status_code == 413
    assert "2 runs match and a bundle holds at most 1" in reply.json()["detail"]


def test_runs_with_different_hash_algorithms_are_refused(recorder: TestClient) -> None:
    _, crossing, _, window = _three_runs(recorder)
    with recorder.app.state.live._sessions() as session:  # type: ignore[attr-defined]
        session.get(RunRow, crossing).hash_alg = "sha3-256"
        session.commit()
    reply = recorder.post("/api/export", params=window, headers=AUTH)
    assert reply.status_code == 409
    assert "different hash algorithms" in reply.json()["detail"]
