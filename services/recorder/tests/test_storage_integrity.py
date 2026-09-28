"""Storage integrity: stored delegations stay, the chain head follows the store, anchoring lives."""

from __future__ import annotations

import asyncio
import io
import logging
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sealedrun import RunWriter, create_delegation, verify_run, write_bundle
from sealedrun.keys import PrivateKeySet
from sealedrun_recorder.anchoring import Anchoring
from sealedrun_recorder.db import DelegationRow, make_engine, session_factory
from sealedrun_recorder.keystore import load_identity
from sealedrun_recorder.live import LiveRunError, LiveRuns
from sealedrun_recorder.settings import Settings

CONFIG = """
upstreams:
  - name: cloudai
    url: https://cloud.example/v1
    dialect: openai
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["gpt-*"]
mcp_servers:
  - name: tools
    url: http://mcp.test/mcp
    location: local
a2a_agents:
  - name: hosted
    url: https://agent.example/rpc
    location: cloud
"""


def _live(tmp_path: Path) -> LiveRuns:
    return LiveRuns(
        session_factory(make_engine(f"sqlite:///{tmp_path / 'db.sqlite'}")), load_identity(tmp_path)
    )


def _bundle_with(
    delegation: dict[str, Any], agent: PrivateKeySet, principal: PrivateKeySet
) -> bytes:
    writer = RunWriter(agent, delegation)
    writer.start()
    writer.append("note", target={"type": "none", "name": "imported"})
    writer.end()
    out = io.BytesIO()
    write_bundle(
        out,
        exporter=agent,
        software="test/0",
        delegations=[delegation],
        runs=[writer.records],
        principal=principal,
    )
    return out.getvalue()


def test_uploaded_bundle_cannot_replace_the_recorders_delegation(
    make_proxy: Callable[..., TestClient], secrets: dict[str, str], tmp_path: Path
) -> None:
    from sealedrun.keys import PrivateKeySet

    headers = {"Authorization": f"Bearer {secrets['token']}", "Sec-Fetch-Site": "same-origin"}
    with make_proxy(CONFIG) as client:
        identity = client.app.state.live.identity  # type: ignore[attr-defined]
        own = identity.delegation
        # An attacker reads the public delegation id and signs their own delegation under it.
        principal = PrivateKeySet.generate(
            own["profile"] if "profile" in own else "sealedrun-hybrid-1"
        )
        agent = PrivateKeySet.generate(principal.public.profile)
        forged = create_delegation(
            principal, agent.public, agent_name="evil", delegation_id=own["delegation_id"]
        )
        reply = client.post(
            "/api/bundles",
            files={"file": ("b.zip", _bundle_with(forged, agent, principal), "application/zip")},
            headers=headers,
        )
        assert reply.status_code == 422, reply.text
        assert reply.json()["detail"]["check"] == "delegation"
        with client.app.state.sessions() as session:  # type: ignore[attr-defined]
            row = session.get(DelegationRow, own["delegation_id"])
            assert row is not None and row.document == own
        # The recorder's own runs still verify and export.
        run_id = str(client.app.state.live.start()["run_id"])  # type: ignore[attr-defined]
        export = client.post(f"/api/runs/{run_id}/export", params={"end": True}, headers=headers)
        assert export.status_code == 200
        # A bundle carrying the very same delegation document is fine.
        same = _bundle_with(own, identity.agent, identity.principal)
        reply = client.post(
            "/api/bundles", files={"file": ("b.zip", same, "application/zip")}, headers=headers
        )
        assert reply.status_code == 201, reply.text


def test_failed_store_leaves_the_chain_head_in_step(tmp_path: Path) -> None:
    live = _live(tmp_path)
    run_id = str(live.start()["run_id"])
    live.append(run_id, "note", target={"type": "none", "name": "first"})
    real_factory = live._sessions

    class BoomError(Exception):
        pass

    class FailingSession:
        def __init__(self) -> None:
            self.inner = real_factory()

        def __enter__(self) -> Any:
            self.inner.__enter__()
            return self

        def __exit__(self, *args: Any) -> Any:
            return self.inner.__exit__(*args)

        def __getattr__(self, name: str) -> Any:
            return getattr(self.inner, name)

        def commit(self) -> None:
            raise BoomError("disk full")

    live._sessions = FailingSession  # type: ignore[assignment]
    with pytest.raises(LiveRunError, match="not stored: BoomError"):
        live.append(run_id, "note", target={"type": "none", "name": "lost"})
    with pytest.raises(LiveRunError, match="not stored: BoomError"):
        live.end(run_id)
    live._sessions = real_factory
    record = live.append(run_id, "note", target={"type": "none", "name": "after"})
    assert record["seq"] == 2
    seq, head, kind = live.head(run_id)
    assert (seq, head, kind) == (2, record["hash"], "note")
    live.end(run_id)
    with live._sessions() as session:
        from sealedrun_recorder.db import RecordRow
        from sqlalchemy import select

        rows = session.scalars(
            select(RecordRow).where(RecordRow.run_id == run_id).order_by(RecordRow.seq)
        ).all()
    records = [r.document for r in rows]
    assert [r["target"]["name"] for r in records] == ["run", "first", "after", "run"]
    verify_run(records, {live.identity.delegation["delegation_id"]: live.identity.delegation})


def test_target_text_that_does_not_fit_the_row_is_refused(
    make_proxy: Callable[..., TestClient], secrets: dict[str, str], upstream: Any, tmp_path: Path
) -> None:
    live = _live(tmp_path)
    run_id = str(live.start()["run_id"])
    with pytest.raises(LiveRunError, match=r"target\.name longer than 256"):
        live.append(run_id, "note", target={"type": "none", "name": "n" * 257})
    assert live.head(run_id)[0] == 0

    bearer = {"Authorization": f"Bearer {secrets['token']}"}
    long_name = "t" * 300
    with make_proxy(CONFIG) as client:
        step = {"kind": "tool_call", "target": {"type": "tool", "name": long_name}}
        reply = client.post("/api/steps", json=step, headers=bearer)
        assert reply.status_code == 400
        assert "target/name" in reply.text
        upstream.routes["/mcp"] = {"jsonrpc": "2.0", "id": 1, "result": {}}
        call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": long_name}}
        reply = client.post("/mcp/tools", json=call, headers=bearer)
        assert reply.status_code == 400
        rpc = {"jsonrpc": "2.0", "id": 1, "method": "m" * 201, "params": {}}
        assert client.post("/a2a/hosted", json=rpc, headers=bearer).status_code == 400
        assert client.put(f"/a2a/hosted/{'p' * 300}", json={}, headers=bearer).status_code == 400
    assert upstream.calls == []


def test_otlp_target_text_is_cut_to_the_row(
    make_proxy: Callable[..., TestClient],
    secrets: dict[str, str],
    otlp_export: Any,
    proxy_records: Any,
) -> None:
    export = otlp_export(
        [
            {
                "name": "execute_tool " + "x" * 400,
                "attributes": {
                    "gen_ai.tool.name": "y" * 400,
                    "gen_ai.provider.name": "p" * 400,
                    "server.address": "s" * 3000,
                },
            }
        ]
    )
    headers = {
        "Authorization": f"Bearer {secrets['token']}",
        "Content-Type": "application/x-protobuf",
    }
    with make_proxy(CONFIG) as client:
        reply = client.post("/otlp/v1/traces", content=export.SerializeToString(), headers=headers)
        assert reply.status_code == 200, reply.text
        [record] = [r for r in proxy_records(client) if r["kind"] == "tool_call"]
    target = record["target"]
    assert (len(target["name"]), len(target["provider"]), len(target["endpoint"])) == (
        256,
        256,
        2048,
    )


def test_anchoring_loop_survives_a_failing_run(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    live = _live(tmp_path)
    settings = Settings(
        data_dir=tmp_path, anchor_tsa_url="http://tsa.test/t", anchor_interval_seconds=0.01
    )
    http = httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    anchoring = Anchoring(live, http, settings)
    calls: list[str] = []

    async def exploding(run_id: str) -> list[dict[str, Any]]:
        calls.append(run_id)
        if len(calls) == 1:
            raise RuntimeError("database went away")
        return []

    anchoring.anchor_run = exploding  # type: ignore[method-assign]
    live.start()

    async def drive() -> None:
        task = asyncio.create_task(anchoring.loop())
        for _ in range(200):
            await asyncio.sleep(0.01)
            if len(calls) >= 3:
                break
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    with caplog.at_level(logging.ERROR, logger="sealedrun.anchoring"):
        asyncio.run(drive())
    assert len(calls) >= 3
    assert "database went away" in caplog.text


def test_stream_record_failure_is_logged_and_the_client_keeps_its_stream(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    secrets: dict[str, str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    chunks = [
        b'data: {"id":"c","choices":[{"delta":{"content":"hi"},"index":0}]}\n\n',
        b"data: [DONE]\n\n",
    ]

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self) -> AsyncIterator[bytes]:
            for chunk in chunks:
                yield chunk

    upstream.routes["/chat/completions"] = lambda r: httpx.Response(
        200, headers={"content-type": "text/event-stream"}, stream=Stream()
    )
    body = {"model": "gpt-4.1", "messages": [{"role": "user", "content": "hi"}], "stream": True}
    with make_proxy(CONFIG) as client:
        runs = client.app.state.runs  # type: ignore[attr-defined]

        def failing(*args: Any, **kwargs: Any) -> dict[str, Any]:
            raise LiveRunError("store is gone")

        runs.record = failing
        with caplog.at_level(logging.ERROR, logger="sealedrun.proxy"):
            reply = client.post(
                "/v1/chat/completions",
                json=body,
                headers={"Authorization": f"Bearer {secrets['token']}"},
            )
    assert reply.status_code == 200
    assert reply.content == b"".join(chunks)
    assert "not recorded after" in caplog.text
