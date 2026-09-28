"""Size and memory caps: chunked bodies, oversize replies, deep JSON, bounded registries."""

from __future__ import annotations

import gzip
import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sealedrun_recorder.anchoring import Anchoring
from sealedrun_recorder.db import make_engine, session_factory
from sealedrun_recorder.keystore import load_identity
from sealedrun_recorder.limits import parse_json
from sealedrun_recorder.live import LiveRunError, LiveRuns
from sealedrun_recorder.proxy.core import MAX_OPEN_RUNS, RunGrouper
from sealedrun_recorder.proxy.mcp import ListSeen
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
  - name: planner
    url: http://agent.test/rpc
    location: local
"""
CHAT_REPLY = {
    "id": "chatcmpl-1",
    "object": "chat.completion",
    "model": "gpt-4.1",
    "choices": [
        {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}
    ],
    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
}
CHAT = {"model": "gpt-4.1", "messages": [{"role": "user", "content": "hi"}]}
MCP_CALL = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "add"}}
A2A_SEND = {"jsonrpc": "2.0", "id": 1, "method": "SendMessage", "params": {"message": {}}}
STEP = {"kind": "tool_call", "target": {"type": "tool", "name": "x"}, "outcome": "success"}
DEEP = b"[" * 100_000 + b"]" * 100_000


@pytest.fixture
def auth(secrets: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {secrets['token']}", "Content-Type": "application/json"}


def _chunks(payload: bytes, size: int = 7) -> Iterator[bytes]:
    for i in range(0, len(payload), size):
        yield payload[i : i + size]


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/v1/chat/completions", CHAT),
        ("/mcp/tools", MCP_CALL),
        ("/a2a/planner", A2A_SEND),
        ("/api/steps", STEP),
    ],
)
def test_chunked_body_past_the_cap_is_413_without_forwarding(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    path: str,
    body: dict[str, Any],
) -> None:
    padded = {**body, "padding": "x" * 4000}
    payload = json.dumps(padded).encode()
    with make_proxy(CONFIG, proxy_max_body_bytes=2048) as client:
        reply = client.post(path, content=_chunks(payload), headers=auth)
        assert reply.status_code == 413, reply.text
        small = client.post(path, content=_chunks(json.dumps(body).encode()), headers=auth)
        assert small.status_code != 413
    assert not any(b"padding" in call.content for call in upstream.calls)


def test_chunked_otlp_export_past_the_cap_is_413(
    make_proxy: Callable[..., TestClient], auth: dict[str, str]
) -> None:
    body = b'{"resourceSpans": [' + b" " * 3000 + b"]}"
    with make_proxy(CONFIG, proxy_max_body_bytes=2048) as client:
        reply = client.post(
            "/otlp/v1/traces",
            content=_chunks(body, 100),
            headers={**auth, "Content-Type": "application/json"},
        )
    assert reply.status_code == 413


def test_oversize_upstream_reply_is_502_and_recorded(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    huge = {**CHAT_REPLY, "padding": "y" * 5000}
    upstream.routes["/chat/completions"] = huge
    with make_proxy(CONFIG, proxy_max_body_bytes=4096) as client:
        reply = client.post("/v1/chat/completions", json=CHAT, headers=auth)
        assert reply.status_code == 502
        assert "size limit" in reply.json()["error"]["message"]
        [record] = [r for r in proxy_records(client) if r["kind"] == "llm_call"]
    assert record["outcome"] == "error"
    assert record["extensions"]["sealedrun.proxy"]["status"] == 502
    assert upstream.calls[0].headers["accept-encoding"] == "identity"


def test_compressed_upstream_reply_is_capped_by_its_real_size(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str]
) -> None:
    body = json.dumps({**CHAT_REPLY, "padding": "z" * 20000}).encode()
    packed = gzip.compress(body)
    assert len(packed) < 1024 < len(body)

    def zipped(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=packed,
            headers={"content-encoding": "gzip", "content-type": "application/json"},
        )

    upstream.routes["/chat/completions"] = zipped
    with make_proxy(CONFIG, proxy_max_body_bytes=4096) as client:
        assert client.post("/v1/chat/completions", json=CHAT, headers=auth).status_code == 502
    with make_proxy(CONFIG, proxy_max_body_bytes=40000) as client:
        reply = client.post("/v1/chat/completions", json=CHAT, headers=auth)
        assert reply.status_code == 200
        assert reply.json()["padding"].startswith("zzz")


def test_oversize_mcp_and_a2a_replies_are_502_and_marked_truncated(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/mcp"] = {"jsonrpc": "2.0", "id": 1, "result": {"content": "q" * 5000}}
    upstream.routes["/rpc"] = {"jsonrpc": "2.0", "id": 1, "result": {"task": {"x": "q" * 5000}}}
    with make_proxy(CONFIG, proxy_max_body_bytes=4096) as client:
        mcp = client.post("/mcp/tools", json=MCP_CALL, headers=auth)
        a2a = client.post("/a2a/planner", json=A2A_SEND, headers=auth)
        records = [r for r in proxy_records(client) if r["kind"] == "tool_call"]
    assert mcp.status_code == 502 and mcp.json()["error"]["code"] == 40000
    assert a2a.status_code == 502 and a2a.json()["error"]["code"] == 40000
    assert [r["outcome"] for r in records] == ["error", "error"]
    assert all(r["extensions"]["sealedrun.proxy"]["truncated"] for r in records)


def test_oversize_agent_card_is_502(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str]
) -> None:
    upstream.routes["/.well-known/agent-card.json"] = {"name": "big", "pad": "c" * 5000}
    with make_proxy(CONFIG, proxy_max_body_bytes=4096) as client:
        reply = client.get("/a2a/planner/.well-known/agent-card.json", headers=auth)
    assert reply.status_code == 502


@pytest.mark.parametrize(
    ("path", "media"),
    [
        ("/v1/chat/completions", "application/json"),
        ("/mcp/tools", "application/json"),
        ("/api/steps", "application/json"),
        ("/otlp/v1/traces", "application/json"),
    ],
)
def test_deeply_nested_json_is_400_not_500(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    path: str,
    media: str,
) -> None:
    upstream.routes["/mcp"] = {"jsonrpc": "2.0", "id": 1, "result": {}}
    with make_proxy(CONFIG) as client:
        reply = client.post(path, content=DEEP, headers={**auth, "Content-Type": media})
    if path == "/mcp/tools":
        # Not a JSON-RPC object the proxy reads: forwarded like any other unparseable line.
        assert reply.status_code == 200, reply.text
    else:
        assert reply.status_code == 400, reply.text


def test_parse_json_turns_recursion_into_value_error() -> None:
    with pytest.raises(ValueError, match="nesting"):
        parse_json(DEEP)
    assert parse_json(b'{"a": 1}') == {"a": 1}


def test_oversize_otlp_span_count_is_413(
    make_proxy: Callable[..., TestClient], auth: dict[str, str], otlp_export: Any
) -> None:
    spans = [
        {"name": f"execute_tool t{i}", "attributes": {"gen_ai.tool.name": "t"}} for i in range(2001)
    ]
    export = otlp_export(spans)
    with make_proxy(CONFIG) as client:
        reply = client.post(
            "/otlp/v1/traces",
            content=export.SerializeToString(),
            headers={**auth, "Content-Type": "application/x-protobuf"},
        )
    assert reply.status_code == 413
    assert "2000 spans" in reply.text


def test_bundle_upload_declared_over_the_cap_is_413_before_reading(
    tmp_path: Path, valid_zip: bytes
) -> None:
    settings = Settings(data_dir=tmp_path, ui_dir=tmp_path / "no-ui", max_bundle_bytes=1024)
    from sealedrun_recorder.main import create_app

    with TestClient(create_app(settings), base_url="http://localhost") as client:
        reply = client.post(
            "/api/bundles",
            files={"file": ("bundle.zip", valid_zip, "application/zip")},
            headers={"Sec-Fetch-Site": "same-origin"},
        )
        assert reply.status_code == 413
        assert client.app.state.settings.max_bundle_bytes == 1024  # type: ignore[attr-defined]
    assert Settings(data_dir=tmp_path).max_bundle_bytes == 64 * 1024 * 1024


def _live(tmp_path: Path) -> LiveRuns:
    return LiveRuns(
        session_factory(make_engine(f"sqlite:///{tmp_path / 'db.sqlite'}")), load_identity(tmp_path)
    )


def test_labelled_runs_idle_close_like_the_default_run(tmp_path: Path) -> None:
    live = _live(tmp_path)
    now = [0.0]
    runs = RunGrouper(live, idle_seconds=10, clock=lambda: now[0])
    first = runs.run_for("nightly")
    now[0] = 9
    assert runs.run_for("nightly") == first
    now[0] = 30
    second = runs.run_for("nightly")
    assert second != first
    with pytest.raises(LiveRunError, match="closed"):
        live.append(first, "note", target={"type": "none", "name": "late"})
    assert live.head(second)[2] == "run_start"


def test_run_registry_is_bounded_and_evicted_runs_are_ended(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sealedrun_recorder.proxy.core as core

    monkeypatch.setattr(core, "MAX_OPEN_RUNS", 3)
    live = _live(tmp_path)
    runs = RunGrouper(live, idle_seconds=1000)
    ids = [runs.run_for(f"label-{i}") for i in range(4)]
    assert len(runs._runs) == 3
    with pytest.raises(LiveRunError, match="closed"):
        live.append(ids[0], "note", target={"type": "none", "name": "late"})
    assert runs.run_for("label-3") == ids[3]
    assert MAX_OPEN_RUNS == 1024


def test_tools_list_memory_is_bounded() -> None:
    seen = ListSeen(limit=2)
    for i in range(3):
        seen.remember((f"run-{i}", "s", "http", None), {"tools": []})
    assert seen.changed(("run-0", "s", "http", None), {"tools": []})
    assert not seen.changed(("run-2", "s", "http", None), {"tools": []})


def test_writers_and_locks_are_bounded_and_dropped_on_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sealedrun_recorder.live as live_module

    monkeypatch.setattr(live_module, "MAX_WRITERS", 2)
    live = _live(tmp_path)
    ids = [str(live.start()["run_id"]) for _ in range(3)]
    assert len(live._writers) == 2
    record = live.append(ids[0], "note", target={"type": "none", "name": "resumed"})
    assert record["seq"] == 1
    live.end(ids[0])
    assert ids[0] not in live._writers and ids[0] not in live._locks
    for run_id in ids[1:]:
        live.end(run_id)
    assert not live._writers


def test_anchoring_forgets_idle_locks(tmp_path: Path) -> None:
    live = _live(tmp_path)
    settings = Settings(data_dir=tmp_path, anchor_tsa_url="http://tsa.test/api/v1/timestamp")
    anchoring = Anchoring(
        live,
        httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(500))),
        settings,
    )
    import asyncio

    run_id = str(live.start()["run_id"])
    assert asyncio.run(anchoring.anchor_run(run_id)) == []
    assert anchoring._busy == {}
