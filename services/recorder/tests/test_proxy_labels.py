"""Data labels supplied through `X-SealedRun-Labels` on every recorded channel."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sealedrun import verify_run
from sealedrun.schema import validate_extensions
from sealedrun_recorder.proxy.labels import LabelsError, header_labels

CONFIG = """
upstreams:
  - name: cloudai
    url: https://cloud.example/v1
    dialect: openai
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["gpt-*"]
  - name: local
    url: http://ollama.test
    dialect: ollama
    location: local
    models: ["qwen*"]
mcp_servers:
  - name: tools
    url: http://mcp.test/mcp
    location: local
a2a_agents:
  - name: planner
    url: http://agent.test/rpc
    location: local
"""
SSE = "text/event-stream"
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
MCP_CALL = {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "add"}}
MCP_RESULT = {"jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": "3"}]}}
A2A_CALL = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "SendMessage",
    "params": {"message": {"messageId": "m-1", "role": "ROLE_USER", "parts": [{"text": "hi"}]}},
}
A2A_RESULT = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {"task": {"id": "t-1", "status": {"state": "TASK_STATE_COMPLETED"}}},
}
STEP = {
    "kind": "note",
    "target": {"type": "none", "name": "planner", "location": "local"},
    "request": "thinking",
}
LABELLED = {"X-SealedRun-Labels": "pii, nda,pii"}


class _Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            yield chunk


class _Request:
    def __init__(self, value: str | None) -> None:
        self.headers = {} if value is None else {"x-sealedrun-labels": value}


def test_header_parsing() -> None:
    assert header_labels(_Request(None)) == []  # type: ignore[arg-type]
    assert header_labels(_Request("nda, pii ,acme:tier-1, nda")) == [  # type: ignore[arg-type]
        "acme:tier-1",
        "nda",
        "pii",
    ]
    for bad in ("", "nda,", "NDA", "a b", "a:b:c", ",".join(f"l{i}" for i in range(65))):
        with pytest.raises(LabelsError):
            header_labels(_Request(bad))  # type: ignore[arg-type]


@pytest.fixture
def auth(secrets: dict[str, str]) -> dict[str, str]:
    return {"X-SealedRun-Token": secrets["token"], "Content-Type": "application/json"}


@pytest.fixture
def api(secrets: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {secrets['token']}"}


def _labelled(records: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    [record] = [r for r in records if r["kind"] == kind]
    assert record["data_labels"] == ["nda", "pii"]
    assert record["extensions"]["sealedrun.labels"] == {
        "nda": {"source": "header"},
        "pii": {"source": "header"},
    }
    assert validate_extensions(record["extensions"]) == []
    return record


def _verified(client: TestClient, api: dict[str, str], records: list[dict[str, Any]]) -> None:
    delegation = client.get("/api/identity", headers=api).json()["delegation"]
    verify_run(records, {delegation["delegation_id"]: delegation})


def test_llm_call_carries_header_labels(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    api: dict[str, str],
    proxy_records: Any,
) -> None:
    upstream.routes["/chat/completions"] = CHAT_REPLY
    with make_proxy(CONFIG) as client:
        reply = client.post("/v1/chat/completions", json=CHAT, headers={**auth, **LABELLED})
        assert reply.status_code == 200, reply.text
        records = proxy_records(client)
        _labelled(records, "llm_call")
        _verified(client, api, records)
        assert "x-sealedrun-labels" not in upstream.calls[0].headers
        run = client.get("/api/runs", headers=api).json()[0]
        assert run["labels_sent_to_cloud"] == {"nda": 1, "pii": 1}


def test_unlabelled_call_has_no_labels_extension(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/chat/completions"] = CHAT_REPLY
    with make_proxy(CONFIG) as client:
        assert client.post("/v1/chat/completions", json=CHAT, headers=auth).status_code == 200
        [record] = [r for r in proxy_records(client) if r["kind"] == "llm_call"]
    assert record["data_labels"] == []
    assert "sealedrun.labels" not in record["extensions"]


def test_bad_label_is_400_before_any_upstream_call(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    api: dict[str, str],
    proxy_records: Any,
) -> None:
    upstream.routes["/chat/completions"] = CHAT_REPLY
    upstream.routes["/mcp"] = MCP_RESULT
    upstream.routes["/rpc"] = A2A_RESULT
    bad = {**auth, "X-SealedRun-Labels": "NDA"}
    with make_proxy(CONFIG) as client:
        reply = client.post("/v1/chat/completions", json=CHAT, headers=bad)
        assert reply.status_code == 400
        assert "x-sealedrun-labels" in reply.json()["error"]["message"]
        assert client.post("/mcp/tools", json=MCP_CALL, headers=bad).status_code == 400
        assert client.post("/a2a/planner", json=A2A_CALL, headers=bad).status_code == 400
        step = {**api, "X-SealedRun-Labels": "NDA"}
        assert client.post("/api/steps", json=STEP, headers=step).status_code == 400
        assert upstream.calls == []
        assert proxy_records(client) == []


def test_streamed_llm_call_carries_header_labels(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    api: dict[str, str],
    proxy_records: Any,
) -> None:
    chunk = {"id": "c", "object": "chat.completion.chunk", "model": "gpt-4.1", "choices": []}
    stream = b"data: " + json.dumps(chunk).encode() + b"\n\ndata: [DONE]\n\n"
    upstream.routes["/chat/completions"] = lambda request: httpx.Response(
        200, headers={"content-type": SSE}, stream=_Chunks([stream])
    )
    with make_proxy(CONFIG) as client:
        body = {**CHAT, "stream": True}
        reply = client.post("/v1/chat/completions", json=body, headers={**auth, **LABELLED})
        assert reply.status_code == 200
        assert reply.content == stream
        records = proxy_records(client)
        record = _labelled(records, "llm_call")
        _verified(client, api, records)
    assert record["extensions"]["sealedrun.llm"]["stream"] is True
    assert "x-sealedrun-labels" not in upstream.calls[0].headers


def test_mcp_and_a2a_calls_carry_header_labels(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    api: dict[str, str],
    proxy_records: Any,
) -> None:
    upstream.routes["/mcp"] = MCP_RESULT
    upstream.routes["/rpc"] = A2A_RESULT
    with make_proxy(CONFIG) as client:
        mcp = {**auth, **LABELLED, "Mcp-Method": "tools/call", "X-SealedRun-Run": "mcp"}
        assert client.post("/mcp/tools", json=MCP_CALL, headers=mcp).status_code == 200
        a2a = {**auth, **LABELLED, "A2A-Version": "1.0", "X-SealedRun-Run": "a2a"}
        assert client.post("/a2a/planner", json=A2A_CALL, headers=a2a).status_code == 200
        for run in client.get("/api/runs", headers=api).json():
            records = client.get(f"/api/runs/{run['run_id']}/records", headers=api).json()
            record = _labelled(records, "tool_call")
            assert record["extensions"]["sealedrun.proxy"]["dialect"] == run["run_label"]
            _verified(client, api, records)
            assert run["labels_sent_to_cloud"] == {}
    for sent in upstream.calls:
        assert "x-sealedrun-labels" not in sent.headers


def test_step_takes_header_labels_unless_it_names_its_own(
    make_proxy: Callable[..., TestClient], upstream: Any, api: dict[str, str]
) -> None:
    with make_proxy(CONFIG) as client:
        reply = client.post("/api/steps", json=STEP, headers={**api, **LABELLED})
        assert reply.status_code == 201, reply.text
        _labelled([reply.json()], "note")
        own = {**STEP, "data_labels": ["legal"]}
        reply = client.post("/api/steps", json=own, headers={**api, **LABELLED})
        assert reply.status_code == 201, reply.text
        assert reply.json()["data_labels"] == ["legal"]
        assert "sealedrun.labels" not in reply.json().get("extensions", {})
        run_id = reply.json()["run_id"]
        reply = client.post(f"/api/runs/{run_id}/steps", json=STEP, headers={**api, **LABELLED})
        assert reply.status_code == 201, reply.text
        _labelled([reply.json()], "note")


def test_no_dialect_forwards_the_labels_header() -> None:
    from sealedrun_recorder.proxy import a2a, anthropic, gemini, mcp, ollama, openai

    for module in (openai, anthropic, ollama, gemini):
        for value in vars(module).values():
            if hasattr(value, "passthrough"):
                assert "x-sealedrun-labels" not in value.passthrough
    assert "x-sealedrun-labels" not in mcp.REQUEST_HEADERS
    assert not any("x-sealedrun-labels".startswith(p) for p in mcp.REQUEST_PREFIXES)
    assert "x-sealedrun-labels" not in a2a.REQUEST_HEADERS
