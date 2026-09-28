import hashlib
import json
from collections.abc import AsyncIterator, Callable
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sealedrun import read_bundle, verify_bundle, verify_run
from sealedrun.schema import validate_extensions

CONFIG = """
mcp_servers:
  - name: tools
    url: http://mcp.test/mcp
    key_env: TEST_UPSTREAM_KEY
    location: local
"""
SSE_TYPE = "text/event-stream"


def _message(method: str, params: dict[str, Any], request_id: Any = 7) -> bytes:
    message = {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    return json.dumps(message).encode()


def _call(name: str = "add", request_id: Any = 7) -> bytes:
    return _message("tools/call", {"name": name, "arguments": {"a": 1, "b": 2}}, request_id)


def _result(result: dict[str, Any], request_id: Any = 7) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _sse(*messages: dict[str, Any]) -> bytes:
    return b"".join(b"event: message\ndata: " + json.dumps(m).encode() + b"\n\n" for m in messages)


class Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes], fail: bool = False) -> None:
        self.chunks = chunks
        self.fail = fail

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            yield chunk
        if self.fail:
            raise httpx.ReadError("upstream broke")


def _stream(chunks: list[bytes], fail: bool = False) -> Callable[[Any], httpx.Response]:
    return lambda request: httpx.Response(
        200, headers={"content-type": SSE_TYPE}, stream=Chunks(chunks, fail)
    )


@pytest.fixture
def auth(secrets: dict[str, str]) -> dict[str, str]:
    return {"X-SealedRun-Token": secrets["token"], "Content-Type": "application/json"}


@pytest.fixture
def api(secrets: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {secrets['token']}"}


def _tool_calls(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in records if r["kind"] == "tool_call"]


def test_tools_call_json_reply_is_recorded(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    api: dict[str, str],
    proxy_records: Any,
) -> None:
    answer = _result({"content": [{"type": "text", "text": "3"}], "isError": False})
    upstream.routes["/mcp"] = answer
    headers = {**auth, "MCP-Protocol-Version": "2026-07-28", "Mcp-Method": "tools/call"}
    with make_proxy(CONFIG) as client:
        reply = client.post("/mcp/tools", content=_call(), headers=headers)
        records = proxy_records(client)
        principal = client.get("/api/identity", headers=api).json()
        [record] = _tool_calls(records)
        body = client.get(f"/api/records/{record['record_id']}/payload/request", headers=api)
        stored = client.get(f"/api/records/{record['record_id']}/payload/response", headers=api)
    assert reply.json() == answer
    assert record["target"] == {
        "type": "tool",
        "name": "add",
        "endpoint": "http://mcp.test/mcp",
        "location": "local",
        "provider": "mcp:tools",
    }
    assert record["outcome"] == "success"
    assert record["extensions"]["sealedrun.mcp"] == {
        "server": "tools",
        "transport": "http",
        "method": "tools/call",
        "request_id": 7,
        "is_error": False,
        "tool": "add",
        "protocol_version": "2026-07-28",
    }
    proxy = record["extensions"]["sealedrun.proxy"]
    assert (proxy["dialect"], proxy["operation"], proxy["status"]) == ("mcp", "tools/call", 200)
    assert record["payload"]["response_media_type"] == "application/json"
    assert validate_extensions(record["extensions"]) == []
    assert body.content == _call()
    assert json.loads(stored.content) == answer
    delegation = principal["delegation"]
    verify_run(records, {delegation["delegation_id"]: delegation})


def test_sse_reply_is_one_record_with_the_raw_stream(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    api: dict[str, str],
    proxy_records: Any,
) -> None:
    progress = {"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progress": 1}}
    server_request = {"jsonrpc": "2.0", "id": 7, "method": "sampling/createMessage"}
    stream = [_sse(progress), _sse(server_request), _sse(_result({"content": []}))]
    upstream.routes["/mcp"] = _stream(stream)
    with make_proxy(CONFIG) as client:
        reply = client.post("/mcp/tools", content=_call(), headers=auth)
        [record] = _tool_calls(proxy_records(client))
        stored = client.get(f"/api/records/{record['record_id']}/payload/response", headers=api)
    assert reply.content == b"".join(stream)
    assert stored.content == b"".join(stream)
    assert record["outcome"] == "success"
    assert record["payload"]["response_media_type"] == SSE_TYPE
    assert "truncated" not in record["extensions"]["sealedrun.proxy"]


@pytest.mark.parametrize(
    ("answer", "outcome"),
    [
        ({"jsonrpc": "2.0", "id": 7, "error": {"code": -32602, "message": "no tool"}}, "error"),
        (_result({"content": [], "isError": True}), "error"),
        (_result({"resultType": "input_required", "inputRequests": {}}), "pending"),
        (_result({"resultType": "complete", "content": []}), "success"),
    ],
)
def test_outcome_follows_the_response(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    proxy_records: Any,
    answer: dict[str, Any],
    outcome: str,
) -> None:
    upstream.routes["/mcp"] = answer
    with make_proxy(CONFIG) as client:
        client.post("/mcp/tools", content=_call(), headers=auth)
        [record] = _tool_calls(proxy_records(client))
    assert record["outcome"] == outcome
    assert record["extensions"]["sealedrun.mcp"]["is_error"] is (outcome == "error")
    if "resultType" in answer.get("result", {}):
        assert (
            record["extensions"]["sealedrun.mcp"]["result_type"] == answer["result"]["resultType"]
        )


def test_input_required_round_then_retry_are_two_records(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    proxy_records: Any,
) -> None:
    replies = iter(
        [
            _result({"resultType": "input_required", "inputRequests": {"q": {}}}, 1),
            _result({"resultType": "complete", "content": []}, 2),
        ]
    )
    upstream.routes["/mcp"] = lambda request: httpx.Response(200, json=next(replies))
    with make_proxy(CONFIG) as client:
        client.post("/mcp/tools", content=_call(request_id=1), headers=auth)
        retry = json.loads(_call(request_id=2))
        retry["params"]["inputResponses"] = {"q": {"action": "accept"}}
        client.post("/mcp/tools", content=json.dumps(retry).encode(), headers=auth)
        records = _tool_calls(proxy_records(client))
    assert [r["outcome"] for r in records] == ["pending", "success"]


@pytest.mark.parametrize(
    ("chunks", "fail"),
    [
        ([_sse({"jsonrpc": "2.0", "method": "notifications/progress", "params": {}})], True),
        ([_sse({"jsonrpc": "2.0", "method": "notifications/progress", "params": {}})], False),
    ],
)
def test_stream_without_response_is_truncated(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    proxy_records: Any,
    chunks: list[bytes],
    fail: bool,
) -> None:
    upstream.routes["/mcp"] = _stream(chunks, fail)
    with make_proxy(CONFIG) as client:
        client.post("/mcp/tools", content=_call(), headers=auth)
        [record] = _tool_calls(proxy_records(client))
    assert record["outcome"] == "error"
    assert record["extensions"]["sealedrun.proxy"]["truncated"] is True


def test_stream_over_the_size_cap_is_cut_and_truncated(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    proxy_records: Any,
) -> None:
    chunks = [b": " + b"x" * 100 + b"\n\n", _sse(_result({"content": []}))]
    upstream.routes["/mcp"] = _stream(chunks)
    with make_proxy(CONFIG, proxy_max_body_bytes=150) as client:
        reply = client.post("/mcp/tools", content=_call(), headers=auth)
        [record] = _tool_calls(proxy_records(client))
    assert reply.content == chunks[0]
    assert record["extensions"]["sealedrun.proxy"]["truncated"] is True


@pytest.mark.parametrize(
    ("method", "params", "name"),
    [
        ("resources/read", {"uri": "file:///etc/hosts"}, "file:///etc/hosts"),
        ("prompts/get", {"name": "review", "arguments": {}}, "review"),
    ],
)
def test_resources_and_prompts_are_recorded(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    proxy_records: Any,
    method: str,
    params: dict[str, Any],
    name: str,
) -> None:
    upstream.routes["/mcp"] = _result({"contents": []})
    with make_proxy(CONFIG) as client:
        client.post("/mcp/tools", content=_message(method, params), headers=auth)
        [record] = _tool_calls(proxy_records(client))
    assert record["target"]["name"] == name
    assert record["extensions"]["sealedrun.mcp"]["method"] == method
    assert "tool" not in record["extensions"]["sealedrun.mcp"]


def test_tools_list_is_recorded_once_per_run_until_it_changes(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    proxy_records: Any,
) -> None:
    lists = iter(
        [
            {"tools": [{"name": "add"}]},
            {"tools": [{"name": "add"}]},
            {"tools": [{"name": "add"}, {"name": "sub"}]},
            {"tools": [{"name": "page2"}]},
        ]
    )
    upstream.routes["/mcp"] = lambda request: httpx.Response(200, json=_result(next(lists)))
    with make_proxy(CONFIG) as client:
        for params in ({}, {}, {}, {"cursor": "p2"}):
            client.post("/mcp/tools", content=_message("tools/list", params), headers=auth)
        records = _tool_calls(proxy_records(client))
    assert len(upstream.calls) == 4
    assert len(records) == 3
    assert {r["target"]["name"] for r in records} == {"tools/list"}


@pytest.mark.parametrize(
    "body",
    [
        _message("initialize", {"protocolVersion": "2025-11-25"}),
        _message("server/discover", {}),
        _message("subscriptions/listen", {}),
        _message("ping", {}),
        b'{"jsonrpc":"2.0","method":"notifications/initialized"}',
        b'{"jsonrpc":"2.0","id":3,"result":{"action":"accept"}}',
        b'{"jsonrpc":"2.0","id":3.5,"result":{"action":"accept"}}',
        b"not json",
    ],
)
def test_other_messages_are_forwarded_unrecorded(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    proxy_records: Any,
    body: bytes,
) -> None:
    upstream.routes["/mcp"] = _result({})
    with make_proxy(CONFIG) as client:
        assert client.post("/mcp/tools", content=body, headers=auth).status_code == 200
        assert _tool_calls(proxy_records(client)) == []
    assert upstream.calls[0].content == body


@pytest.mark.parametrize(
    "body",
    [
        b"[" + _call() + b"]",
        b"[]",
        _call(request_id=7.0),
        _call(request_id=None),
        _call(request_id=True),
        _call(request_id=[7]),
        _message("resources/read", {"uri": "file:///x"}, None),
        _message("initialize", {}, 1.5),
        b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"add"}}',
        b'{"jsonrpc":"2.0","method":"prompts/get","params":{"name":"p"}}',
    ],
)
def test_batches_bad_ids_and_id_less_calls_are_refused_unforwarded(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    proxy_records: Any,
    body: bytes,
) -> None:
    upstream.routes["/mcp"] = _result({})
    with make_proxy(CONFIG) as client:
        reply = client.post("/mcp/tools", content=body, headers=auth)
        assert reply.status_code == 400, reply.text
        assert reply.json()["error"]["code"] == 40000
        assert reply.json()["id"] is None
        assert _tool_calls(proxy_records(client)) == []
    assert upstream.calls == []


@pytest.mark.parametrize("status", [400, 401, 404, 500])
def test_refused_messages_are_unrecorded(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    proxy_records: Any,
    status: int,
) -> None:
    mismatch = {"jsonrpc": "2.0", "id": 7, "error": {"code": -32020, "message": "HeaderMismatch"}}
    upstream.routes["/mcp"] = lambda request: httpx.Response(status, json=mismatch)
    with make_proxy(CONFIG) as client:
        assert client.post("/mcp/tools", content=_call(), headers=auth).status_code == status
        assert _tool_calls(proxy_records(client)) == []


def test_get_stream_and_delete_are_unrecorded(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    proxy_records: Any,
) -> None:
    upstream.routes["/mcp"] = _stream([_sse(_result({"content": []}))])
    with make_proxy(CONFIG) as client:
        client.get("/mcp/tools", headers={**auth, "Mcp-Session-Id": "s"})
        client.delete("/mcp/tools", headers={**auth, "Mcp-Session-Id": "s"})
        assert _tool_calls(proxy_records(client)) == []


def test_legacy_session_is_recorded_as_a_hash_and_secrets_never(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    secrets: dict[str, str],
    proxy_records: Any,
    stored_text: Any,
) -> None:
    upstream.routes["/mcp"] = _result({"content": []})
    session = "session-secret-123"
    headers = {**auth, "Mcp-Session-Id": session, "MCP-Protocol-Version": "2025-11-25"}
    with make_proxy(CONFIG) as client:
        client.post("/mcp/tools", content=_call(), headers=headers)
        [record] = _tool_calls(proxy_records(client))
        text = stored_text(client)
    mcp = record["extensions"]["sealedrun.mcp"]
    assert mcp["session"] == hashlib.sha256(session.encode()).hexdigest()
    assert mcp["protocol_version"] == "2025-11-25"
    for secret in (session, secrets["token"], secrets["upstream_key"]):
        assert secret not in text
    assert upstream.calls[0].headers["authorization"] == f"Bearer {secrets['upstream_key']}"


def test_run_label_groups_mcp_calls(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    api: dict[str, str],
) -> None:
    upstream.routes["/mcp"] = _result({"content": []})
    with make_proxy(CONFIG) as client:
        bad = client.post("/mcp/tools", content=_call(), headers={**auth, "X-SealedRun-Run": "a b"})
        for label in ("job-1", "job-1", "job-2"):
            headers = {**auth, "X-SealedRun-Run": label}
            client.post("/mcp/tools", content=_call(), headers=headers)
        runs = client.get("/api/runs", headers=api).json()
    assert bad.status_code == 400
    assert sorted((r["run_label"], r["record_count"]) for r in runs) == [("job-1", 3), ("job-2", 2)]


BOTH = (
    CONFIG
    + """
upstreams:
  - name: cloud
    url: https://cloud.example/v1
    dialect: openai
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["gpt-*"]
"""
)
CHAT = {"model": "gpt-4.1", "messages": [{"role": "user", "content": "add 1 and 2"}]}
CHAT_REPLY = {"id": "c1", "model": "gpt-4.1", "choices": [], "usage": {}}


@pytest.mark.parametrize("label", ["job-7", None])
def test_llm_and_mcp_calls_share_one_run_and_export_verifies(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    api: dict[str, str],
    label: str | None,
) -> None:
    upstream.routes["/chat/completions"] = CHAT_REPLY
    upstream.routes["/mcp"] = _result({"content": [{"type": "text", "text": "3"}]})
    run = {"X-SealedRun-Run": label} if label else {}
    with make_proxy(BOTH) as client:
        llm = {"Authorization": api["Authorization"], **run}
        assert client.post("/v1/chat/completions", json=CHAT, headers=llm).status_code == 200
        assert (
            client.post("/mcp/tools", content=_call(), headers={**auth, **run}).status_code == 200
        )
        assert client.post("/v1/chat/completions", json=CHAT, headers=llm).status_code == 200
        [summary] = client.get("/api/runs", headers=api).json()
        principal = client.get("/api/identity", headers=api).json()["principal_id"]
        exported = client.post(f"/api/runs/{summary['run_id']}/export?end=true", headers=api)
    assert summary["run_label"] == label
    assert exported.status_code == 200
    report = verify_bundle(read_bundle(exported.content), [principal])
    assert report.principal_trusted
    assert [(r.record_count, r.complete) for r in report.runs] == [(5, True)]
    bundle = read_bundle(exported.content)
    kinds = [r["kind"] for r in next(iter(bundle.runs.values()))]
    assert kinds == ["run_start", "llm_call", "tool_call", "llm_call", "run_end"]


def test_passed_through_client_token_is_never_recorded(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    proxy_records: Any,
    stored_text: Any,
) -> None:
    config = CONFIG + "    client_auth: passthrough\n"
    upstream.routes["/mcp"] = _result({"content": []})
    with make_proxy(config) as client:
        headers = {**auth, "Authorization": "Bearer user-oauth-token"}
        client.post("/mcp/tools", content=_call(), headers=headers)
        assert len(_tool_calls(proxy_records(client))) == 1
        text = stored_text(client)
    assert upstream.calls[0].headers["authorization"] == "Bearer user-oauth-token"
    assert "user-oauth-token" not in text
