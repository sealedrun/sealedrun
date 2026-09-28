import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from sealedrun_recorder.proxy.a2a import card_url, rewrite_card, safe_path
from sealedrun_recorder.upstreams import UpstreamConfigError, load_upstreams

SSE_TYPE = "text/event-stream"
EXAMPLE = Path(__file__).resolve().parents[1] / "upstreams.example.yaml"

CONFIG = """
a2a_agents:
  - name: planner
    url: http://agent.test/rpc
    location: local
  - name: keyed
    url: https://agent.test/keyed/
    key_env: TEST_UPSTREAM_KEY
    location: cloud
  - name: nokey
    url: https://agent.test/nokey
    key_env: TEST_MISSING_KEY
"""
CARD = {
    "name": "Planner",
    "protocolVersion": "1.0",
    "url": "http://agent.test/rpc",
    "supportedInterfaces": [
        {"url": "http://agent.test/rpc", "protocolBinding": "JSONRPC"},
        {"url": "http://agent.test/rpc/rest", "protocolBinding": "HTTP+JSON"},
        {"url": "grpc://agent.test:9000", "protocolBinding": "GRPC"},
    ],
    "capabilities": {"streaming": True},
    "signatures": [{"protected": "x", "signature": "y"}],
}


def _load(tmp_path: Path, text: str, environ: dict[str, str] | None = None) -> Any:
    path = tmp_path / "u.yaml"
    path.write_text(text)
    return load_upstreams(path, environ=environ or {})


def test_a2a_agents_load_by_name(tmp_path: Path) -> None:
    config = _load(tmp_path, CONFIG, {"TEST_UPSTREAM_KEY": "sk-1"})
    assert [a.name for a in config.a2a_agents] == ["planner", "keyed", "nokey"]
    assert config.mcp_servers == [] and list(config) == []
    assert config.a2a("planner").location == "local"
    assert config.a2a("keyed").request_headers() == {"authorization": "Bearer sk-1"}
    assert config.a2a("nokey").missing_key
    assert config.a2a("absent") is None
    assert config.mcp("planner") is None


def test_example_file_a2a_agents() -> None:
    config = load_upstreams(EXAMPLE, environ={})
    assert [a.name for a in config.a2a_agents] == ["planner"]


@pytest.mark.parametrize(
    "text",
    [
        "a2a_agents: 1\n",
        "a2a_agents:\n  - {name: 'bad name', url: http://a}\n",
        "a2a_agents:\n  - {name: a, url: ftp://a}\n",
        "a2a_agents:\n  - {name: a, url: http://a}\n  - {name: a, url: http://b}\n",
    ],
)
def test_a2a_config_errors(tmp_path: Path, text: str) -> None:
    with pytest.raises(UpstreamConfigError):
        _load(tmp_path, text)


@pytest.fixture
def auth(secrets: dict[str, str]) -> dict[str, str]:
    return {"X-SealedRun-Token": secrets["token"], "Content-Type": "application/json"}


def _rpc(method: str = "SendMessage", rid: int = 1) -> bytes:
    params = {"message": {"messageId": "m-1", "role": "ROLE_USER", "parts": [{"text": "hi"}]}}
    return json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}).encode()


def test_route_needs_token_and_known_agent(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str]
) -> None:
    upstream.routes["/rpc"] = {"jsonrpc": "2.0", "id": 1, "result": {}}
    with make_proxy(CONFIG) as client:
        assert client.post("/a2a/planner", content=_rpc()).status_code == 401
        assert client.post("/a2a/absent", content=_rpc(), headers=auth).status_code == 404
        assert client.post("/a2a/nokey", content=_rpc(), headers=auth).status_code == 503
        cross = {**auth, "Sec-Fetch-Site": "cross-site"}
        assert client.post("/a2a/planner", content=_rpc(), headers=cross).status_code == 403
        bad = {**auth, "X-SealedRun-Run": "a b"}
        assert client.post("/a2a/planner", content=_rpc(), headers=bad).status_code == 400
        assert client.post("/a2a/planner", content=_rpc(), headers=auth).status_code == 200


def test_json_rpc_is_forwarded_with_allowed_headers(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str]
) -> None:
    def answer(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": 1, "result": {"kind": "task", "id": "t-1"}},
            headers={"A2A-Version": "1.0", "X-Internal": "no"},
        )

    upstream.routes["/rpc"] = answer
    headers = {**auth, "A2A-Version": "1.0", "A2A-Extensions": "urn:x", "X-Custom": "drop"}
    with make_proxy(CONFIG) as client:
        reply = client.post("/a2a/planner?x=1", content=_rpc(), headers=headers)
    assert reply.status_code == 200
    assert reply.json()["result"]["id"] == "t-1"
    assert reply.headers["a2a-version"] == "1.0"
    assert "x-internal" not in reply.headers
    [sent] = upstream.calls
    assert str(sent.url) == "http://agent.test/rpc?x=1"
    assert sent.content == _rpc()
    assert sent.headers["a2a-version"] == "1.0"
    assert sent.headers["a2a-extensions"] == "urn:x"
    assert sent.headers["accept-encoding"] == "identity"
    assert "x-custom" not in sent.headers
    assert "x-sealedrun-token" not in sent.headers


def test_agent_key_is_swapped_in_and_rest_paths_are_forwarded(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str]
) -> None:
    upstream.routes["/keyed/tasks/t-9"] = {"id": "t-9", "status": {"state": "TASK_STATE_COMPLETED"}}
    with make_proxy(CONFIG) as client:
        reply = client.get("/a2a/keyed/tasks/t-9", headers=auth)
    assert reply.status_code == 200
    assert reply.json()["id"] == "t-9"
    [sent] = upstream.calls
    assert str(sent.url) == "https://agent.test/keyed/tasks/t-9"
    assert sent.headers["authorization"] == "Bearer sk-upstream-secret-456"


def test_sse_reply_is_relayed(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str]
) -> None:
    events = b'data: {"jsonrpc":"2.0","id":1,"result":{"statusUpdate":{}}}\n\n'

    def answer(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=events, headers={"content-type": SSE_TYPE})

    upstream.routes["/rpc"] = answer
    with make_proxy(CONFIG) as client:
        reply = client.post("/a2a/planner", content=_rpc("SendStreamingMessage"), headers=auth)
    assert reply.status_code == 200
    assert reply.headers["x-accel-buffering"] == "no"
    assert reply.content == events


def test_agent_card_is_rewritten_to_the_proxy(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str]
) -> None:
    upstream.routes["/.well-known/agent-card.json"] = CARD
    with make_proxy(CONFIG) as client:
        reply = client.get("/a2a/planner/.well-known/agent-card.json", headers=auth)
    assert reply.status_code == 200, reply.text
    card = reply.json()
    assert card["url"] == "http://localhost/a2a/planner"
    assert [i["url"] for i in card["supportedInterfaces"]] == [
        "http://localhost/a2a/planner",
        "http://localhost/a2a/planner/rest",
        "grpc://agent.test:9000",
    ]
    assert card["name"] == "Planner"
    assert card["signatures"] == CARD["signatures"]
    [sent] = upstream.calls
    assert str(sent.url) == "http://agent.test/.well-known/agent-card.json"


def test_agent_card_errors_pass_through(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str]
) -> None:
    upstream.routes["/.well-known/agent-card.json"] = lambda r: httpx.Response(404, json={"e": 1})
    with make_proxy(CONFIG) as client:
        assert (
            client.get("/a2a/planner/.well-known/agent-card.json", headers=auth).status_code == 404
        )
        upstream.fail = "down"
        assert (
            client.get("/a2a/planner/.well-known/agent-card.json", headers=auth).status_code == 502
        )
        assert client.post("/a2a/planner", content=_rpc(), headers=auth).status_code == 502


def test_card_helpers() -> None:
    assert (
        card_url("https://agent.test/some/deep/rpc?x=1")
        == "https://agent.test/.well-known/agent-card.json"
    )
    card = rewrite_card({"url": "http://a/rpc/", "other": 1}, "http://a/rpc", "http://p/a2a/x")
    assert card == {"url": "http://p/a2a/x", "other": 1}
    assert (
        rewrite_card({"url": "http://elsewhere/"}, "http://a/rpc", "http://p")["url"]
        == "http://elsewhere/"
    )


# --- recording ---------------------------------------------------------------------------------

from sealedrun import verify_run  # noqa: E402
from sealedrun.schema import validate_extensions  # noqa: E402

TASK_DONE = {"id": "t-1", "contextId": "c-1", "status": {"state": "TASK_STATE_COMPLETED"}}


def _result(payload: dict[str, Any], rid: int = 1) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "result": payload}


def _sse(*messages: dict[str, Any]) -> bytes:
    return b"".join(b"data: " + json.dumps(m).encode() + b"\n\n" for m in messages)


def _stream(chunks: list[bytes]) -> Callable[[Any], httpx.Response]:
    return lambda request: httpx.Response(
        200, headers={"content-type": SSE_TYPE}, content=b"".join(chunks)
    )


@pytest.fixture
def api(secrets: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {secrets['token']}"}


def _tool_calls(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in records if r["kind"] == "tool_call"]


def test_send_message_json_reply_is_recorded(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    api: dict[str, str],
    proxy_records: Any,
) -> None:
    upstream.routes["/rpc"] = _result({"task": TASK_DONE})
    headers = {**auth, "A2A-Version": "1.0", "X-SealedRun-Run": "job-a2a"}
    with make_proxy(CONFIG) as client:
        reply = client.post("/a2a/planner", content=_rpc(), headers=headers)
        records = proxy_records(client)
        [record] = _tool_calls(records)
        stored = client.get(f"/api/records/{record['record_id']}/payload/response", headers=api)
        principal = client.get("/api/identity", headers=api).json()
    assert reply.status_code == 200
    assert record["target"] == {
        "type": "tool",
        "name": "planner/message",
        "endpoint": "http://agent.test/rpc",
        "location": "local",
        "provider": "a2a:planner",
    }
    assert record["outcome"] == "success"
    assert record["extensions"]["sealedrun.a2a"] == {
        "agent": "planner",
        "method": "SendMessage",
        "binding": "jsonrpc",
        "is_error": False,
        "task_id": "t-1",
        "context_id": "c-1",
        "message_id": "m-1",
        "state": "TASK_STATE_COMPLETED",
        "protocol_version": "1.0",
    }
    proxy = record["extensions"]["sealedrun.proxy"]
    assert (proxy["dialect"], proxy["operation"], proxy["status"]) == ("a2a", "SendMessage", 200)
    assert validate_extensions(record["extensions"]) == []
    assert json.loads(stored.content) == _result({"task": TASK_DONE})
    delegation = principal["delegation"]
    verify_run(records, {delegation["delegation_id"]: delegation})


def test_streaming_reply_is_one_record_with_the_final_state(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    submitted = {"id": "t-2", "contextId": "c-2", "status": {"state": "TASK_STATE_SUBMITTED"}}
    working = {"taskId": "t-2", "contextId": "c-2", "status": {"state": "TASK_STATE_WORKING"}}
    artifact = {"taskId": "t-2", "artifact": {"artifactId": "a", "parts": [{"text": "x"}]}}
    done = {"taskId": "t-2", "contextId": "c-2", "status": {"state": "TASK_STATE_COMPLETED"}}
    events = [
        _sse(_result({"task": submitted})),
        _sse(_result({"statusUpdate": working})),
        _sse(_result({"artifactUpdate": artifact})),
        _sse(_result({"statusUpdate": done})),
    ]
    upstream.routes["/rpc"] = _stream(events)
    with make_proxy(CONFIG) as client:
        reply = client.post("/a2a/planner", content=_rpc("SendStreamingMessage"), headers=auth)
        [record] = _tool_calls(proxy_records(client))
    assert reply.content == b"".join(events)
    assert record["outcome"] == "success"
    a2a = record["extensions"]["sealedrun.a2a"]
    assert (a2a["method"], a2a["task_id"], a2a["context_id"], a2a["state"]) == (
        "SendStreamingMessage",
        "t-2",
        "c-2",
        "TASK_STATE_COMPLETED",
    )
    assert record["payload"]["response_media_type"] == SSE_TYPE
    assert "truncated" not in record["extensions"]["sealedrun.proxy"]


@pytest.mark.parametrize(
    ("payload", "outcome", "state"),
    [
        (
            {"task": {"id": "t", "status": {"state": "TASK_STATE_FAILED"}}},
            "error",
            "TASK_STATE_FAILED",
        ),
        (
            {"task": {"id": "t", "status": {"state": "TASK_STATE_REJECTED"}}},
            "error",
            "TASK_STATE_REJECTED",
        ),
        (
            {"task": {"id": "t", "status": {"state": "TASK_STATE_INPUT_REQUIRED"}}},
            "pending",
            "TASK_STATE_INPUT_REQUIRED",
        ),
        (
            {"task": {"id": "t", "status": {"state": "TASK_STATE_WORKING"}}},
            "pending",
            "TASK_STATE_WORKING",
        ),
        (
            {"message": {"messageId": "r", "role": "ROLE_AGENT", "parts": [{"text": "hi"}]}},
            "success",
            None,
        ),
    ],
)
def test_outcome_follows_the_task_state(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    proxy_records: Any,
    payload: dict[str, Any],
    outcome: str,
    state: str | None,
) -> None:
    upstream.routes["/rpc"] = _result(payload)
    with make_proxy(CONFIG) as client:
        assert client.post("/a2a/planner", content=_rpc(), headers=auth).status_code == 200
        [record] = _tool_calls(proxy_records(client))
    assert record["outcome"] == outcome
    assert record["extensions"]["sealedrun.a2a"].get("state") == state


def test_json_rpc_error_and_cut_stream(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/rpc"] = {
        "jsonrpc": "2.0",
        "id": 1,
        "error": {"code": -32001, "message": "TaskNotFoundError"},
    }
    with make_proxy(CONFIG) as client:
        assert (
            client.post("/a2a/planner", content=_rpc("CancelTask"), headers=auth).status_code == 200
        )
        upstream.routes["/rpc"] = _stream([_sse({"jsonrpc": "2.0", "method": "notifications/x"})])
        assert (
            client.post(
                "/a2a/planner", content=_rpc("SendStreamingMessage", 2), headers=auth
            ).status_code
            == 200
        )
        first, second = _tool_calls(proxy_records(client))
    assert first["outcome"] == "error"
    assert first["extensions"]["sealedrun.a2a"]["is_error"] is True
    assert first["target"]["name"] == "planner/cancel"
    assert second["outcome"] == "error"
    assert second["extensions"]["sealedrun.proxy"]["truncated"] is True


def test_rest_operations_are_recorded_and_others_are_not(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/keyed/message:send"] = {"task": TASK_DONE}
    upstream.routes["/keyed/tasks/t-1:cancel"] = {
        "task": {**TASK_DONE, "status": {"state": "TASK_STATE_CANCELED"}}
    }
    upstream.routes["/keyed/tasks/t-1"] = {"task": TASK_DONE}
    upstream.routes["/keyed/tasks"] = {"tasks": []}
    message = {"message": {"messageId": "m-9", "role": "ROLE_USER", "parts": [{"text": "hi"}]}}
    with make_proxy(CONFIG) as client:
        assert client.post("/a2a/keyed/message:send", json=message, headers=auth).status_code == 200
        assert (
            client.post("/a2a/keyed/tasks/t-1:cancel", content=b"{}", headers=auth).status_code
            == 200
        )
        assert client.get("/a2a/keyed/tasks/t-1", headers=auth).status_code == 200
        assert client.get("/a2a/keyed/tasks", headers=auth).status_code == 200
        get = _rpc("GetTask", 5)
        upstream.routes["/keyed/"] = _result({"task": TASK_DONE}, 5)
        assert client.post("/a2a/keyed", content=get, headers=auth).status_code == 200
        upstream.routes["/rpc"] = _result({"task": TASK_DONE}, 5)
        assert client.post("/a2a/planner", content=get, headers=auth).status_code == 200
        upstream.routes["/rpc"] = _result({"tasks": []}, 6)
        assert (
            client.post("/a2a/planner", content=_rpc("ListTasks", 6), headers=auth).status_code
            == 200
        )
        records = _tool_calls(proxy_records(client))
        for record in records:
            validate_extensions(record["extensions"])
    assert [
        (
            r["extensions"]["sealedrun.a2a"]["method"],
            r["extensions"]["sealedrun.a2a"]["binding"],
            r["outcome"],
        )
        for r in records
    ] == [
        ("SendMessage", "rest", "success"),
        ("CancelTask", "rest", "error"),
        ("GetTask", "jsonrpc", "success"),
    ]
    assert records[0]["extensions"]["sealedrun.a2a"]["message_id"] == "m-9"
    assert records[1]["extensions"]["sealedrun.a2a"]["task_id"] == "t-1"
    assert records[2]["target"]["name"] == "keyed/GetTask"
    assert len(upstream.calls) == 7


def test_a2a_03_method_names_are_recorded(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/rpc"] = _result({"task": TASK_DONE})
    with make_proxy(CONFIG) as client:
        assert (
            client.post("/a2a/planner", content=_rpc("message/send"), headers=auth).status_code
            == 200
        )
        assert (
            client.post("/a2a/planner", content=_rpc("tasks/cancel"), headers=auth).status_code
            == 200
        )
        assert (
            client.post("/a2a/planner", content=_rpc("tasks/get"), headers=auth).status_code == 200
        )
        records = _tool_calls(proxy_records(client))
    assert [(r["extensions"]["sealedrun.a2a"]["method"], r["target"]["name"]) for r in records] == [
        ("message/send", "planner/message"),
        ("tasks/cancel", "planner/cancel"),
    ]


@pytest.mark.parametrize(
    "body",
    [b"[]", b"[" + _rpc() + b"]", _rpc(rid=1.5), _rpc(rid=None), _rpc("CancelTask", rid=True)],  # type: ignore[arg-type]
)
def test_batches_and_bad_ids_are_refused_for_local_agents_too(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], body: bytes
) -> None:
    with make_proxy(CONFIG) as client:
        reply = client.post("/a2a/planner", content=body, headers=auth)
    assert reply.status_code == 400, body
    assert reply.json()["error"]["code"] == 40000
    assert upstream.calls == []


@pytest.mark.parametrize(
    "path",
    [
        "../other/message:send",
        "tasks/../../admin",
        "./message:send",
        "tasks//t-1",
        "a?b",
        "a#b",
        "..;/admin",
        "tasks/t-1;x=1",
        "%2e%2e/admin",
        "%252e%252e/admin",
        "a b",
    ],
)
def test_dot_segments_are_refused_before_any_client_normalisation(path: str) -> None:
    scope = {"type": "http", "raw_path": f"/a2a/keyed/{path}".encode(), "headers": []}
    assert not safe_path(Request(scope), path)
    plain = {"type": "http", "raw_path": b"/a2a/keyed/tasks/t-1:cancel", "headers": []}
    assert safe_path(Request(plain), "tasks/t-1:cancel")
    assert safe_path(Request(plain), "")


@pytest.mark.parametrize(
    "path",
    [
        "/a2a/keyed/%2e%2e/other",
        "/a2a/keyed/%2E%2E/other",
        "/a2a/keyed/tasks%2f..%2fadmin",
        "/a2a/keyed/message:send%3fkey=1",
        "/a2a/keyed/message:send%23x",
        "/a2a/keyed/tasks//t-1",
        "/a2a/keyed/tasks%5c..",
        "/a2a/keyed/%252e%252e/%252e%252e/admin",
        "/a2a/keyed/..;/admin",
        "/a2a/keyed/tasks%2Ft-1:cancel",
    ],
)
def test_path_escapes_are_refused(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], path: str
) -> None:
    with make_proxy(CONFIG) as client:
        reply = client.post(path, content=b"{}", headers=auth)
        assert reply.status_code == 400, path
        assert client.get(path, headers=auth).status_code == 400
    assert upstream.calls == []


def test_agent_error_status_is_not_recorded(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/rpc"] = lambda r: httpx.Response(401, json={"e": "auth"})
    with make_proxy(CONFIG) as client:
        assert client.post("/a2a/planner", content=_rpc(), headers=auth).status_code == 401
        assert proxy_records(client) == []
