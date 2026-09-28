"""The block-to-cloud rule: evaluation, the blocked path of the LLM proxy, every dialect."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sealedrun import verify_run
from sealedrun.schema import validator
from sealedrun_recorder.policy import Rule

CONFIG = """
upstreams:
  - name: cloudai
    url: https://cloud.example/v1
    dialect: openai
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["gpt-*"]
  - name: anthropic
    url: https://anthropic.example
    dialect: anthropic
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["claude-*"]
  - name: gemini
    url: https://gemini.example
    dialect: gemini
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["gemini-*"]
  - name: hosted-ollama
    url: https://ollama.example
    dialect: ollama
    location: cloud
    models: ["qwen*"]
  - name: local
    url: http://ollama.test
    dialect: ollama
    location: local
    models: ["llama*"]
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
OLLAMA_REPLY = {"model": "llama3", "message": {"role": "assistant", "content": "ok"}, "done": True}
MESSAGES = [{"role": "user", "content": "the NDA text"}]
RULE = {"policy_block_to_cloud": ["nda", "secret"]}
BLOCK = {
    "rule_id": "recorder/no-nda-to-cloud",
    "decision": "block",
    "reason": "target.location=cloud and labels contain nda",
}


def test_rule_evaluation() -> None:
    off = Rule()
    assert not off.active
    assert off.evaluate("cloud", ["nda"]) is None
    rule = Rule(("nda", "secret"))
    assert rule.evaluate("local", ["nda"]) is None
    assert rule.evaluate("cloud", []) is not None
    allowed = rule.evaluate("cloud", ["pii"])
    assert allowed is not None and not allowed.blocked
    assert allowed.document() == {
        "rule_id": "default/allow",
        "decision": "allow",
        "reason": "target.location=cloud and no configured label is present",
    }
    blocked = rule.evaluate("cloud", ["pii", "secret", "nda"])
    assert blocked is not None and blocked.blocked
    assert blocked.rule_id == "recorder/no-nda-to-cloud"
    assert blocked.document() == BLOCK


@pytest.fixture
def auth(secrets: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {secrets['token']}"}


def _labelled(auth: dict[str, str], labels: str, **more: str) -> dict[str, str]:
    return {**auth, "X-SealedRun-Labels": labels, **more}


def _llm_calls(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in records if r["kind"] == "llm_call"]


def test_blocked_call_never_reaches_the_upstream_and_is_recorded(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/chat/completions"] = CHAT_REPLY
    body = {"model": "gpt-4.1", "messages": MESSAGES}
    with make_proxy(CONFIG, **RULE) as client:
        reply = client.post(
            "/v1/chat/completions",
            json=body,
            headers=_labelled(auth, "nda, pii", **{"X-SealedRun-Run": "r"}),
        )
        assert reply.status_code == 403
        assert reply.json() == {
            "error": {
                "message": "blocked by policy recorder/no-nda-to-cloud: target.location=cloud"
                " and labels contain nda",
                "type": "sealedrun_proxy_error",
            }
        }
        assert upstream.calls == []
        records = proxy_records(client)
        [record] = _llm_calls(records)
        stored = client.get(f"/api/records/{record['record_id']}/payload/request", headers=auth)
        missing = client.get(f"/api/records/{record['record_id']}/payload/response", headers=auth)
        run = client.get("/api/runs", headers=auth).json()[0]
        delegation = client.get("/api/identity", headers=auth).json()["delegation"]
    assert record["outcome"] == "blocked"
    assert record["policy"] == BLOCK
    assert record["data_labels"] == ["nda", "pii"]
    assert record["target"]["location"] == "cloud"
    assert "response_hash" not in record["payload"]
    assert record["extensions"]["sealedrun.proxy"]["status"] == 403
    assert record["extensions"]["sealedrun.llm"] == {
        "model": "gpt-4.1",
        "provider": "cloudai",
        "stream": False,
    }
    assert json.loads(stored.content) == body
    assert missing.status_code == 404
    assert validator("record.json").is_valid(record)
    verify_run(records, {delegation["delegation_id"]: delegation})
    assert run["labels_sent_to_cloud"] == {}


def test_streamed_call_is_blocked_before_any_upstream_contact(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    body = {"model": "gpt-4.1", "messages": MESSAGES, "stream": True}
    with make_proxy(CONFIG, **RULE) as client:
        reply = client.post("/v1/chat/completions", json=body, headers=_labelled(auth, "secret"))
        assert reply.status_code == 403
        assert reply.headers["content-type"].startswith("application/json")
        [record] = _llm_calls(proxy_records(client))
    assert upstream.calls == []
    assert record["outcome"] == "blocked"
    assert record["policy"]["rule_id"] == "recorder/no-secret-to-cloud"
    assert record["extensions"]["sealedrun.llm"]["stream"] is True


@pytest.mark.parametrize(
    ("path", "body", "shape"),
    [
        (
            "/v1/messages",
            {"model": "claude-sonnet-4-5", "max_tokens": 5, "messages": MESSAGES},
            {"type": "error", "error": {"type": "permission_error"}},
        ),
        (
            "/v1beta/models/gemini-2.5-flash:generateContent",
            {"contents": [{"parts": [{"text": "hi"}]}]},
            {"error": {"code": 403, "status": "PERMISSION_DENIED"}},
        ),
        ("/api/chat", {"model": "qwen3:8b", "messages": MESSAGES}, {"error": str}),
    ],
)
def test_403_in_every_dialect_shape(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    proxy_records: Any,
    path: str,
    body: dict[str, Any],
    shape: dict[str, Any],
) -> None:
    with make_proxy(CONFIG, **RULE) as client:
        reply = client.post(path, json=body, headers=_labelled(auth, "nda"))
        assert reply.status_code == 403, reply.text
        answer = reply.json()
        [record] = _llm_calls(proxy_records(client))
    assert upstream.calls == []
    assert record["outcome"] == "blocked"
    if shape == {"error": str}:
        assert answer["error"].startswith("blocked by policy recorder/no-nda-to-cloud")
    else:
        for key, expected in shape.items():
            if isinstance(expected, dict):
                assert all(answer[key][k] == v for k, v in expected.items())
                assert "no-nda-to-cloud" in answer[key]["message"]
            else:
                assert answer[key] == expected


def test_allowed_cloud_call_carries_the_allow_decision(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/chat/completions"] = CHAT_REPLY
    body = {"model": "gpt-4.1", "messages": MESSAGES}
    with make_proxy(CONFIG, **RULE) as client:
        assert (
            client.post(
                "/v1/chat/completions", json=body, headers=_labelled(auth, "pii")
            ).status_code
            == 200
        )
        assert client.post("/v1/chat/completions", json=body, headers=auth).status_code == 200
        records = _llm_calls(proxy_records(client))
        run = client.get("/api/runs", headers=auth).json()[0]
    assert len(upstream.calls) == 2
    labelled, plain = records
    assert labelled["outcome"] == "success"
    assert labelled["policy"] == {
        "rule_id": "default/allow",
        "decision": "allow",
        "reason": "target.location=cloud and no configured label is present",
    }
    assert plain["policy"]["decision"] == "allow"
    assert run["labels_sent_to_cloud"] == {"pii": 1}


def test_local_target_gets_no_policy_object(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/api/chat"] = OLLAMA_REPLY
    with make_proxy(CONFIG, **RULE) as client:
        local = {"model": "llama3", "messages": MESSAGES, "stream": False}
        reply = client.post("/api/chat", json=local, headers=_labelled(auth, "nda"))
        assert reply.status_code == 200
        [record] = _llm_calls(proxy_records(client))
    assert record["outcome"] == "success"
    assert "policy" not in record
    assert record["data_labels"] == ["nda"]


def test_rule_off_gets_no_policy_object(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/chat/completions"] = CHAT_REPLY
    with make_proxy(CONFIG) as client:
        cloud = {"model": "gpt-4.1", "messages": MESSAGES}
        reply = client.post("/v1/chat/completions", json=cloud, headers=_labelled(auth, "nda"))
        assert reply.status_code == 200
        [record] = _llm_calls(proxy_records(client))
    assert record["outcome"] == "success"
    assert "policy" not in record


MCP_CONFIG = """
mcp_servers:
  - name: saas
    url: https://mcp.example/mcp
    location: cloud
  - name: local
    url: http://mcp.test/mcp
    location: local
a2a_agents:
  - name: hosted
    url: https://agent.example/rpc
    location: cloud
"""
MCP_RESULT = {"jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": "3"}]}}
A2A_RESULT = {
    "jsonrpc": "2.0",
    "id": 1,
    "result": {"task": {"id": "t-1", "status": {"state": "TASK_STATE_COMPLETED"}}},
}


def _rpc(method: str, params: dict[str, Any], rid: Any = 7) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}


def _a2a(method: str = "SendMessage") -> dict[str, Any]:
    message = {"messageId": "m-1", "role": "ROLE_USER", "parts": [{"text": "the NDA"}]}
    return _rpc(method, {"message": message}, 1)


@pytest.fixture
def token(secrets: dict[str, str]) -> dict[str, str]:
    return {"X-SealedRun-Token": secrets["token"], "Content-Type": "application/json"}


def _tool_calls(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in records if r["kind"] == "tool_call"]


@pytest.mark.parametrize(
    "method, params",
    [
        ("tools/call", {"name": "add", "arguments": {"a": 1}}),
        ("resources/read", {"uri": "file:///nda.txt"}),
        ("prompts/get", {"name": "summarise"}),
    ],
)
def test_mcp_call_to_a_cloud_server_is_blocked(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    token: dict[str, str],
    auth: dict[str, str],
    proxy_records: Any,
    method: str,
    params: dict[str, Any],
) -> None:
    upstream.routes["/mcp"] = MCP_RESULT
    body = _rpc(method, params, "req-9")
    headers = _labelled(token, "nda", **{"Mcp-Method": method, "X-SealedRun-Run": "mcp"})
    with make_proxy(MCP_CONFIG, **RULE) as client:
        reply = client.post("/mcp/saas", json=body, headers=headers)
        assert reply.status_code == 403, reply.text
        records = proxy_records(client)
        [record] = _tool_calls(records)
        missing = client.get(f"/api/records/{record['record_id']}/payload/response", headers=auth)
        delegation = client.get("/api/identity", headers=auth).json()["delegation"]
    assert reply.json() == {
        "jsonrpc": "2.0",
        "id": "req-9",
        "error": {
            "code": 40003,
            "message": "blocked by policy recorder/no-nda-to-cloud: target.location=cloud and"
            " labels contain nda",
        },
    }
    assert upstream.calls == []
    assert record["outcome"] == "blocked"
    assert record["policy"] == BLOCK
    assert record["target"]["provider"] == "mcp:saas"
    assert record["extensions"]["sealedrun.mcp"]["method"] == method
    assert record["extensions"]["sealedrun.mcp"]["is_error"] is False
    assert record["extensions"]["sealedrun.proxy"]["status"] == 403
    assert "truncated" not in record["extensions"]["sealedrun.proxy"]
    assert "response_hash" not in record["payload"]
    assert missing.status_code == 404
    assert validator("record.json").is_valid(record)
    verify_run(records, {delegation["delegation_id"]: delegation})


def test_mcp_allow_and_unlisted_methods(
    make_proxy: Callable[..., TestClient], upstream: Any, token: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/mcp"] = MCP_RESULT
    listing = {"jsonrpc": "2.0", "id": 7, "result": {"tools": [{"name": "add"}]}}
    with make_proxy(MCP_CONFIG, **RULE) as client:
        headers = _labelled(token, "pii", **{"Mcp-Method": "tools/call"})
        call = _rpc("tools/call", {"name": "add"})
        assert client.post("/mcp/saas", json=call, headers=headers).status_code == 200
        upstream.routes["/mcp"] = listing
        headers = _labelled(token, "nda", **{"Mcp-Method": "tools/list"})
        assert (
            client.post("/mcp/saas", json=_rpc("tools/list", {}), headers=headers).status_code
            == 200
        )
        upstream.routes["/mcp"] = MCP_RESULT
        headers = _labelled(token, "nda", **{"Mcp-Method": "tools/call"})
        assert client.post("/mcp/local", json=call, headers=headers).status_code == 200
        allowed, listed, local = _tool_calls(proxy_records(client))
    assert len(upstream.calls) == 3
    assert allowed["policy"]["decision"] == "allow"
    assert allowed["outcome"] == "success"
    assert "policy" not in listed
    assert "policy" not in local


def test_a2a_delegation_to_a_cloud_agent_is_blocked_in_both_bindings(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    token: dict[str, str],
    auth: dict[str, str],
    proxy_records: Any,
) -> None:
    upstream.routes["/rpc"] = A2A_RESULT
    headers = _labelled(token, "nda", **{"A2A-Version": "1.0", "X-SealedRun-Run": "a2a"})
    with make_proxy(MCP_CONFIG, **RULE) as client:
        rpc = client.post("/a2a/hosted", json=_a2a("SendStreamingMessage"), headers=headers)
        rest = client.post("/a2a/hosted/message:send", json={"message": {}}, headers=headers)
        cancel = client.post(
            "/a2a/hosted", json=_rpc("CancelTask", {"id": "t-1"}, 2), headers=headers
        )
        records = proxy_records(client)
        blocked_rpc, blocked_rest, cancelled = _tool_calls(records)
        delegation = client.get("/api/identity", headers=auth).json()["delegation"]
    assert rpc.status_code == 403
    assert rpc.json()["id"] == 1
    assert rpc.json()["error"]["code"] == 40003
    assert "no-nda-to-cloud" in rpc.json()["error"]["message"]
    assert rest.status_code == 403
    assert rest.json()["status"] == "PERMISSION_DENIED"
    assert rest.json()["code"] == 7
    assert cancel.status_code == 403
    assert cancel.json()["id"] == 2
    assert upstream.calls == []
    for record in (blocked_rpc, blocked_rest, cancelled):
        assert record["outcome"] == "blocked"
        assert record["policy"] == BLOCK
        assert record["extensions"]["sealedrun.a2a"]["is_error"] is False
        assert "truncated" not in record["extensions"]["sealedrun.proxy"]
        assert validator("record.json").is_valid(record)
    assert blocked_rpc["extensions"]["sealedrun.a2a"]["binding"] == "jsonrpc"
    assert blocked_rest["extensions"]["sealedrun.a2a"]["binding"] == "rest"
    assert cancelled["target"]["name"] == "hosted/cancel"
    verify_run(records, {delegation["delegation_id"]: delegation})


@pytest.mark.parametrize(
    ("verb", "path", "body", "method", "name"),
    [
        ("POST", "/a2a/hosted", _rpc("GetTask", {"id": "t-1"}, 3), "GetTask", "hosted/GetTask"),
        ("POST", "/a2a/hosted", _rpc("message/send", {}, "x"), "message/send", "hosted/message"),
        (
            "POST",
            "/a2a/hosted",
            _rpc("tasks/cancel", {"id": "t"}, 4),
            "tasks/cancel",
            "hosted/cancel",
        ),
        (
            "POST",
            "/a2a/hosted",
            _rpc("custom/Anything", {"secret": 1}, 5),
            "custom/Anything",
            "hosted/custom/Anything",
        ),
        (
            "PUT",
            "/a2a/hosted/tasks/t-1/pushNotificationConfigs/c-1",
            {"url": "https://evil.example"},
            "PUT /tasks/t-1/pushNotificationConfigs/c-1",
            "hosted/PUT /tasks/t-1/pushNotificationConfigs/c-1",
        ),
        ("PATCH", "/a2a/hosted/tasks/t-1", {"x": 1}, "PATCH /tasks/t-1", "hosted/PATCH /tasks/t-1"),
        (
            "POST",
            "/a2a/hosted/tasks/t-1:subscribe",
            {},
            "POST /tasks/t-1:subscribe",
            "hosted/POST /tasks/t-1:subscribe",
        ),
    ],
)
def test_every_body_request_to_a_cloud_agent_is_governed(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    token: dict[str, str],
    proxy_records: Any,
    verb: str,
    path: str,
    body: dict[str, Any],
    method: str,
    name: str,
) -> None:
    headers = _labelled(token, "nda", **{"X-SealedRun-Run": "a2a"})
    with make_proxy(MCP_CONFIG, **RULE) as client:
        reply = client.request(verb, path, json=body, headers=headers)
        assert reply.status_code == 403, reply.text
        [record] = _tool_calls(proxy_records(client))
    assert upstream.calls == []
    assert record["outcome"] == "blocked"
    assert record["policy"] == BLOCK
    assert record["extensions"]["sealedrun.a2a"]["method"] == method
    assert record["target"]["name"] == name
    assert validator("record.json").is_valid(record)


def test_unreadable_cloud_requests_are_refused_and_local_ones_pass(
    make_proxy: Callable[..., TestClient], upstream: Any, token: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/rpc"] = A2A_RESULT
    upstream.routes["/tasks/t-1"] = {"task": {"id": "t-1"}}
    config = MCP_CONFIG + "  - name: nearby\n    url: http://agent.test/rpc\n    location: local\n"
    with make_proxy(config, **RULE) as client:
        for body in (b"not json", b"[]", b'[{"jsonrpc":"2.0","id":1,"method":"SendMessage"}]'):
            reply = client.post("/a2a/hosted", content=body, headers=token)
            assert reply.status_code == 400, body
            assert reply.json()["error"]["code"] == 40000
        for body in (
            _rpc("GetTask", {"id": "t-1"}, 1.5),
            _rpc("GetTask", {"id": "t-1"}, None),
            {"jsonrpc": "2.0", "id": 1, "method": 7},
            {"jsonrpc": "2.0", "id": 1},
        ):
            assert client.post("/a2a/hosted", json=body, headers=token).status_code == 400
        assert client.post("/a2a/hosted/tasks", content=b"raw", headers=token).status_code == 400
        assert upstream.calls == []
        assert client.post("/a2a/nearby", content=b"not json", headers=token).status_code == 200
        get = _rpc("GetTask", {"id": "t-1"}, 1)
        assert client.post("/a2a/nearby", json=get, headers=token).status_code == 200
        assert client.put("/a2a/nearby/tasks/t-1", json={}, headers=token).status_code == 200
        assert len(upstream.calls) == 3
        assert _tool_calls(proxy_records(client)) == []


def test_rule_labels_are_validated_at_startup(make_app: Callable[..., Any], tmp_path: Any) -> None:
    from sealedrun_recorder.policy import PolicyConfigError

    for label in ("NDA", "nda secret", "", "acme:tier:1", "nda,"):
        with pytest.raises(PolicyConfigError, match="SEALEDRUN_POLICY_BLOCK_TO_CLOUD"):
            Rule((label,))
    Rule(("nda", "acme:tier-1", "a_b-c"))
    app = make_app(MCP_CONFIG, policy_block_to_cloud=["nda", "Secret"])
    with pytest.raises(PolicyConfigError), TestClient(app):
        pass


def test_a2a_allowed_delegation_carries_the_allow_decision(
    make_proxy: Callable[..., TestClient], upstream: Any, token: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/rpc"] = A2A_RESULT
    headers = _labelled(token, "pii", **{"A2A-Version": "1.0"})
    with make_proxy(MCP_CONFIG, **RULE) as client:
        assert client.post("/a2a/hosted", json=_a2a(), headers=headers).status_code == 200
        [record] = _tool_calls(proxy_records(client))
    assert record["outcome"] == "success"
    assert record["policy"]["rule_id"] == "default/allow"
