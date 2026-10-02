"""`sealedrun.context` on `run_start` (SPEC 10.6): who ran, under which policy and tools."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sealedrun import verify_run
from sealedrun.canonical import canonicalize
from sealedrun.schema import validate_extensions
from sealedrun_recorder import __version__
from sealedrun_recorder.policy import Rule
from sealedrun_recorder.proxy.context import (
    AgentError,
    client_info_agent,
    header_agent,
    otel_agent,
    tool_inventory_digest,
)

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
"""
CHAT = {"model": "gpt-4.1", "messages": [{"role": "user", "content": "hi"}]}
CHAT_REPLY = {
    "id": "chatcmpl-1",
    "object": "chat.completion",
    "model": "gpt-4.1",
    "choices": [
        {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}
    ],
    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
}
RULE = {"policy_block_to_cloud": ["secret", "nda"]}
RULE_HASH = hashlib.sha256(canonicalize({"block_to_cloud": ["nda", "secret"]})).hexdigest()
TOOLS = [{"name": "sub", "inputSchema": {"type": "object"}}, {"name": "add"}]
TOOLS_HASH = hashlib.sha256(canonicalize(sorted(TOOLS, key=lambda t: t["name"]))).hexdigest()
AGENT = {"X-SealedRun-Agent": "acme-planner/2.3.1"}
SOFTWARE = f"sealedrun-recorder/{__version__}"


@pytest.fixture
def auth(secrets: dict[str, str]) -> dict[str, str]:
    return {"X-SealedRun-Token": secrets["token"], "Content-Type": "application/json"}


@pytest.fixture
def api(secrets: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {secrets['token']}"}


class _Request:
    def __init__(self, value: str | None) -> None:
        self.headers = {} if value is None else {"x-sealedrun-agent": value}


def _mcp(method: str, params: dict[str, Any], request_id: int = 7) -> bytes:
    return json.dumps(
        {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}
    ).encode()


def _run_start(records: list[dict[str, Any]]) -> dict[str, Any]:
    [start] = [r for r in records if r["kind"] == "run_start"]
    return start


def _verified(client: TestClient, api: dict[str, str], records: list[dict[str, Any]]) -> None:
    delegation = client.get("/api/identity", headers=api).json()["delegation"]
    verify_run(records, {delegation["delegation_id"]: delegation})
    for record in records:
        assert validate_extensions(record.get("extensions", {})) == []


def test_header_parsing() -> None:
    assert header_agent(_Request(None)) is None  # type: ignore[arg-type]
    assert header_agent(_Request(" my.agent/1.0+rc1 ")) == ("my.agent", "1.0+rc1")  # type: ignore[arg-type]
    for bad in ("", "noslash", "name/", "/1.0", "na me/1", "n/" + "x" * 33, "x" * 65 + "/1"):
        with pytest.raises(AgentError):
            header_agent(_Request(bad))  # type: ignore[arg-type]


def test_client_info_and_otel_agents() -> None:
    meta = {"io.modelcontextprotocol/clientInfo": {"name": "codex", "version": "0.159.0"}}
    assert client_info_agent({"params": {"_meta": meta}}) == ("codex", "0.159.0")
    assert (
        client_info_agent({"params": {"_meta": {"io.modelcontextprotocol/clientInfo": 1}}}) is None
    )
    assert (
        client_info_agent(
            {
                "params": {
                    "_meta": {"io.modelcontextprotocol/clientInfo": {"name": "x y", "version": "1"}}
                }
            }
        )
        is None
    )
    assert client_info_agent("nope") is None
    assert otel_agent({"gen_ai.agent.name": "planner", "gen_ai.agent.version": "3"}) == (
        "planner",
        "3",
    )
    assert otel_agent({"gen_ai.agent.name": "planner"}) is None


def test_tool_inventory_digest_is_order_independent() -> None:
    assert tool_inventory_digest({"tools": TOOLS}) == TOOLS_HASH
    assert tool_inventory_digest({"tools": list(reversed(TOOLS))}) == TOOLS_HASH
    assert tool_inventory_digest({"tools": [{"noname": 1}]}) is None
    assert tool_inventory_digest({"tools": "x"}) is None
    assert tool_inventory_digest(None) is None


def test_rule_set_hash() -> None:
    assert Rule().set_hash is None
    assert Rule(("secret", "nda")).set_hash == RULE_HASH
    assert Rule(("nda", "secret", "nda")).set_hash == RULE_HASH
    rule = Rule(("nda",))
    allowed, blocked = rule.evaluate("cloud", []), rule.evaluate("cloud", ["nda"])
    assert allowed is not None and blocked is not None
    assert allowed.document()["policy_set_hash"] == rule.set_hash
    assert blocked.document()["policy_set_hash"] == rule.set_hash
    assert Rule().evaluate("cloud", []) is None


def test_llm_call_opens_a_run_with_the_context(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    api: dict[str, str],
    proxy_records: Any,
) -> None:
    upstream.routes["/chat/completions"] = CHAT_REPLY
    with make_proxy(CONFIG, **RULE) as client:
        labelled = {**auth, **AGENT, "X-SealedRun-Labels": "pii"}
        assert client.post("/v1/chat/completions", json=CHAT, headers=labelled).status_code == 200
        assert client.post("/v1/chat/completions", json=CHAT, headers=auth).status_code == 200
        records = proxy_records(client)
        _verified(client, api, records)
    assert "x-sealedrun-agent" not in upstream.calls[0].headers
    context = _run_start(records)["extensions"]["sealedrun.context"]
    assert context == {
        "recorder_software": SOFTWARE,
        "agent_software": "acme-planner",
        "agent_version": "2.3.1",
        "agent_source": "header",
        "policy_set_hash": RULE_HASH,
    }
    calls = [r for r in records if r["kind"] == "llm_call"]
    assert all(r["policy"]["policy_set_hash"] == RULE_HASH for r in calls)


def test_without_header_or_rule_only_the_recorder_is_named(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/chat/completions"] = CHAT_REPLY
    with make_proxy(CONFIG) as client:
        assert client.post("/v1/chat/completions", json=CHAT, headers=auth).status_code == 200
        records = proxy_records(client)
    assert _run_start(records)["extensions"]["sealedrun.context"] == {"recorder_software": SOFTWARE}
    assert "policy" not in next(r for r in records if r["kind"] == "llm_call")


def test_bad_agent_header_is_400_before_any_upstream_call(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str]
) -> None:
    upstream.routes["/chat/completions"] = CHAT_REPLY
    with make_proxy(CONFIG) as client:
        bad = {**auth, "X-SealedRun-Agent": "no version"}
        assert client.post("/v1/chat/completions", json=CHAT, headers=bad).status_code == 400
        assert (
            client.post(
                "/mcp/tools", content=_mcp("tools/call", {"name": "add"}), headers=bad
            ).status_code
            == 400
        )
    assert upstream.calls == []


def test_mcp_tools_list_opens_the_run_with_the_inventory_and_client_info(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    api: dict[str, str],
    proxy_records: Any,
) -> None:
    upstream.routes["/mcp"] = lambda request: httpx.Response(
        200, json={"jsonrpc": "2.0", "id": 7, "result": {"tools": TOOLS}}
    )
    meta = {"io.modelcontextprotocol/clientInfo": {"name": "codex", "version": "0.159.0"}}
    with make_proxy(CONFIG) as client:
        reply = client.post("/mcp/tools", content=_mcp("tools/list", {"_meta": meta}), headers=auth)
        assert reply.status_code == 200, reply.text
        records = proxy_records(client)
        _verified(client, api, records)
    assert _run_start(records)["extensions"]["sealedrun.context"] == {
        "recorder_software": SOFTWARE,
        "agent_software": "codex",
        "agent_version": "0.159.0",
        "agent_source": "mcp_client_info",
        "tool_inventory_server": "tools",
        "tool_inventory_hash": TOOLS_HASH,
    }


def test_mcp_header_wins_over_client_info_and_a_later_list_adds_nothing(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    answers = iter(
        [
            {"jsonrpc": "2.0", "id": 7, "result": {"content": [{"type": "text", "text": "3"}]}},
            {"jsonrpc": "2.0", "id": 7, "result": {"tools": TOOLS}},
        ]
    )
    upstream.routes["/mcp"] = lambda request: httpx.Response(200, json=next(answers))
    meta = {"io.modelcontextprotocol/clientInfo": {"name": "codex", "version": "0.159.0"}}
    with make_proxy(CONFIG) as client:
        headers = {**auth, **AGENT}
        call = _mcp("tools/call", {"name": "add", "_meta": meta})
        assert client.post("/mcp/tools", content=call, headers=headers).status_code == 200
        listing = _mcp("tools/list", {})
        assert client.post("/mcp/tools", content=listing, headers=headers).status_code == 200
        records = proxy_records(client)
    context = _run_start(records)["extensions"]["sealedrun.context"]
    assert (context["agent_software"], context["agent_source"]) == ("acme-planner", "header")
    assert "tool_inventory_hash" not in context
    assert [r["kind"] for r in records] == ["run_start", "tool_call", "tool_call"]


def test_self_reported_step_opens_the_run_with_the_header(
    make_proxy: Callable[..., TestClient], upstream: Any, api: dict[str, str], app_records: Any
) -> None:
    request = {"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}
    response = {"jsonrpc": "2.0", "id": 3, "result": {"tools": TOOLS}}
    step = {
        "kind": "tool_call",
        "target": {
            "type": "tool",
            "name": "tools/list",
            "location": "local",
            "provider": "mcp:calc",
        },
        "outcome": "success",
        "request": json.dumps(request),
        "response": json.dumps(response),
        "request_media_type": "application/json",
        "response_media_type": "application/json",
        "extensions": {
            "sealedrun.mcp": {"server": "calc", "transport": "stdio", "method": "tools/list"}
        },
    }
    with make_proxy(CONFIG) as client:
        headers = {**api, **AGENT, "X-SealedRun-Run": "job-1"}
        assert client.post("/api/steps", json=step, headers=headers).status_code == 201
        assert (
            client.post(
                "/api/steps", json=step, headers={**api, "X-SealedRun-Agent": "x"}
            ).status_code
            == 400
        )
        records = app_records(client.app)
    context = _run_start(records)["extensions"]["sealedrun.context"]
    assert context["agent_source"] == "header"
    assert context["agent_software"] == "acme-planner"
    assert (context["tool_inventory_server"], context["tool_inventory_hash"]) == (
        "calc",
        TOOLS_HASH,
    )


def test_otlp_span_names_the_agent(
    make_proxy: Callable[..., TestClient],
    secrets: dict[str, str],
    otlp_export: Callable[..., Any],
    app_records: Any,
) -> None:
    export = otlp_export(
        [
            {
                "name": "invoke_agent planner",
                "attributes": {
                    "gen_ai.operation.name": "chat",
                    "gen_ai.request.model": "gpt-4.1",
                    "gen_ai.agent.name": "planner",
                    "gen_ai.agent.version": "3.0",
                },
            }
        ]
    )
    with make_proxy(CONFIG) as client:
        reply = client.post(
            "/otlp/v1/traces",
            content=export.SerializeToString(),
            headers={
                "X-SealedRun-Token": secrets["token"],
                "Content-Type": "application/x-protobuf",
            },
        )
        assert reply.status_code == 200, reply.text
        records = app_records(client.app)
    context = _run_start(records)["extensions"]["sealedrun.context"]
    assert (context["agent_software"], context["agent_version"], context["agent_source"]) == (
        "planner",
        "3.0",
        "otel",
    )
