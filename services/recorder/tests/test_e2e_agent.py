"""One agent turn end to end: LLM and MCP calls through the proxy, export, both verifiers."""

import json
import shutil
import subprocess
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sealedrun import read_bundle, verify_bundle

TS_DIST = Path(__file__).resolve().parents[3] / "packages" / "sealedrun-ts" / "dist" / "index.js"

CONFIG = """
upstreams:
  - name: cloud
    url: https://cloud.example/v1
    dialect: openai
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["gpt-*"]
mcp_servers:
  - name: files
    url: http://mcp.test/mcp
    key_env: TEST_UPSTREAM_KEY
    location: local
"""
RUN = "agent-turn-1"
TOOLS = {"tools": [{"name": "read_file", "inputSchema": {"type": "object"}}]}
READ_FILE = {"content": [{"type": "text", "text": "hello from disk"}]}


def _sse_chunk(delta: dict[str, Any], finish: str | None = None) -> bytes:
    body = {"id": "c1", "object": "chat.completion.chunk", "model": "gpt-4.1"}
    body["choices"] = [{"index": 0, "delta": delta, "finish_reason": finish}]
    return b"data: " + json.dumps(body).encode() + b"\n\n"


TOOL_CALL_STREAM = [
    _sse_chunk({"role": "assistant", "content": ""}),
    _sse_chunk(
        {
            "tool_calls": [
                {
                    "index": 0,
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "read_file", "arguments": '{"path":"a.txt"}'},
                }
            ]
        }
    ),
    _sse_chunk({}, "tool_calls"),
    b'data: {"id":"c1","object":"chat.completion.chunk","choices":[],'
    b'"usage":{"prompt_tokens":20,"completion_tokens":9}}\n\n',
    b"data: [DONE]\n\n",
]
FINAL_REPLY = {
    "id": "c2",
    "model": "gpt-4.1",
    "choices": [
        {
            "index": 0,
            "message": {"role": "assistant", "content": "The file says: hello from disk"},
            "finish_reason": "stop",
        }
    ],
    "usage": {"prompt_tokens": 40, "completion_tokens": 8},
}


class Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            yield chunk


class FakeMcp:
    """Answers `tools/list` and `tools/call`; `broken` makes the tool report an error."""

    def __init__(self, broken: bool = False) -> None:
        self.broken = broken

    def __call__(self, request: httpx.Request) -> httpx.Response:
        message = json.loads(request.content)
        if message["method"] == "tools/list":
            result: dict[str, Any] = TOOLS
        elif self.broken:
            result = {"content": [{"type": "text", "text": "no such file"}], "isError": True}
        else:
            result = READ_FILE
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": message["id"], "result": result})


class FakeChat:
    """First call streams a tool call, the second answers in full; `fail_second` makes it 500."""

    def __init__(self, fail_second: bool = False) -> None:
        self.calls = 0
        self.fail_second = fail_second

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls += 1
        if self.calls == 1:
            headers = {"content-type": "text/event-stream"}
            return httpx.Response(200, headers=headers, stream=Chunks(TOOL_CALL_STREAM))
        if self.fail_second:
            return httpx.Response(500, json={"error": {"message": "model overloaded"}})
        return httpx.Response(200, json=FINAL_REPLY)


def _agent_turn(client: TestClient, token: str) -> list[int]:
    """What a small agent does: ask the model, list tools, call the tool, ask again."""
    llm = {"Authorization": f"Bearer {token}", "X-SealedRun-Run": RUN}
    mcp = {"X-SealedRun-Token": token, "X-SealedRun-Run": RUN}
    messages: list[dict[str, Any]] = [{"role": "user", "content": "what is in a.txt?"}]
    first = client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4.1", "messages": messages, "stream": True},
        headers=llm,
    )
    statuses = [first.status_code]
    for line in first.text.splitlines():
        if line.startswith("data: {"):
            delta = json.loads(line[6:])["choices"]
            if delta and "tool_calls" in delta[0]["delta"]:
                arguments = json.loads(delta[0]["delta"]["tool_calls"][0]["function"]["arguments"])
    listing = client.post(
        "/mcp/files",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        headers=mcp,
    )
    statuses.append(listing.status_code)
    assert [t["name"] for t in listing.json()["result"]["tools"]] == ["read_file"]
    call = client.post(
        "/mcp/files",
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": arguments},
        },
        headers=mcp,
    )
    statuses.append(call.status_code)
    messages.append({"role": "tool", "tool_call_id": "call_1", "content": call.json()["result"]})
    second = client.post(
        "/v1/chat/completions", json={"model": "gpt-4.1", "messages": messages}, headers=llm
    )
    statuses.append(second.status_code)
    return statuses


def _export(client: TestClient, token: str) -> tuple[bytes, str]:
    api = {"Authorization": f"Bearer {token}"}
    [summary] = client.get("/api/runs", headers=api).json()
    assert summary["run_label"] == RUN
    principal = client.get("/api/identity", headers=api).json()["principal_id"]
    exported = client.post(f"/api/runs/{summary['run_id']}/export?end=true", headers=api)
    assert exported.status_code == 200
    return exported.content, str(principal)


def _verify_with_typescript(bundle: bytes, principal: str, tmp_path: Path) -> dict[str, Any]:
    node = shutil.which("node")
    if node is None or not TS_DIST.exists():
        pytest.skip("TypeScript verifier not built; `pnpm --filter @sealedrun/core build`")
    path = tmp_path / "run.zip"
    path.write_bytes(bundle)
    script = (
        f"import {{ readBundle, verifyBundleAsync }} from {json.dumps(TS_DIST.as_uri())};\n"
        "import { readFileSync } from 'node:fs';\n"
        f"const bundle = readBundle(new Uint8Array(readFileSync({json.dumps(str(path))})));\n"
        f"const trusted = {{ trustedPrincipals: [{principal!r}] }};\n"
        "const report = await verifyBundleAsync(bundle, trusted);\n"
        "console.log(JSON.stringify(report));\n"
    )
    (tmp_path / "verify.mjs").write_text(script)
    done = subprocess.run(
        [node, str(tmp_path / "verify.mjs")], capture_output=True, text=True, check=True
    )
    return dict(json.loads(done.stdout))


def test_agent_turn_exports_a_bundle_both_verifiers_accept(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: dict[str, str], tmp_path: Path
) -> None:
    upstream.routes["/chat/completions"] = FakeChat()
    upstream.routes["/mcp"] = FakeMcp()
    with make_proxy(CONFIG) as client:
        assert _agent_turn(client, secrets["token"]) == [200, 200, 200, 200]
        bundle, principal = _export(client, secrets["token"])

    report = verify_bundle(read_bundle(bundle), [principal])
    assert report.principal_trusted
    [run] = report.runs
    assert (run.record_count, run.complete) == (6, True)
    records = next(iter(read_bundle(bundle).runs.values()))
    assert [r["kind"] for r in records] == [
        "run_start",
        "llm_call",
        "tool_call",
        "tool_call",
        "llm_call",
        "run_end",
    ]
    assert [r["outcome"] for r in records[1:-1]] == ["success"] * 4
    assert [r["target"]["name"] for r in records[2:4]] == ["tools/list", "read_file"]
    first_llm = records[1]["extensions"]["sealedrun.llm"]
    assert (first_llm["stream"], first_llm["finish_reason"]) == (True, "tool_calls")
    assert first_llm["tool_calls_requested"] == ["read_file"]
    assert records[4]["extensions"]["sealedrun.llm"]["output_tokens"] == 8
    assert secrets["upstream_key"] not in json.dumps(records)

    ts = _verify_with_typescript(bundle, principal, tmp_path)
    assert ts["principalTrusted"] is True
    assert [(r["recordCount"], r["complete"]) for r in ts["runs"]] == [(6, True)]


def test_model_failure_mid_turn_is_an_error_record_and_the_run_still_verifies(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: dict[str, str]
) -> None:
    upstream.routes["/chat/completions"] = FakeChat(fail_second=True)
    upstream.routes["/mcp"] = FakeMcp()
    with make_proxy(CONFIG) as client:
        assert _agent_turn(client, secrets["token"]) == [200, 200, 200, 500]
        bundle, principal = _export(client, secrets["token"])
    report = verify_bundle(read_bundle(bundle), [principal])
    assert report.principal_trusted and report.runs[0].complete
    records = next(iter(read_bundle(bundle).runs.values()))
    assert records[4]["kind"] == "llm_call"
    assert records[4]["outcome"] == "error"
    assert records[4]["extensions"]["sealedrun.proxy"]["status"] == 500


def test_tool_failure_is_an_error_record_and_the_run_still_verifies(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: dict[str, str]
) -> None:
    upstream.routes["/chat/completions"] = FakeChat()
    upstream.routes["/mcp"] = FakeMcp(broken=True)
    with make_proxy(CONFIG) as client:
        assert _agent_turn(client, secrets["token"]) == [200, 200, 200, 200]
        bundle, principal = _export(client, secrets["token"])
    report = verify_bundle(read_bundle(bundle), [principal])
    assert report.principal_trusted and report.runs[0].complete
    records = next(iter(read_bundle(bundle).runs.values()))
    assert [r["outcome"] for r in records[1:-1]] == ["success", "success", "error", "success"]
