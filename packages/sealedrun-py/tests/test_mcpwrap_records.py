import json
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

ECHO = str(Path(__file__).parent / "mcp" / "echo_server.py")
WRAP = [sys.executable, "-m", "sealedrun.mcpwrap"]
MODERN_META = {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}


class FakeRecorder:
    """Captures every POST /api/steps; `status` sets the answer it gives."""

    def __init__(self) -> None:
        self.posts: list[dict[str, Any]] = []
        self.headers: list[dict[str, str]] = []
        self.status = 201
        recorder = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length))
                recorder.posts.append({"path": self.path, "body": body})
                recorder.headers.append({k.lower(): v for k, v in self.headers.items()})
                self.send_response(recorder.status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    b'{"record_id": "r"}' if recorder.status < 300 else b'{"detail":"no"}'
                )

            def log_message(self, *args: Any) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def steps(self) -> list[dict[str, Any]]:
        return [p["body"] for p in self.posts]


@pytest.fixture
def recorder() -> Iterator[FakeRecorder]:
    fake = FakeRecorder()
    yield fake
    fake.close()


def _spawn(url: str, *args: str, env: dict[str, str] | None = None) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [
            *WRAP,
            "--server",
            "calc",
            "--run",
            "job-9",
            "--url",
            url,
            "--token",
            "tok",
            *args,
            "--",
            sys.executable,
            ECHO,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, **(env or {})},
    )


def _request(method: str, rid: Any = 1, meta: dict[str, Any] | None = None, **params: Any) -> bytes:
    if meta is not None:
        params["_meta"] = meta
    return json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}).encode()


def _send(proc: subprocess.Popen[bytes], line: bytes) -> None:
    assert proc.stdin is not None
    proc.stdin.write(line + b"\n")
    proc.stdin.flush()


def _readline(proc: subprocess.Popen[bytes]) -> Any:
    assert proc.stdout is not None
    return json.loads(proc.stdout.readline())


def _finish(proc: subprocess.Popen[bytes]) -> bytes:
    _, err = proc.communicate(timeout=10)
    return err


def test_tool_call_is_posted_before_the_reply_is_delivered(recorder: FakeRecorder) -> None:
    proc = _spawn(recorder.url)
    _send(proc, _request("tools/call", 5, MODERN_META, name="add", arguments={"a": 1}))
    reply = _readline(proc)
    posted_before_reply = len(recorder.posts)
    err = _finish(proc)
    assert reply["id"] == 5
    assert posted_before_reply == 1
    [post] = recorder.posts
    step = post["body"]
    assert post["path"] == "/api/steps"
    assert recorder.headers[0]["authorization"] == "Bearer tok"
    assert recorder.headers[0]["x-sealedrun-run"] == "job-9"
    assert step["kind"] == "tool_call"
    assert step["outcome"] == "success"
    assert step["target"] == {
        "type": "tool",
        "name": "add",
        "endpoint": os.path.basename(sys.executable),
        "location": "local",
        "provider": "mcp:calc",
    }
    assert step["extensions"]["sealedrun.mcp"] == {
        "server": "calc",
        "transport": "stdio",
        "method": "tools/call",
        "request_id": 5,
        "is_error": False,
        "tool": "add",
        "protocol_version": "2026-07-28",
    }
    proxy = step["extensions"]["sealedrun.proxy"]
    assert (proxy["upstream"], proxy["dialect"], proxy["operation"]) == (
        "calc",
        "mcp",
        "tools/call",
    )
    assert proxy["latency_ms"] >= 0
    assert "truncated" not in proxy
    assert json.loads(step["request"])["id"] == 5
    assert json.loads(step["response"]) == reply
    assert step["request_media_type"] == step["response_media_type"] == "application/json"
    assert b"tok" not in err


def test_legacy_initialize_version_is_remembered(recorder: FakeRecorder) -> None:
    proc = _spawn(recorder.url)
    _send(proc, _request("initialize", 0, protocolVersion="2025-11-25", capabilities={}))
    assert _readline(proc)["result"]["protocolVersion"] == "2025-11-25"
    _send(proc, _request("resources/read", 1, uri="file:///a.txt"))
    _readline(proc)
    _send(proc, _request("prompts/get", 2, name="greet"))
    _readline(proc)
    _finish(proc)
    steps = recorder.steps()
    assert [s["extensions"]["sealedrun.mcp"]["method"] for s in steps] == [
        "resources/read",
        "prompts/get",
    ]
    assert [s["target"]["name"] for s in steps] == ["file:///a.txt", "greet"]
    assert all(s["extensions"]["sealedrun.mcp"]["protocol_version"] == "2025-11-25" for s in steps)
    assert all("tool" not in s["extensions"]["sealedrun.mcp"] for s in steps)


@pytest.mark.parametrize(
    ("arguments", "outcome", "is_error", "result_type"),
    [
        ({"fail": True}, "error", True, None),
        ({"is_error": True}, "error", True, None),
        ({"input_required": True}, "pending", False, "input_required"),
    ],
)
def test_outcomes_follow_the_result(
    recorder: FakeRecorder,
    arguments: dict[str, Any],
    outcome: str,
    is_error: bool,
    result_type: str | None,
) -> None:
    proc = _spawn(recorder.url)
    _send(proc, _request("tools/call", 1, name="add", arguments=arguments))
    _readline(proc)
    _finish(proc)
    [step] = recorder.steps()
    mcp = step["extensions"]["sealedrun.mcp"]
    assert (step["outcome"], mcp["is_error"], mcp.get("result_type")) == (
        outcome,
        is_error,
        result_type,
    )


def test_cancelled_and_abandoned_requests_are_truncated(recorder: FakeRecorder) -> None:
    proc = _spawn(recorder.url)
    _send(proc, _request("tools/call", 1, name="add", arguments={"sleep": 1}))
    cancel = {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": {"requestId": 1}}
    _send(proc, json.dumps(cancel).encode())
    deadline = time.monotonic() + 5
    while len(recorder.posts) < 1 and time.monotonic() < deadline:
        time.sleep(0.05)
    late = _readline(proc)
    _send(proc, _request("tools/call", 2, name="add", arguments={"crash": True}))
    proc.wait(timeout=10)
    steps = recorder.steps()
    assert late["id"] == 1
    assert [s["extensions"]["sealedrun.mcp"]["request_id"] for s in steps] == [1, 2]
    for step in steps:
        assert step["outcome"] == "error"
        assert step["extensions"]["sealedrun.proxy"]["truncated"] is True
        assert "response" not in step
    assert proc.returncode == 9


def test_unrecorded_messages_are_not_posted(recorder: FakeRecorder) -> None:
    proc = _spawn(recorder.url)
    _send(proc, _request("server/discover", 1))
    _readline(proc)
    _send(proc, _request("initialize", 2, protocolVersion="2025-11-25"))
    _readline(proc)
    notice = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    _send(proc, json.dumps(notice).encode())
    _send(proc, _request("subscriptions/listen", 3))
    _readline(proc)
    _send(proc, _request("ping", 4))
    _readline(proc)
    _send(proc, json.dumps({"jsonrpc": "2.0", "id": 99, "result": {}}).encode())
    _send(proc, _request("tools/list", 5))
    _readline(proc)
    _finish(proc)
    assert [s["extensions"]["sealedrun.mcp"]["method"] for s in recorder.steps()] == ["tools/list"]


def test_recorder_down_delivers_the_reply_and_warns() -> None:
    proc = _spawn("http://127.0.0.1:9")
    _send(proc, _request("tools/call", 1, name="add", arguments={}))
    reply = _readline(proc)
    err = _finish(proc)
    assert reply["id"] == 1 and "result" in reply
    assert b"sealedrun-mcp-wrap: recorder unreachable" in err
    assert proc.returncode == 0


def test_recorder_refusal_is_reported(recorder: FakeRecorder) -> None:
    recorder.status = 400
    proc = _spawn(recorder.url)
    _send(proc, _request("tools/call", 1, name="add", arguments={}))
    reply = _readline(proc)
    err = _finish(proc)
    assert "result" in reply
    assert b"recorder refused the tools/call record: 400" in err


def test_strict_mode_withholds_the_result(recorder: FakeRecorder) -> None:
    recorder.status = 503
    proc = _spawn(recorder.url, "--strict")
    _send(proc, _request("tools/call", 7, name="add", arguments={}))
    reply = _readline(proc)
    _send(proc, _request("ping", 8))
    ping = _readline(proc)
    _finish(proc)
    assert reply["id"] == 7
    assert reply["error"]["code"] == 1001
    assert "recorder" in reply["error"]["message"]
    assert ping["result"] == {"echo": "ping"}


def test_concurrent_requests_are_matched_by_id(recorder: FakeRecorder) -> None:
    proc = _spawn(recorder.url)
    _send(proc, _request("tools/call", "slow", name="add", arguments={"sleep": 0.5, "n": 1}))
    _send(proc, _request("tools/call", "fast", name="add", arguments={"n": 2}))
    first = _readline(proc)
    second = _readline(proc)
    _finish(proc)
    assert {first["id"], second["id"]} == {"slow", "fast"}
    by_id = {s["extensions"]["sealedrun.mcp"]["request_id"]: s for s in recorder.steps()}
    assert set(by_id) == {"slow", "fast"}
    for rid, step in by_id.items():
        assert json.loads(step["request"])["id"] == rid
        assert json.loads(step["response"])["id"] == rid
    assert by_id["slow"]["extensions"]["sealedrun.proxy"]["latency_ms"] >= 500


def test_signal_during_call_records_truncation(recorder: FakeRecorder) -> None:
    proc = _spawn(recorder.url)
    _send(proc, _request("ping", 0))
    assert _readline(proc)["id"] == 0
    _send(proc, _request("tools/call", 1, name="add", arguments={"sleep": 30}))
    time.sleep(0.3)
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=10)
    [step] = recorder.steps()
    assert step["extensions"]["sealedrun.proxy"]["truncated"] is True


def test_child_does_not_inherit_the_recorder_settings(recorder: FakeRecorder) -> None:
    probe = [
        sys.executable,
        "-c",
        "import os; print(sorted(k for k in os.environ if k.startswith('SEALEDRUN')))",
    ]
    proc = subprocess.run(
        [*WRAP, "--url", recorder.url, "--token", "tok", "--run", "r", "--", *probe],
        input=b"",
        capture_output=True,
        timeout=10,
        env={**os.environ, "SEALEDRUN_TOKEN": "tok", "SEALEDRUN_URL": recorder.url},
    )
    assert proc.stdout.strip() == b"[]"


def test_duplicate_request_id_truncates_the_first_call(recorder: FakeRecorder) -> None:
    proc = _spawn(recorder.url)
    _send(proc, _request("tools/call", 1, name="add", arguments={"sleep": 0.5}))
    _send(proc, _request("tools/call", 1, name="add", arguments={"n": 2}))
    _readline(proc)
    _readline(proc)
    _finish(proc)
    steps = recorder.steps()
    assert len(steps) == 2
    assert steps[0]["extensions"]["sealedrun.proxy"].get("truncated") is True
    assert "truncated" not in steps[1]["extensions"]["sealedrun.proxy"]


def test_batch_is_relayed_with_a_warning(recorder: FakeRecorder) -> None:
    proc = _spawn(recorder.url)
    batch = [json.loads(_request("tools/call", 1, name="add", arguments={}))]
    _send(proc, json.dumps(batch).encode())
    _send(proc, _request("ping", 2))
    assert _readline(proc)["id"] == 2
    err = _finish(proc)
    assert b"batch relayed without recording" in err
    assert recorder.steps() == []
