import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from sealedrun.mcpwrap import parse_args, parse_message

ECHO = str(Path(__file__).parent / "mcp" / "echo_server.py")
WRAP = [sys.executable, "-m", "sealedrun.mcpwrap"]


def _request(method: str, rid: int = 1, **params: Any) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}).encode()


def _spawn(*args: str, env: dict[str, str] | None = None) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [*WRAP, *args, "--", sys.executable, ECHO],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, **(env or {})},
    )


def _readline(proc: subprocess.Popen[bytes]) -> bytes:
    assert proc.stdout is not None
    return proc.stdout.readline()


def _send(proc: subprocess.Popen[bytes], line: bytes) -> None:
    assert proc.stdin is not None
    proc.stdin.write(line + b"\n")
    proc.stdin.flush()


def test_requests_and_replies_are_relayed_unchanged() -> None:
    proc = _spawn()
    try:
        _send(proc, _request("tools/call", 1, name="add", arguments={"a": 1}))
        first = _readline(proc)
        _send(proc, _request("tools/list", 2))
        second = _readline(proc)
    finally:
        out, err = proc.communicate(timeout=10)
    assert json.loads(first) == {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {"content": [{"type": "text", "text": json.dumps({"a": 1})}]},
    }
    assert json.loads(second)["result"] == {"tools": [{"name": "add"}]}
    assert out == b""
    assert b"echo server started" in err
    assert proc.returncode == 0


def test_non_json_lines_and_large_lines_pass_through() -> None:
    proc = _spawn()
    big = "x" * (1024 * 1024)
    try:
        _send(proc, _request("tools/call", 1, name="add", arguments={"chatter": True}))
        assert _readline(proc) == b"not json at all\n"
        assert json.loads(_readline(proc))["id"] == 1
        _send(proc, b"garbage line")
        _send(proc, _request("tools/call", 2, name="add", arguments={"big": big}))
        line = _readline(proc)
    finally:
        proc.communicate(timeout=10)
    assert json.loads(json.loads(line)["result"]["content"][0]["text"]) == {"big": big}


def test_eof_closes_the_child_and_exit_code_is_propagated() -> None:
    proc = _spawn(env={"EXIT_CODE": "3"})
    assert proc.stdin is not None
    _send(proc, _request("ping", 1))
    assert json.loads(_readline(proc))["result"] == {"echo": "ping"}
    proc.stdin.close()
    proc.wait(timeout=10)
    assert proc.returncode == 3


def test_child_that_ignores_eof_is_terminated() -> None:
    proc = _spawn("--timeout", "0.5", env={"IGNORE_EOF": "1"})
    assert proc.stdin is not None
    started = time.monotonic()
    proc.stdin.close()
    proc.wait(timeout=10)
    assert time.monotonic() - started < 5
    assert proc.returncode == 128 + signal.SIGTERM


def test_child_that_ignores_sigterm_is_killed() -> None:
    proc = _spawn("--timeout", "0.5", env={"IGNORE_EOF": "1", "IGNORE_SIGTERM": "1"})
    assert proc.stdin is not None
    proc.stdin.close()
    proc.wait(timeout=10)
    assert proc.returncode == 128 + signal.SIGKILL


def test_signals_are_forwarded_to_the_child() -> None:
    proc = _spawn(env={"IGNORE_EOF": "1"})
    _send(proc, _request("ping", 1))
    assert _readline(proc)
    proc.send_signal(signal.SIGTERM)
    proc.wait(timeout=10)
    assert proc.returncode == 128 + signal.SIGTERM


def test_child_crash_ends_the_wrapper() -> None:
    proc = _spawn()
    _send(proc, _request("tools/call", 1, name="add", arguments={"crash": True}))
    proc.wait(timeout=10)
    assert proc.returncode == 9


def test_missing_command_fails_clearly(tmp_path: Path) -> None:
    proc = subprocess.run(
        [*WRAP, "--", str(tmp_path / "no-such-server")],
        capture_output=True,
        timeout=10,
    )
    assert proc.returncode == 127
    assert b"cannot start" in proc.stderr
    usage = subprocess.run([*WRAP], capture_output=True, timeout=10)
    assert usage.returncode == 2
    assert b"server command is required" in usage.stderr


def test_arguments_and_environment_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SEALEDRUN_URL", raising=False)
    monkeypatch.delenv("SEALEDRUN_TOKEN", raising=False)
    monkeypatch.delenv("SEALEDRUN_RUN", raising=False)
    args = parse_args(["--", "/usr/bin/server", "--flag"])
    assert (args.server, args.run, args.url, args.token) == (
        "server",
        None,
        "http://127.0.0.1:8080",
        None,
    )
    assert args.command == ["/usr/bin/server", "--flag"]
    monkeypatch.setenv("SEALEDRUN_URL", "http://recorder:9000/")
    monkeypatch.setenv("SEALEDRUN_TOKEN", "tok")
    monkeypatch.setenv("SEALEDRUN_RUN", "job")
    args = parse_args(["--server", "fs", "--strict", "--", "npx", "server"])
    assert (args.server, args.run, args.url, args.token, args.strict) == (
        "fs",
        "job",
        "http://recorder:9000",
        "tok",
        True,
    )


def test_parse_message_accepts_objects_only() -> None:
    assert parse_message(b'{"jsonrpc": "2.0", "id": 1}\n') == {"jsonrpc": "2.0", "id": 1}
    assert parse_message(b"[1, 2]\n") is None
    assert parse_message(b"not json\n") is None
    assert parse_message(b"{broken\n") is None
