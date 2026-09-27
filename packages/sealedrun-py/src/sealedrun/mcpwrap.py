"""`sealedrun-mcp-wrap`: run an MCP stdio server and record its tool calls on a recorder.

The wrapper is what the MCP client launches. It starts the real server as a child process and
relays the two standard streams line by line, unchanged and unbuffered: the client's stdin to
the child's stdin, the child's stdout to the wrapper's stdout. The child's stderr is inherited,
so its logs still reach the terminal. Lines the wrapper cannot parse pass through untouched.

Shutdown follows the stdio binding: when the client closes stdin the wrapper closes the child's
stdin, waits for it to exit, then escalates to SIGTERM and SIGKILL. SIGINT and SIGTERM sent to
the wrapper are forwarded to the child. The wrapper exits with the child's exit code.

Recording follows the HTTP proxy's rules: `tools/call`, `resources/read`, `prompts/get` and
`tools/list` requests become `tool_call` steps posted to `POST /api/steps` with the request line
and the response line as payloads, before the response is delivered to the client. A recorder
that cannot be reached does not stop the call: the response is delivered and a warning goes to
stderr, unless `--strict` is set, in which case the client gets a JSON-RPC error instead. A
request cancelled by the client or still open when the server exits is recorded as truncated.

Only POSIX is supported: signal forwarding and the termination ladder rely on it.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import IO, Any

DEFAULT_URL = "http://127.0.0.1:8080"
DEFAULT_TIMEOUT = 5.0
KILL_GRACE = 2.0
RECORDED = frozenset({"tools/call", "resources/read", "prompts/get", "tools/list"})
NAME_PARAM = {"tools/call": "name", "resources/read": "uri", "prompts/get": "name"}
META_VERSION = "io.modelcontextprotocol/protocolVersion"
NOT_RECORDED_CODE = 1001
HIDDEN_ENV = frozenset({"SEALEDRUN_TOKEN", "SEALEDRUN_URL", "SEALEDRUN_RUN"})


class Observer:
    """Hooks called with every line relayed; the base class does nothing.

    `client_line` sees a line before it is written to the child, `server_line` a line before
    it is written to the client and may return a replacement line to deliver instead.
    Both are called on the relay threads, so a slow hook delays that direction of traffic.
    """

    def client_line(self, line: bytes) -> None:
        """Observe one line from the client."""

    def server_line(self, line: bytes) -> bytes:
        """Observe one line from the server and return the line to deliver."""
        return line

    def closed(self, exit_code: int) -> None:
        """Observe the end of the child process."""


def parse_message(line: bytes) -> dict[str, Any] | None:
    """Return the JSON-RPC object on `line`, or None when the line is not one."""
    stripped = line.strip()
    if not stripped.startswith(b"{"):
        return None
    try:
        message = json.loads(stripped)
    except ValueError:
        return None
    return message if isinstance(message, dict) else None


@dataclass
class Pending:
    """A recorded request waiting for its response."""

    id: str | int
    line: bytes
    method: str
    name: str
    started: float
    protocol_version: str | None


@dataclass
class Recording(Observer):
    """Post the recorded request/response pairs of one server to the recorder.

    `protocol_version` is taken from each request's `_meta` (modern era) or remembered from the
    `initialize` handshake (legacy era). Posting happens on the server relay thread, so a call's
    response reaches the client only after its record was accepted or the recorder gave up.
    """

    server: str
    command: Sequence[str]
    url: str
    token: str | None = None
    run: str | None = None
    strict: bool = False
    timeout: float = DEFAULT_TIMEOUT
    stderr: IO[str] = field(default_factory=lambda: sys.stderr)
    _pending: dict[str | int, Pending] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _legacy_version: str | None = None

    def client_line(self, line: bytes) -> None:
        """Remember recorded requests; note `initialize` and cancellations.

        A JSON-RPC batch (an array, 2025-03-26 only) is relayed but its calls cannot be paired
        with their replies here, so it is reported on stderr and not recorded.
        """
        message = parse_message(line)
        if message is None:
            if line.lstrip().startswith(b"["):
                self._warn("JSON-RPC batch relayed without recording")
            return
        method = message.get("method")
        params = message.get("params")
        params = params if isinstance(params, dict) else {}
        if method == "initialize":
            version = params.get("protocolVersion")
            self._legacy_version = version if isinstance(version, str) else None
            return
        if method == "notifications/cancelled":
            pending = self._take(params.get("requestId"))
            if pending is not None:
                self._post(pending, None, truncated=True)
            return
        request_id = message.get("id")
        if method not in RECORDED or not isinstance(request_id, str | int) or _is_bool(request_id):
            return
        meta = params.get("_meta")
        version = meta.get(META_VERSION) if isinstance(meta, dict) else None
        name = params.get(NAME_PARAM.get(method, ""))
        with self._lock:
            stale = self._pending.pop(request_id, None)
        if stale is not None:
            self._post(stale, None, truncated=True)
        with self._lock:
            self._pending[request_id] = Pending(
                id=request_id,
                line=line,
                method=method,
                name=name if isinstance(name, str) and name else method,
                started=time.perf_counter(),
                protocol_version=version if isinstance(version, str) else self._legacy_version,
            )

    def server_line(self, line: bytes) -> bytes:
        """Record the response to a pending request before it is delivered."""
        message = parse_message(line)
        if message is None or "method" in message:
            return line
        if "result" not in message and "error" not in message:
            return line
        result = message.get("result")
        if isinstance(result, dict) and isinstance(result.get("protocolVersion"), str):
            self._legacy_version = result["protocolVersion"]
        pending = self._take(message.get("id"))
        if pending is None:
            return line
        if not self._post(pending, line, message=message) and self.strict:
            return _refusal(message["id"], self.server)
        return line

    def closed(self, exit_code: int) -> None:
        """Record every request still open as truncated."""
        with self._lock:
            open_calls = list(self._pending.values())
            self._pending.clear()
        for pending in open_calls:
            self._post(pending, None, truncated=True)

    def _take(self, request_id: Any) -> Pending | None:
        if not _valid_id(request_id):
            return None
        with self._lock:
            return self._pending.pop(request_id, None)

    def _post(
        self,
        pending: Pending,
        line: bytes | None,
        *,
        message: dict[str, Any] | None = None,
        truncated: bool = False,
    ) -> bool:
        step = self._step(pending, line, message, truncated)
        body = json.dumps(step).encode()
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.run:
            headers["X-SealedRun-Run"] = self.run
        request = urllib.request.Request(  # noqa: S310
            f"{self.url}/api/steps", data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as reply:  # noqa: S310
                reply.read()
            return True
        except urllib.error.HTTPError as error:
            detail = error.read(300).decode(errors="replace")
            self._warn(f"recorder refused the {pending.method} record: {error.code} {detail}")
        except (urllib.error.URLError, OSError, ValueError) as error:
            self._warn(f"recorder unreachable at {_public(self.url)}: {error}")
        return False

    def _step(
        self,
        pending: Pending,
        line: bytes | None,
        message: dict[str, Any] | None,
        truncated: bool,
    ) -> dict[str, Any]:
        result = message.get("result") if message is not None else None
        result = result if isinstance(result, dict) else {}
        failed = message is None or "error" in message or result.get("isError") is True
        if failed:
            outcome = "error"
        elif result.get("resultType") == "input_required":
            outcome = "pending"
        else:
            outcome = "success"
        mcp: dict[str, Any] = {
            "server": self.server,
            "transport": "stdio",
            "method": pending.method,
            "request_id": pending.id,
            "is_error": failed,
        }
        if pending.method == "tools/call":
            mcp["tool"] = pending.name
        if isinstance(result.get("resultType"), str):
            mcp["result_type"] = result["resultType"]
        if pending.protocol_version:
            mcp["protocol_version"] = pending.protocol_version
        proxy: dict[str, Any] = {
            "upstream": self.server,
            "dialect": "mcp",
            "operation": pending.method,
            "latency_ms": round((time.perf_counter() - pending.started) * 1000, 1),
        }
        if truncated:
            proxy["truncated"] = True
        step: dict[str, Any] = {
            "kind": "tool_call",
            "target": {
                "type": "tool",
                "name": pending.name,
                "endpoint": os.path.basename(self.command[0]),
                "location": "local",
                "provider": f"mcp:{self.server}",
            },
            "outcome": outcome,
            "request": pending.line.rstrip(b"\r\n").decode(errors="replace"),
            "request_media_type": "application/json",
            "extensions": {"sealedrun.mcp": mcp, "sealedrun.proxy": proxy},
        }
        if line is not None:
            step["response"] = line.rstrip(b"\r\n").decode(errors="replace")
            step["response_media_type"] = "application/json"
        return step

    def _warn(self, text: str) -> None:
        print(f"sealedrun-mcp-wrap: {text}", file=self.stderr, flush=True)


def _write_all(stream: IO[bytes], data: bytes) -> None:
    """Write every byte of `data`: an unbuffered pipe may take a short write after a signal."""
    view = memoryview(data)
    while view:
        written = stream.write(view)
        view = view[written or 0 :]
    stream.flush()


def _valid_id(value: Any) -> bool:
    return isinstance(value, str | int) and not _is_bool(value)


def _is_bool(value: object) -> bool:
    return isinstance(value, bool)


def _public(url: str) -> str:
    scheme, _, rest = url.partition("://")
    return f"{scheme}://{rest.rpartition('@')[2]}"


def _refusal(request_id: Any, server: str) -> bytes:
    error = {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": NOT_RECORDED_CODE,
            "message": f"SealedRun recorder did not accept the record for {server}; "
            "the result was withheld (sealedrun-mcp-wrap --strict)",
        },
    }
    return json.dumps(error).encode() + b"\n"


class Wrapper:
    """Relay one client to one child process and observe the traffic."""

    def __init__(
        self,
        command: Sequence[str],
        observer: Observer | None = None,
        *,
        timeout: float = DEFAULT_TIMEOUT,
        stdin: IO[bytes] | None = None,
        stdout: IO[bytes] | None = None,
    ) -> None:
        self.command = list(command)
        self.observer = observer or Observer()
        self.timeout = timeout
        self._stdin = stdin if stdin is not None else sys.stdin.buffer
        self._stdout = stdout if stdout is not None else sys.stdout.buffer
        self._child: subprocess.Popen[bytes] | None = None
        self._client_closed = threading.Event()

    def run(self) -> int:
        """Run the child until it exits and return its exit code."""
        try:
            self._child = subprocess.Popen(  # noqa: S603
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                bufsize=0,
                env={k: v for k, v in os.environ.items() if k not in HIDDEN_ENV},
            )
        except OSError as error:
            print(f"sealedrun-mcp-wrap: cannot start {self.command[0]}: {error}", file=sys.stderr)
            return 127
        child = self._child
        self._install_signals()
        upstream = threading.Thread(target=self._pump_client, daemon=True)
        downstream = threading.Thread(target=self._pump_server, daemon=True)
        upstream.start()
        downstream.start()
        downstream.join()
        self._finish(child)
        code = child.returncode if child.returncode >= 0 else 128 - child.returncode
        self.observer.closed(code)
        return code

    def _pump_client(self) -> None:
        child = self._child
        assert child is not None and child.stdin is not None
        try:
            while True:
                line = self._stdin.readline()
                if not line:
                    break
                self.observer.client_line(line)
                _write_all(child.stdin, line)
        except (OSError, ValueError):
            pass
        finally:
            self._client_closed.set()
            threading.Thread(target=self._finish, args=(child,), daemon=True).start()

    def _pump_server(self) -> None:
        child = self._child
        assert child is not None and child.stdout is not None
        try:
            while True:
                line = child.stdout.readline()
                if not line:
                    break
                _write_all(self._stdout, self.observer.server_line(line))
        except (OSError, ValueError):
            pass

    def _finish(self, child: subprocess.Popen[bytes]) -> None:
        """Wait for the child, escalating from stdin EOF to SIGTERM to SIGKILL."""
        if child.stdin is not None:
            try:
                child.stdin.close()
            except OSError:
                pass
        ladder = ((None, self.timeout), (child.terminate, KILL_GRACE), (child.kill, None))
        for send, grace in ladder:
            if send is not None:
                try:
                    send()
                except OSError:
                    pass
            try:
                child.wait(timeout=grace)
                return
            except subprocess.TimeoutExpired:
                continue

    def _install_signals(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            return

        def forward(signum: int, _frame: Any) -> None:
            if self._child is not None and self._child.poll() is None:
                try:
                    self._child.send_signal(signum)
                except OSError:
                    pass

        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, forward)


def build_parser() -> argparse.ArgumentParser:
    """Return the command line parser of `sealedrun-mcp-wrap`."""
    parser = argparse.ArgumentParser(
        prog="sealedrun-mcp-wrap",
        description="Run an MCP stdio server and record its tool calls on a SealedRun recorder.",
    )
    parser.add_argument("--server", help="server name in the records (default: command name)")
    parser.add_argument("--run", help="run label, joins the run of proxied LLM calls with it")
    parser.add_argument("--url", help=f"recorder URL (default {DEFAULT_URL} or SEALEDRUN_URL)")
    parser.add_argument("--token", help="recorder token (default SEALEDRUN_TOKEN)")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="answer the client with a JSON-RPC error when a call cannot be recorded",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="seconds to wait for the server to exit or the recorder to answer (default 5)",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- server command and args")
    return parser


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    """Parse `argv`; the server command follows `--`."""
    args = build_parser().parse_args(list(argv))
    command = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        build_parser().error("a server command is required after --")
    args.command = command
    args.server = args.server or os.path.basename(command[0])
    args.run = args.run or os.environ.get("SEALEDRUN_RUN") or None
    args.url = (args.url or os.environ.get("SEALEDRUN_URL") or DEFAULT_URL).rstrip("/")
    if not args.url.startswith(("http://", "https://")):
        build_parser().error("--url must start with http:// or https://")
    args.token = args.token or os.environ.get("SEALEDRUN_TOKEN") or None
    return args


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point of `sealedrun-mcp-wrap`."""
    args = parse_args(sys.argv[1:] if argv is None else argv)
    recording = Recording(
        server=args.server,
        command=args.command,
        url=args.url,
        token=args.token,
        run=args.run,
        strict=args.strict,
        timeout=args.timeout,
    )
    return Wrapper(args.command, recording, timeout=args.timeout).run()


def run() -> None:
    """Console script entry point.

    Exits with `os._exit`: the client relay thread may still be blocked reading stdin, and a
    normal interpreter shutdown aborts while that thread holds the stream's lock.
    """
    code = main()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except OSError:
            pass
    os._exit(code)


if __name__ == "__main__":
    run()
