"""Caps of the stdio wrapper: open requests, oversize lines and the recorder post deadline."""

from __future__ import annotations

import io
import json
import sys
import time
from pathlib import Path
from typing import Any

import pytest
from sealedrun import mcpwrap
from sealedrun.mcpwrap import MAX_PENDING, Recording, Wrapper

ECHO = str(Path(__file__).parent / "mcp" / "echo_server.py")


def _request(method: str, rid: Any, **params: Any) -> bytes:
    return json.dumps({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}).encode()


def _recording(**options: Any) -> tuple[Recording, io.StringIO]:
    err = io.StringIO()
    rec = Recording(
        server="echo", command=["echo"], url="http://127.0.0.1:9", stderr=err, **options
    )
    return rec, err


def test_open_requests_are_capped_and_the_oldest_is_recorded_truncated(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    posted: list[dict[str, Any]] = []
    monkeypatch.setattr(mcpwrap, "post_step", lambda url, step, **kw: posted.append(step))
    rec, err = _recording()
    for rid in range(MAX_PENDING + 2):
        rec.client_line(_request("tools/call", rid, name="add") + b"\n")
    assert len(rec._pending) == MAX_PENDING
    assert [s["extensions"]["sealedrun.mcp"]["request_id"] for s in posted] == [0, 1]
    assert all(s["extensions"]["sealedrun.step"]["truncated"] for s in posted)
    assert f"more than {MAX_PENDING} open requests" in err.getvalue()


def test_post_gives_up_after_the_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    def stall(url: str, step: dict[str, Any], **kw: Any) -> dict[str, Any]:
        time.sleep(3)
        return {}

    monkeypatch.setattr(mcpwrap, "post_step", stall)
    rec, err = _recording(timeout=0.2, strict=True)
    rec.client_line(_request("tools/call", 1, name="add") + b"\n")
    started = time.perf_counter()
    line = rec.server_line(b'{"jsonrpc":"2.0","id":1,"result":{}}\n')
    assert time.perf_counter() - started < 1.5
    assert json.loads(line)["error"]["code"] == mcpwrap.NOT_RECORDED_CODE
    assert "did not answer within 0.2s" in err.getvalue()


def test_oversize_lines_are_relayed_in_pieces_and_not_parsed() -> None:
    big = b"x" * 500
    stdin = io.BytesIO(
        big + b"\n" + _request("tools/call", 1, name="add", arguments={"a": 1}) + b"\n"
    )
    stdout = io.BytesIO()
    seen: list[str] = []

    class Spy(mcpwrap.Observer):
        def oversize_line(self, source: str) -> None:
            seen.append(source)

        def client_line(self, line: bytes) -> None:
            seen.append(f"client:{len(line)}")

    code = Wrapper(
        [sys.executable, ECHO], Spy(), stdin=stdin, stdout=stdout, max_line_bytes=256
    ).run()
    assert code == 0
    answers = stdout.getvalue().splitlines()
    assert json.loads(answers[-1])["id"] == 1
    assert seen[0] == "client"
    assert any(s.startswith("client:") for s in seen)
