import json
from collections.abc import AsyncIterator, Callable
from typing import Any

import anyio
import httpx
import pytest
from fastapi import FastAPI
from sealedrun.schema import validate_extensions
from starlette.requests import ClientDisconnect

CONFIG = """
mcp_servers:
  - {name: tools, url: http://mcp.test/mcp, location: local}
"""
CALL = json.dumps(
    {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "slow", "arguments": {}}}
).encode()
LISTEN = json.dumps({"jsonrpc": "2.0", "id": 8, "method": "subscriptions/listen"}).encode()
CHUNKS = [
    b'data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":1}}\n\n',
    b'data: {"jsonrpc":"2.0","method":"notifications/progress","params":{"progress":2}}\n\n',
    b'data: {"jsonrpc":"2.0","id":7,"result":{"content":[]}}\n\n',
]


class Gated(httpx.AsyncByteStream):
    """Upstream SSE that waits on `gate` before its second chunk and notes when it is closed."""

    def __init__(self, chunks: list[bytes], gate: anyio.Event) -> None:
        self.chunks = chunks
        self.gate = gate
        self.closed = False

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for index, chunk in enumerate(self.chunks):
            if index == 1:
                await self.gate.wait()
            yield chunk

    async def aclose(self) -> None:
        self.closed = True


def _route(stream: Gated) -> Callable[[Any], httpx.Response]:
    return lambda request: httpx.Response(
        200, headers={"content-type": "text/event-stream"}, stream=stream
    )


def _scope(token: str, method: str, body: bytes) -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": "/mcp/tools",
        "raw_path": b"/mcp/tools",
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"host", b"localhost"),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"x-sealedrun-token", token.encode()),
        ],
        "client": ("127.0.0.1", 1234),
        "server": ("localhost", 80),
    }


def _receive(body: bytes) -> Callable[[], Any]:
    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


def _leave_after_first_chunk(delivered: list[bytes]) -> Callable[[dict[str, Any]], Any]:
    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.body" and message.get("body"):
            delivered.append(message["body"])
            raise OSError("client went away")

    return send


async def _wait_for(app_records: Any, app: FastAPI, count: int) -> list[dict[str, Any]]:
    for _ in range(200):
        records = app_records(app)
        if len(records) >= count:
            return records
        await anyio.sleep(0.01)
    raise AssertionError(f"expected {count} records, got {len(app_records(app))}")


@pytest.mark.anyio
async def test_progress_reaches_the_client_before_the_tool_finishes(
    make_app: Callable[..., FastAPI], upstream: Any, secrets: dict[str, str], app_records: Any
) -> None:
    gate = anyio.Event()
    upstream.routes["/mcp"] = _route(Gated(CHUNKS, gate))
    app = make_app(CONFIG)
    delivered: list[bytes] = []
    first = anyio.Event()

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.body" and message.get("body"):
            delivered.append(message["body"])
            first.set()

    async with app.router.lifespan_context(app):
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(app, _scope(secrets["token"], "POST", CALL), _receive(CALL), send)
            with anyio.fail_after(5):
                await first.wait()
            assert delivered == [CHUNKS[0]]
            assert app_records(app) == []
            gate.set()
        records = await _wait_for(app_records, app, 2)
    assert b"".join(delivered) == b"".join(CHUNKS)
    assert records[1]["outcome"] == "success"


@pytest.mark.anyio
async def test_client_leaving_mid_tool_call_records_the_partial_stream(
    make_app: Callable[..., FastAPI], upstream: Any, secrets: dict[str, str], app_records: Any
) -> None:
    stream = Gated(CHUNKS, anyio.Event())
    upstream.routes["/mcp"] = _route(stream)
    app = make_app(CONFIG)
    delivered: list[bytes] = []
    async with app.router.lifespan_context(app):
        with pytest.raises(ClientDisconnect):
            await app(
                _scope(secrets["token"], "POST", CALL),
                _receive(CALL),
                _leave_after_first_chunk(delivered),
            )
        records = await _wait_for(app_records, app, 2)
    call = records[1]
    assert delivered == [CHUNKS[0]]
    assert call["outcome"] == "error"
    assert call["extensions"]["sealedrun.proxy"]["truncated"] is True
    assert call["payload"]["response_size"] == len(CHUNKS[0])
    assert validate_extensions(call["extensions"]) == []
    assert stream.closed


@pytest.mark.anyio
@pytest.mark.parametrize(("method", "body"), [("POST", LISTEN), ("GET", b"")])
async def test_long_streams_closed_by_the_client_leave_no_record(
    make_app: Callable[..., FastAPI],
    upstream: Any,
    secrets: dict[str, str],
    app_records: Any,
    method: str,
    body: bytes,
) -> None:
    stream = Gated(CHUNKS[:2], anyio.Event())
    upstream.routes["/mcp"] = _route(stream)
    app = make_app(CONFIG)
    delivered: list[bytes] = []
    async with app.router.lifespan_context(app):
        with pytest.raises(ClientDisconnect):
            await app(
                _scope(secrets["token"], method, body),
                _receive(body),
                _leave_after_first_chunk(delivered),
            )
        await anyio.sleep(0.05)
        assert app_records(app) == []
    assert delivered == [CHUNKS[0]]
    assert stream.closed
