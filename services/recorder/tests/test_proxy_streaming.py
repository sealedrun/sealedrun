"""Streaming through the proxy: pass-through, recording, and every way a stream can end."""

import json
from collections.abc import AsyncIterator, Callable
from typing import Any

import anyio
import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sealedrun.schema import validate_extensions
from sealedrun_recorder.proxy.core import ndjson, sse_data, sse_done
from starlette.requests import ClientDisconnect

UPSTREAMS = """
upstreams:
  - name: cloudai
    url: https://cloud.example/v1
    dialect: openai
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["gpt-*"]
"""
SSE = "text/event-stream"


def _sse(*events: Any) -> list[bytes]:
    return [
        (b"data: " + (e if isinstance(e, bytes) else json.dumps(e).encode()) + b"\n\n")
        for e in events
    ]


def _chunk(**delta: Any) -> dict[str, Any]:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion.chunk",
        "model": "gpt-4.1-2025-04-14",
        "choices": [{"index": 0, "delta": delta, "finish_reason": None}],
    }


CHAT_CHUNKS = _sse(
    _chunk(role="assistant", content=""),
    _chunk(content="Hel"),
    _chunk(content="lo"),
    _chunk(tool_calls=[{"index": 0, "id": "c1", "function": {"name": "read_file"}}]),
    {**_chunk(), "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]},
    {**_chunk(), "choices": [], "usage": {"prompt_tokens": 41, "completion_tokens": 12}},
    b"[DONE]",
)


class Stream(httpx.AsyncByteStream):
    """A fake upstream stream: chunks, an optional gate before chunk two, an optional break."""

    def __init__(
        self,
        chunks: list[bytes],
        gate: anyio.Event | None = None,
        break_after: int | None = None,
    ) -> None:
        self.chunks = chunks
        self.gate = gate
        self.break_after = break_after
        self.sent = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for index, chunk in enumerate(self.chunks):
            if index == 1 and self.gate is not None:
                await self.gate.wait()
            if self.break_after is not None and index == self.break_after:
                raise httpx.ReadError("connection reset")
            self.sent += 1
            yield chunk


def _streaming_route(stream: Stream, status: int = 200) -> Callable[..., httpx.Response]:
    def _route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, headers={"content-type": SSE}, stream=stream)

    return _route


BODY = {
    "model": "gpt-4.1",
    "messages": [{"role": "user", "content": "hi"}],
    "stream": True,
    "stream_options": {"include_usage": True},
    "temperature": 0.5,
}


@pytest.fixture
def auth(secrets: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {secrets['token']}"}


async def _wait_for_records(
    app_records: Callable[[Any], list[dict[str, Any]]], app: FastAPI, count: int
) -> list[dict[str, Any]]:
    for _ in range(200):
        records = app_records(app)
        if len(records) >= count:
            return records
        await anyio.sleep(0.01)
    raise AssertionError(f"expected {count} records, got {len(app_records(app))}")


def test_chat_stream_passed_through_and_recorded(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    secrets: dict[str, str],
    proxy_records: Any,
    stored_text: Any,
) -> None:
    upstream.routes["/chat/completions"] = _streaming_route(Stream(CHAT_CHUNKS))
    with make_proxy(UPSTREAMS) as proxy:
        response = proxy.post("/v1/chat/completions", json=BODY, headers=auth)
        assert response.status_code == 200
        assert response.headers["content-type"] == SSE
        assert response.content == b"".join(CHAT_CHUNKS)
        sent = upstream.calls[0]
        assert sent.headers["accept"].startswith(SSE)
        assert sent.headers["authorization"] == f"Bearer {secrets['upstream_key']}"
        assert json.loads(sent.content) == BODY

        records = proxy_records(proxy)
        assert [r["kind"] for r in records] == ["run_start", "llm_call"]
        call = records[1]
        assert call["outcome"] == "success"
        assert call["extensions"]["sealedrun.llm"] == {
            "model": "gpt-4.1-2025-04-14",
            "provider": "cloudai",
            "stream": True,
            "temperature": 0.5,
            "input_tokens": 41,
            "output_tokens": 12,
            "finish_reason": "tool_calls",
            "tool_calls_requested": ["read_file"],
        }
        proxy_ext = call["extensions"]["sealedrun.proxy"]
        assert proxy_ext["status"] == 200
        assert "truncated" not in proxy_ext
        assert validate_extensions(call["extensions"]) == []
        assert call["payload"]["response_media_type"] == SSE
        stored = proxy.get(f"/api/records/{call['record_id']}/payload/response", headers=auth)
        assert stored.content == b"".join(CHAT_CHUNKS)
        assert secrets["upstream_key"] not in stored_text(proxy)


def test_stream_without_usage_records_what_it_has(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    chunks = _sse(_chunk(content="Hi"), b"[DONE]")
    upstream.routes["/chat/completions"] = _streaming_route(Stream(chunks))
    body = {"model": "gpt-4.1", "messages": [], "stream": True}
    with make_proxy(UPSTREAMS) as proxy:
        assert proxy.post("/v1/chat/completions", json=body, headers=auth).content == b"".join(
            chunks
        )
        llm = proxy_records(proxy)[1]["extensions"]["sealedrun.llm"]
    assert llm == {"model": "gpt-4.1-2025-04-14", "provider": "cloudai", "stream": True}


def _scope(auth: dict[str, str], body: bytes) -> dict[str, Any]:
    return {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.4"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": "/v1/chat/completions",
        "raw_path": b"/v1/chat/completions",
        "query_string": b"",
        "root_path": "",
        "headers": [
            (b"host", b"localhost"),
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
            (b"authorization", auth["Authorization"].encode()),
        ],
        "client": ("127.0.0.1", 1234),
        "server": ("localhost", 80),
    }


def _receive(body: bytes) -> Callable[[], Any]:
    async def receive() -> dict[str, Any]:
        return {"type": "http.request", "body": body, "more_body": False}

    return receive


@pytest.mark.anyio
async def test_chunks_reach_the_client_before_the_upstream_finishes(
    make_app: Callable[..., FastAPI], upstream: Any, auth: dict[str, str], app_records: Any
) -> None:
    gate = anyio.Event()
    stream = Stream(CHAT_CHUNKS, gate=gate)
    upstream.routes["/chat/completions"] = _streaming_route(stream)
    app = make_app(UPSTREAMS)
    body = json.dumps(BODY).encode()
    delivered: list[bytes] = []
    first_chunk = anyio.Event()

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.body" and message.get("body"):
            delivered.append(message["body"])
            first_chunk.set()

    async with app.router.lifespan_context(app):
        async with anyio.create_task_group() as tasks:
            tasks.start_soon(app, _scope(auth, body), _receive(body), send)
            with anyio.fail_after(5):
                await first_chunk.wait()
            assert delivered == [CHAT_CHUNKS[0]]
            assert stream.sent == 1
            assert len(app_records(app)) < 2
            gate.set()
        records = await _wait_for_records(app_records, app, 2)
    assert b"".join(delivered) == b"".join(CHAT_CHUNKS)
    assert records[1]["outcome"] == "success"


@pytest.mark.anyio
async def test_client_disconnect_records_partial_stream_as_truncated(
    make_app: Callable[..., FastAPI], upstream: Any, auth: dict[str, str], app_records: Any
) -> None:
    gate = anyio.Event()
    upstream.routes["/chat/completions"] = _streaming_route(Stream(CHAT_CHUNKS, gate=gate))
    app = make_app(UPSTREAMS)
    body = json.dumps(BODY).encode()
    delivered: list[bytes] = []

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.body" and message.get("body"):
            delivered.append(message["body"])
            raise OSError("client went away")

    async with app.router.lifespan_context(app):
        with pytest.raises(ClientDisconnect):
            await app(_scope(auth, body), _receive(body), send)
        records = await _wait_for_records(app_records, app, 2)
    call = records[1]
    assert delivered == [CHAT_CHUNKS[0]]
    assert call["outcome"] == "error"
    assert call["extensions"]["sealedrun.proxy"]["truncated"] is True
    assert call["extensions"]["sealedrun.llm"]["stream"] is True
    assert call["payload"]["response_size"] == len(CHAT_CHUNKS[0])
    assert validate_extensions(call["extensions"]) == []


@pytest.mark.anyio
async def test_client_leaving_after_done_is_not_a_truncation(
    make_app: Callable[..., FastAPI], upstream: Any, auth: dict[str, str], app_records: Any
) -> None:
    """SDKs close the connection on `[DONE]`, before the upstream sends its end of body."""
    gate = anyio.Event()
    chunks = [*CHAT_CHUNKS, b": trailing comment after DONE\n\n"]
    stream = Stream(chunks, gate=gate)
    upstream.routes["/chat/completions"] = _streaming_route(stream)
    app = make_app(UPSTREAMS)
    body = json.dumps(BODY).encode()
    delivered: list[bytes] = []

    async def send(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.body" and message.get("body"):
            delivered.append(message["body"])
            if len(delivered) == 1:
                gate.set()
            if message["body"] == CHAT_CHUNKS[-1]:
                raise OSError("client closed on DONE")

    async with app.router.lifespan_context(app):
        with pytest.raises(ClientDisconnect):
            await app(_scope(auth, body), _receive(body), send)
        records = await _wait_for_records(app_records, app, 2)
    call = records[1]
    assert delivered == CHAT_CHUNKS
    assert call["outcome"] == "success"
    assert "truncated" not in call["extensions"]["sealedrun.proxy"]
    assert call["extensions"]["sealedrun.llm"]["input_tokens"] == 41


def _response_event(kind: str, **response: Any) -> dict[str, Any]:
    base = {"id": "resp_1", "object": "response", "model": "gpt-5-2025-08-07", "output": []}
    return {"type": kind, "sequence_number": 0, "response": {**base, **response}}


RESPONSES_FINAL = {
    "status": "completed",
    "usage": {"input_tokens": 7, "output_tokens": 3},
    "output": [
        {"type": "function_call", "name": "lookup", "call_id": "c1", "arguments": "{}"},
        {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "x"}]},
    ],
}
RESPONSES_CHUNKS = _sse(
    _response_event("response.created", status="in_progress"),
    {"type": "response.output_text.delta", "delta": "x", "sequence_number": 1},
    _response_event("response.completed", **RESPONSES_FINAL),
)
RESPONSES_BODY = {"model": "gpt-5", "input": "hi", "stream": True}


def test_responses_stream_passed_through_and_recorded(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/responses"] = _streaming_route(Stream(RESPONSES_CHUNKS))
    with make_proxy(UPSTREAMS) as proxy:
        response = proxy.post("/v1/responses", json=RESPONSES_BODY, headers=auth)
        assert response.status_code == 200
        assert response.content == b"".join(RESPONSES_CHUNKS)
        call = proxy_records(proxy)[1]
    assert call["outcome"] == "success"
    assert call["extensions"]["sealedrun.llm"] == {
        "model": "gpt-5-2025-08-07",
        "provider": "cloudai",
        "stream": True,
        "input_tokens": 7,
        "output_tokens": 3,
        "finish_reason": "completed",
        "tool_calls_requested": ["lookup"],
    }
    assert call["extensions"]["sealedrun.proxy"]["operation"] == "responses"
    assert "truncated" not in call["extensions"]["sealedrun.proxy"]
    assert validate_extensions(call["extensions"]) == []


@pytest.mark.parametrize(
    ("final", "finish_reason", "outcome"),
    [
        (
            _response_event(
                "response.incomplete",
                status="incomplete",
                incomplete_details={"reason": "max_output_tokens"},
                usage={"input_tokens": 7, "output_tokens": 3},
            ),
            "max_output_tokens",
            "success",
        ),
        (
            _response_event(
                "response.failed",
                status="failed",
                error={"code": "server_error", "message": "boom"},
            ),
            "failed",
            "error",
        ),
    ],
)
def test_responses_stream_ends(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    proxy_records: Any,
    final: dict[str, Any],
    finish_reason: str,
    outcome: str,
) -> None:
    chunks = _sse(_response_event("response.created", status="in_progress"), final)
    upstream.routes["/responses"] = _streaming_route(Stream(chunks))
    with make_proxy(UPSTREAMS) as proxy:
        assert proxy.post("/v1/responses", json=RESPONSES_BODY, headers=auth).status_code == 200
        call = proxy_records(proxy)[1]
    assert call["outcome"] == outcome
    assert call["extensions"]["sealedrun.llm"]["finish_reason"] == finish_reason
    assert "truncated" not in call["extensions"]["sealedrun.proxy"]


def test_responses_stream_cut_before_the_end_is_truncated(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/responses"] = _streaming_route(Stream(RESPONSES_CHUNKS, break_after=2))
    with make_proxy(UPSTREAMS) as proxy:
        assert proxy.post("/v1/responses", json=RESPONSES_BODY, headers=auth).content == b"".join(
            RESPONSES_CHUNKS[:2]
        )
        call = proxy_records(proxy)[1]
    assert call["outcome"] == "error"
    assert call["extensions"]["sealedrun.proxy"]["truncated"] is True
    assert call["extensions"]["sealedrun.llm"] == {
        "model": "gpt-5-2025-08-07",
        "provider": "cloudai",
        "stream": True,
    }


ANTHROPIC_UPSTREAMS = """
upstreams:
  - name: anthropic
    url: https://anthropic.example
    dialect: anthropic
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["claude-*"]
"""


def _anthropic_event(kind: str, **fields: Any) -> bytes:
    return f"event: {kind}\n".encode() + _sse({"type": kind, **fields})[0]


MESSAGE_CHUNKS = [
    _anthropic_event(
        "message_start",
        message={
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-5-20260501",
            "content": [],
            "stop_reason": None,
            "usage": {
                "input_tokens": 10,
                "cache_creation_input_tokens": 20,
                "cache_read_input_tokens": 30,
                "output_tokens": 1,
            },
        },
    ),
    _anthropic_event("content_block_start", index=0, content_block={"type": "text", "text": ""}),
    _anthropic_event("content_block_delta", index=0, delta={"type": "text_delta", "text": "Hi"}),
    _anthropic_event("content_block_stop", index=0),
    _anthropic_event(
        "content_block_start",
        index=1,
        content_block={"type": "tool_use", "id": "t1", "name": "read_file", "input": {}},
    ),
    _anthropic_event("content_block_stop", index=1),
    _anthropic_event(
        "message_delta",
        delta={"stop_reason": "tool_use", "stop_sequence": None},
        usage={"output_tokens": 12},
    ),
    _anthropic_event("message_stop"),
]
MESSAGE_BODY = {
    "model": "claude-sonnet-5",
    "max_tokens": 64,
    "messages": [{"role": "user", "content": "hi"}],
    "stream": True,
}


def test_anthropic_stream_passed_through_and_recorded(
    make_proxy: Callable[..., TestClient], upstream: Any, proxy_records: Any, secrets: Any
) -> None:
    upstream.routes["/v1/messages"] = _streaming_route(Stream(MESSAGE_CHUNKS))
    headers = {"x-api-key": secrets["token"], "anthropic-version": "2023-06-01"}
    with make_proxy(ANTHROPIC_UPSTREAMS) as proxy:
        response = proxy.post("/v1/messages", json=MESSAGE_BODY, headers=headers)
        assert response.status_code == 200
        assert response.headers["content-type"] == SSE
        assert response.content == b"".join(MESSAGE_CHUNKS)
        assert upstream.calls[0].headers["accept"].startswith(SSE)
        call = proxy_records(proxy)[1]
    assert call["outcome"] == "success"
    assert call["extensions"]["sealedrun.llm"] == {
        "model": "claude-sonnet-5-20260501",
        "provider": "anthropic",
        "stream": True,
        "input_tokens": 60,
        "output_tokens": 12,
        "finish_reason": "tool_use",
        "tool_calls_requested": ["read_file"],
    }
    assert call["extensions"]["sealedrun.proxy"]["dialect"] == "anthropic"
    assert "truncated" not in call["extensions"]["sealedrun.proxy"]
    assert validate_extensions(call["extensions"]) == []


def test_anthropic_error_event_and_cut_stream(
    make_proxy: Callable[..., TestClient], upstream: Any, proxy_records: Any, secrets: Any
) -> None:
    failing = [
        *MESSAGE_CHUNKS[:3],
        _anthropic_event("error", error={"type": "overloaded_error", "message": "busy"}),
    ]
    headers = {"x-api-key": secrets["token"], "anthropic-version": "2023-06-01"}
    with make_proxy(ANTHROPIC_UPSTREAMS) as proxy:
        upstream.routes["/v1/messages"] = _streaming_route(Stream(failing))
        assert proxy.post("/v1/messages", json=MESSAGE_BODY, headers=headers).status_code == 200
        upstream.routes["/v1/messages"] = _streaming_route(Stream(MESSAGE_CHUNKS, break_after=7))
        assert proxy.post("/v1/messages", json=MESSAGE_BODY, headers=headers).status_code == 200
        records = proxy_records(proxy)
    errored, cut = records[1], records[2]
    assert errored["outcome"] == "error"
    assert "truncated" not in errored["extensions"]["sealedrun.proxy"]
    assert errored["extensions"]["sealedrun.llm"]["input_tokens"] == 60
    assert cut["outcome"] == "error"
    assert cut["extensions"]["sealedrun.proxy"]["truncated"] is True
    assert cut["extensions"]["sealedrun.llm"]["finish_reason"] == "tool_use"


def test_anthropic_count_tokens_does_not_stream(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: Any
) -> None:
    headers = {"x-api-key": secrets["token"], "anthropic-version": "2023-06-01"}
    with make_proxy(ANTHROPIC_UPSTREAMS) as proxy:
        response = proxy.post("/v1/messages/count_tokens", json=MESSAGE_BODY, headers=headers)
    assert response.status_code == 400
    assert "streaming" in response.json()["error"]["message"]
    assert upstream.calls == []


OLLAMA_UPSTREAMS = """
upstreams:
  - name: ollama-native
    url: http://127.0.0.1:11434
    dialect: ollama
    location: local
    models: ["*"]
"""
NDJSON = "application/x-ndjson"


def _ollama_line(**fields: Any) -> bytes:
    base = {"model": "llama3.2:3b", "created_at": "2026-09-24T10:00:00Z", "done": False}
    return json.dumps({**base, **fields}).encode() + b"\n"


OLLAMA_CHAT_LINES = [
    _ollama_line(message={"role": "assistant", "content": "Hel"}),
    _ollama_line(message={"role": "assistant", "content": "lo"}),
    _ollama_line(
        message={
            "role": "assistant",
            "content": "",
            "tool_calls": [{"function": {"name": "read_file", "arguments": {}}}],
        }
    ),
    _ollama_line(
        message={"role": "assistant", "content": ""},
        done=True,
        done_reason="stop",
        prompt_eval_count=9,
        eval_count=4,
    ),
]


def _ndjson_route(stream: Stream) -> Callable[..., httpx.Response]:
    def _route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": NDJSON}, stream=stream)

    return _route


def test_ollama_streams_by_default_and_records_the_final_line(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/api/chat"] = _ndjson_route(Stream(OLLAMA_CHAT_LINES))
    body = {"model": "llama3.2:3b", "messages": [{"role": "user", "content": "hi"}]}
    with make_proxy(OLLAMA_UPSTREAMS) as proxy:
        response = proxy.post("/api/chat", json=body, headers=auth)
        assert response.status_code == 200
        assert response.headers["content-type"] == NDJSON
        assert response.content == b"".join(OLLAMA_CHAT_LINES)
        assert upstream.calls[0].headers["accept"].startswith(NDJSON)
        call = proxy_records(proxy)[1]
    assert call["outcome"] == "success"
    assert call["extensions"]["sealedrun.llm"] == {
        "model": "llama3.2:3b",
        "provider": "ollama-native",
        "stream": True,
        "input_tokens": 9,
        "output_tokens": 4,
        "finish_reason": "stop",
        "tool_calls_requested": ["read_file"],
    }
    assert call["payload"]["response_media_type"] == NDJSON
    assert "truncated" not in call["extensions"]["sealedrun.proxy"]
    assert validate_extensions(call["extensions"]) == []


def test_ollama_generate_stream_cut_before_done_is_truncated(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    lines = [
        _ollama_line(response="Hel"),
        _ollama_line(response="lo"),
        _ollama_line(response="", done=True, done_reason="stop", eval_count=2),
    ]
    upstream.routes["/api/generate"] = _ndjson_route(Stream(lines, break_after=2))
    body = {"model": "llama3.2:3b", "prompt": "hi", "stream": True}
    with make_proxy(OLLAMA_UPSTREAMS) as proxy:
        response = proxy.post("/api/generate", json=body, headers=auth)
        assert response.content == b"".join(lines[:2])
        call = proxy_records(proxy)[1]
    assert call["outcome"] == "error"
    assert call["extensions"]["sealedrun.proxy"]["truncated"] is True
    assert call["extensions"]["sealedrun.llm"] == {
        "model": "llama3.2:3b",
        "provider": "ollama-native",
        "stream": True,
    }


def test_ollama_error_line_is_a_failure(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    lines = [OLLAMA_CHAT_LINES[0], b'{"error": "model went away"}\n']
    upstream.routes["/api/chat"] = _ndjson_route(Stream(lines))
    body = {"model": "llama3.2:3b", "messages": []}
    with make_proxy(OLLAMA_UPSTREAMS) as proxy:
        assert proxy.post("/api/chat", json=body, headers=auth).content == b"".join(lines)
        call = proxy_records(proxy)[1]
    assert call["outcome"] == "error"
    assert "truncated" not in call["extensions"]["sealedrun.proxy"]


GEMINI_UPSTREAMS = """
upstreams:
  - name: gemini
    url: https://gemini.example
    dialect: gemini
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["gemini-*"]
"""
GEMINI_STREAM_PATH = "/v1beta/models/gemini-3-flash:streamGenerateContent?alt=sse"


def _gemini_chunk(parts: list[dict[str, Any]], **extra: Any) -> dict[str, Any]:
    candidate: dict[str, Any] = {"content": {"role": "model", "parts": parts}, "index": 0}
    if "finishReason" in extra:
        candidate["finishReason"] = extra.pop("finishReason")
    return {"candidates": [candidate], "modelVersion": "gemini-3-flash-001", **extra}


GEMINI_CHUNKS = _sse(
    _gemini_chunk([{"text": "Look"}]),
    _gemini_chunk([{"functionCall": {"name": "lookup", "args": {}}}]),
    _gemini_chunk(
        [{"text": "ing"}],
        finishReason="STOP",
        usageMetadata={"promptTokenCount": 8, "candidatesTokenCount": 3, "thoughtsTokenCount": 2},
    ),
)
GEMINI_BODY = {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}


def test_gemini_stream_passed_through_and_recorded(
    make_proxy: Callable[..., TestClient], upstream: Any, proxy_records: Any, secrets: Any
) -> None:
    upstream.routes[":streamGenerateContent"] = _streaming_route(Stream(GEMINI_CHUNKS))
    with make_proxy(GEMINI_UPSTREAMS) as proxy:
        response = proxy.post(f"{GEMINI_STREAM_PATH}&key={secrets['token']}", json=GEMINI_BODY)
        assert response.status_code == 200
        assert response.headers["content-type"] == SSE
        assert response.content == b"".join(GEMINI_CHUNKS)
        sent = upstream.calls[0]
        assert sent.url.path.endswith(":streamGenerateContent")
        assert sent.url.params.get("alt") == "sse"
        assert "key" not in sent.url.params
        assert sent.headers["x-goog-api-key"] == secrets["upstream_key"]
        call = proxy_records(proxy)[1]
    assert call["outcome"] == "success"
    assert call["extensions"]["sealedrun.llm"] == {
        "model": "gemini-3-flash-001",
        "provider": "gemini",
        "stream": True,
        "input_tokens": 8,
        "output_tokens": 5,
        "finish_reason": "STOP",
        "tool_calls_requested": ["lookup"],
    }
    assert call["extensions"]["sealedrun.proxy"]["operation"] == "generate"
    assert "truncated" not in call["extensions"]["sealedrun.proxy"]
    assert validate_extensions(call["extensions"]) == []


def test_gemini_stream_cut_before_the_last_chunk_is_truncated(
    make_proxy: Callable[..., TestClient], upstream: Any, proxy_records: Any, secrets: Any
) -> None:
    upstream.routes[":streamGenerateContent"] = _streaming_route(
        Stream(GEMINI_CHUNKS, break_after=2)
    )
    headers = {"x-goog-api-key": secrets["token"]}
    with make_proxy(GEMINI_UPSTREAMS) as proxy:
        response = proxy.post(GEMINI_STREAM_PATH, json=GEMINI_BODY, headers=headers)
        assert response.content == b"".join(GEMINI_CHUNKS[:2])
        call = proxy_records(proxy)[1]
    assert call["outcome"] == "error"
    assert call["extensions"]["sealedrun.proxy"]["truncated"] is True
    assert call["extensions"]["sealedrun.llm"]["tool_calls_requested"] == ["lookup"]
    assert "finish_reason" not in call["extensions"]["sealedrun.llm"]


def test_gemini_error_chunk_is_a_failure(
    make_proxy: Callable[..., TestClient], upstream: Any, proxy_records: Any, secrets: Any
) -> None:
    chunks = _sse(_gemini_chunk([{"text": "x"}]), {"error": {"code": 503, "status": "UNAVAILABLE"}})
    upstream.routes[":streamGenerateContent"] = _streaming_route(Stream(chunks))
    headers = {"x-goog-api-key": secrets["token"]}
    with make_proxy(GEMINI_UPSTREAMS) as proxy:
        assert proxy.post(GEMINI_STREAM_PATH, json=GEMINI_BODY, headers=headers).status_code == 200
        call = proxy_records(proxy)[1]
    assert call["outcome"] == "error"
    assert "truncated" not in call["extensions"]["sealedrun.proxy"]


def test_upstream_break_mid_stream_is_truncated(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/chat/completions"] = _streaming_route(Stream(CHAT_CHUNKS, break_after=2))
    with make_proxy(UPSTREAMS) as proxy:
        response = proxy.post("/v1/chat/completions", json=BODY, headers=auth)
        assert response.status_code == 200
        assert response.content == b"".join(CHAT_CHUNKS[:2])
        call = proxy_records(proxy)[1]
    assert call["outcome"] == "error"
    assert call["extensions"]["sealedrun.proxy"]["truncated"] is True
    assert call["extensions"]["sealedrun.llm"]["model"] == "gpt-4.1-2025-04-14"


def test_stream_over_size_cap_is_cut_and_truncated(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    stream = Stream(CHAT_CHUNKS)
    upstream.routes["/chat/completions"] = _streaming_route(stream)
    limit = len(CHAT_CHUNKS[0]) + len(CHAT_CHUNKS[1])
    with make_proxy(UPSTREAMS, proxy_max_body_bytes=limit) as proxy:
        response = proxy.post("/v1/chat/completions", json=BODY, headers=auth)
        assert response.content == b"".join(CHAT_CHUNKS[:2])
        call = proxy_records(proxy)[1]
    assert stream.sent == 3
    assert call["extensions"]["sealedrun.proxy"]["truncated"] is True
    assert call["payload"]["response_size"] == limit


def test_upstream_error_status_is_a_plain_reply(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.fail = "429"
    with make_proxy(UPSTREAMS) as proxy:
        response = proxy.post("/v1/chat/completions", json=BODY, headers=auth)
        assert response.status_code == 429
        assert response.json()["error"]["message"] == "upstream failed"
        call = proxy_records(proxy)[1]
    assert call["outcome"] == "error"
    assert call["extensions"]["sealedrun.llm"]["stream"] is True
    assert "truncated" not in call["extensions"]["sealedrun.proxy"]
    assert call["payload"]["response_media_type"] == "application/json"


def test_unreachable_upstream_when_streaming(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.fail = "down"
    with make_proxy(UPSTREAMS) as proxy:
        response = proxy.post("/v1/chat/completions", json=BODY, headers=auth)
        assert response.status_code == 502
        assert proxy_records(proxy)[1]["extensions"]["sealedrun.proxy"]["status"] == 502


def test_error_event_in_stream_is_a_failure(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    chunks = _sse(_chunk(content="Hi"), {"error": {"message": "overloaded"}})
    upstream.routes["/chat/completions"] = _streaming_route(Stream(chunks))
    with make_proxy(UPSTREAMS) as proxy:
        assert proxy.post("/v1/chat/completions", json=BODY, headers=auth).status_code == 200
        call = proxy_records(proxy)[1]
    assert call["outcome"] == "error"
    assert "truncated" not in call["extensions"]["sealedrun.proxy"]


def test_embeddings_do_not_stream(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str]
) -> None:
    with make_proxy(UPSTREAMS) as proxy:
        body = {"model": "gpt-4.1", "input": "x", "stream": True}
        response = proxy.post("/v1/embeddings", json=body, headers=auth)
    assert response.status_code == 400
    assert "streaming" in response.json()["error"]["message"]
    assert upstream.calls == []


def test_sse_data_parser() -> None:
    raw = (
        b'event: ping\r\ndata: {"a": 1}\r\n\r\n'
        b": comment\n\n"
        b'data: {"b":\ndata: 2}\n\n'
        b"data: [DONE]\n\n"
        b"data: not json\n\n"
        b"data: [1, 2]\n\n"
    )
    assert sse_data(raw) == [{"a": 1}, {"b": 2}]
    assert sse_data(b"") == []
    assert sse_done(b'data: {"a": 1}\n\ndata: [DONE]\n\n') is True
    assert sse_done(b'data: {"a": 1}\n\ndata: [DONE]\n\n: keepalive\n\n') is True
    assert sse_done(b'data: [DONE]\n\ndata: {"a": 1}\n\n') is False
    assert sse_done(b"") is False


def test_ndjson_parser() -> None:
    raw = b'{"a": 1}\n\n{"b": 2}\r\nnot json\n[1]\n{"c": 3}'
    assert ndjson(raw) == [{"a": 1}, {"b": 2}, {"c": 3}]


def test_anthropic_stream_carries_retry_and_ratelimit_headers(
    make_proxy: Callable[..., TestClient], upstream: Any, secrets: Any
) -> None:
    extra = {
        "x-should-retry": "false",
        "anthropic-ratelimit-unified-status": "allowed",
        "anthropic-organization-id": "org_secret",
    }

    def _route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, headers={"content-type": SSE, **extra}, stream=Stream(MESSAGE_CHUNKS)
        )

    upstream.routes["/v1/messages"] = _route
    headers = {"x-api-key": secrets["token"], "anthropic-version": "2023-06-01"}
    with make_proxy(ANTHROPIC_UPSTREAMS) as proxy:
        response = proxy.post("/v1/messages", json=MESSAGE_BODY, headers=headers)
        assert response.status_code == 200
        assert response.headers["content-type"] == SSE
        assert response.headers["x-should-retry"] == "false"
        assert response.headers["anthropic-ratelimit-unified-status"] == "allowed"
        assert "anthropic-organization-id" not in response.headers
        assert response.content == b"".join(MESSAGE_CHUNKS)
