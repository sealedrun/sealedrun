"""Anthropic Messages wire format: `/v1/messages`, token counting and the model list.

Spoken by Anthropic and by the Anthropic-compatible endpoints of DeepSeek, Kimi, Qwen, GLM,
MiniMax, Ollama, llama.cpp, vLLM and LM Studio. Claude Code and the Anthropic SDKs reach it
through `ANTHROPIC_BASE_URL`; they send the recorder token as `x-api-key` or, with
`ANTHROPIC_AUTH_TOKEN`, as a bearer token.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Request, Response

from sealedrun_recorder.proxy.core import (
    Dialect,
    Operation,
    StreamSummary,
    client_credentials,
    forward,
    integer,
    mapping,
    require_proxy_token,
    sequence,
    sse_data,
)

ERROR_TYPES = {
    400: "invalid_request_error",
    401: "authentication_error",
    403: "permission_error",
    404: "not_found_error",
    413: "request_too_large",
    429: "rate_limit_error",
}
TOOL_BLOCKS = frozenset({"tool_use", "server_tool_use", "mcp_tool_use"})
PASSTHROUGH = ("anthropic-version", "anthropic-beta")


def _error_body(status: int, message: str) -> bytes:
    kind = ERROR_TYPES.get(status, "api_error")
    return json.dumps({"type": "error", "error": {"type": kind, "message": message}}).encode()


def messages_usage(reply: dict[str, Any]) -> dict[str, Any]:
    """Read model, token counts, stop reason and requested tools from a Messages reply.

    `input_tokens` is the whole prompt: Anthropic reports cache writes and cache reads apart
    from the uncached input, while the other formats count them in, so the three are added up.
    """
    llm: dict[str, Any] = {}
    model = reply.get("model")
    if isinstance(model, str) and model:
        llm["model"] = model
    usage = mapping(reply.get("usage"))
    parts = [
        integer(usage.get(field))
        for field in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
    ]
    if parts[0] is not None:
        llm["input_tokens"] = sum(p for p in parts if p is not None)
    output = integer(usage.get("output_tokens"))
    if output is not None:
        llm["output_tokens"] = output
    if isinstance(reply.get("stop_reason"), str):
        llm["finish_reason"] = reply["stop_reason"]
    names = [
        block["name"]
        for block in map(mapping, sequence(reply.get("content")))
        if block.get("type") in TOOL_BLOCKS and isinstance(block.get("name"), str)
    ]
    if names:
        llm["tool_calls_requested"] = names
    return llm


def count_tokens_usage(reply: dict[str, Any]) -> dict[str, Any]:
    """Read the counted prompt size from a token counting reply."""
    counted = integer(reply.get("input_tokens"))
    return {} if counted is None else {"input_tokens": counted}


ANTHROPIC = Dialect(
    "anthropic",
    _error_body,
    passthrough=PASSTHROUGH,
    reply_passthrough=("x-should-retry", "retry-after", "request-id"),
    reply_prefixes=("anthropic-ratelimit-",),
)


def messages_stream(raw: bytes) -> StreamSummary:
    """Read the same fields from a streamed Messages call.

    `message_start` carries the model and the input token counts, `content_block_start` opens
    each tool use, `message_delta` carries the stop reason and the output token count, and
    `message_stop` ends the stream. An `error` event marks it failed.
    """
    llm: dict[str, Any] = {}
    names: list[str] = []
    failed = False
    complete = False
    for event in sse_data(raw):
        kind = event.get("type")
        if kind == "message_start":
            llm.update(messages_usage(mapping(event.get("message"))))
        elif kind == "content_block_start":
            block = mapping(event.get("content_block"))
            if block.get("type") in TOOL_BLOCKS and isinstance(block.get("name"), str):
                names.append(block["name"])
        elif kind == "message_delta":
            delta = {**mapping(event.get("delta")), "usage": event.get("usage")}
            llm.update(messages_usage(delta))
        elif kind == "message_stop":
            complete = True
        elif kind == "error":
            failed = True
    if names:
        llm["tool_calls_requested"] = names
    return StreamSummary(llm, failed, complete)


MESSAGES = Operation(ANTHROPIC, "messages", "/v1/messages", messages_usage, stream=messages_stream)
COUNT_TOKENS = Operation(ANTHROPIC, "count_tokens", "/v1/messages/count_tokens", count_tokens_usage)

router = APIRouter(prefix="/v1", dependencies=[Depends(require_proxy_token)])


@router.post("/messages")
async def messages(request: Request) -> Response:
    """Forward a Messages call and record it as an `llm_call`."""
    return await forward(request, MESSAGES)


@router.post("/messages/count_tokens")
async def count_tokens(request: Request) -> Response:
    """Forward a token counting call and record it as an `llm_call`."""
    return await forward(request, COUNT_TOKENS)


async def list_models(request: Request) -> dict[str, Any]:
    """List the models of every Anthropic-format upstream that the upstream's patterns route.

    Answers in the Anthropic list shape, as one page. Upstreams that fail to answer or lack
    their key are left out. Listing is not recorded.
    """
    client: httpx.AsyncClient = request.app.state.http
    headers = {"accept": "application/json"}
    for name in PASSTHROUGH:
        if name in request.headers:
            headers[name] = request.headers[name]
    data: list[dict[str, Any]] = []
    seen: set[str] = set()
    for upstream in request.app.state.upstreams:
        if upstream.dialect != "anthropic" or not upstream.ready(client_credentials(request)):
            continue
        try:
            reply = await client.get(
                upstream.endpoint("/v1/models"),
                params={"limit": 1000},
                headers={**headers, **upstream.request_headers(client_credentials(request))},
            )
            items = sequence(reply.json().get("data")) if reply.is_success else []
        except (httpx.HTTPError, ValueError, AttributeError):
            continue
        for item in map(mapping, items):
            model_id = item.get("id")
            if isinstance(model_id, str) and model_id not in seen and upstream.serves(model_id):
                seen.add(model_id)
                data.append(item)
    return {
        "data": data,
        "has_more": False,
        "first_id": data[0]["id"] if data else None,
        "last_id": data[-1]["id"] if data else None,
    }
