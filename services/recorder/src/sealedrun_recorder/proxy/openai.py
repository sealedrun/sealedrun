"""OpenAI wire format: Chat Completions, Responses, Embeddings and the model list.

Spoken by OpenAI, Azure OpenAI v1, Gemini's compatibility layer, DeepSeek, Kimi, Qwen, GLM,
MiniMax, Mistral, xAI, Groq, OpenRouter and the local runtimes (Ollama, LM Studio, vLLM,
llama.cpp, SGLang).
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Request, Response

from sealedrun_recorder.proxy.core import (
    Dialect,
    Operation,
    forward,
    integer,
    mapping,
    require_proxy_token,
    sequence,
)


def _error_body(status: int, message: str) -> bytes:
    return json.dumps({"error": {"message": message, "type": "sealedrun_proxy_error"}}).encode()


def _model(reply: dict[str, Any]) -> dict[str, Any]:
    model = reply.get("model")
    return {"model": model} if isinstance(model, str) and model else {}


def _tokens(usage: dict[str, Any], input_field: str, output_field: str) -> dict[str, Any]:
    llm: dict[str, Any] = {}
    for source, field in ((input_field, "input_tokens"), (output_field, "output_tokens")):
        value = integer(usage.get(source))
        if value is not None:
            llm[field] = value
    return llm


def chat_usage(reply: dict[str, Any]) -> dict[str, Any]:
    """Read model, token counts, finish reason and requested tools from a chat completion."""
    llm = _model(reply) | _tokens(mapping(reply.get("usage")), "prompt_tokens", "completion_tokens")
    choices = sequence(reply.get("choices"))
    if choices:
        first = mapping(choices[0])
        if isinstance(first.get("finish_reason"), str):
            llm["finish_reason"] = first["finish_reason"]
        names = [
            name
            for call in sequence(mapping(first.get("message")).get("tool_calls"))
            if isinstance(name := mapping(mapping(call).get("function")).get("name"), str)
        ]
        if names:
            llm["tool_calls_requested"] = names
    return llm


def embeddings_usage(reply: dict[str, Any]) -> dict[str, Any]:
    """Read model and input token count from an embeddings reply."""
    return _model(reply) | _tokens(mapping(reply.get("usage")), "prompt_tokens", "-")


def responses_usage(reply: dict[str, Any]) -> dict[str, Any]:
    """Read model, token counts, status and requested tools from a Responses API reply.

    `finish_reason` is the incomplete reason when the response stopped early, else its status.
    """
    llm = _model(reply) | _tokens(mapping(reply.get("usage")), "input_tokens", "output_tokens")
    reason = mapping(reply.get("incomplete_details")).get("reason")
    status = reply.get("status")
    if isinstance(reason, str):
        llm["finish_reason"] = reason
    elif isinstance(status, str):
        llm["finish_reason"] = status
    names = [
        item["name"]
        for item in map(mapping, sequence(reply.get("output")))
        if item.get("type") in ("function_call", "custom_tool_call")
        and isinstance(item.get("name"), str)
    ]
    if names:
        llm["tool_calls_requested"] = names
    return llm


OPENAI = Dialect("openai", _error_body, passthrough=("openai-beta",))
CHAT = Operation(OPENAI, "chat", "/chat/completions", chat_usage)
EMBEDDINGS = Operation(OPENAI, "embeddings", "/embeddings", embeddings_usage)
RESPONSES = Operation(OPENAI, "responses", "/responses", responses_usage)

router = APIRouter(prefix="/v1", dependencies=[Depends(require_proxy_token)])


@router.post("/chat/completions")
async def chat_completions(request: Request) -> Response:
    """Forward a chat completion and record it as an `llm_call`."""
    return await forward(request, CHAT)


@router.post("/responses")
async def responses(request: Request) -> Response:
    """Forward a Responses API call and record it as an `llm_call`."""
    return await forward(request, RESPONSES)


@router.post("/embeddings")
async def embeddings(request: Request) -> Response:
    """Forward an embeddings request and record it as an `llm_call`."""
    return await forward(request, EMBEDDINGS)


async def list_models(request: Request) -> dict[str, Any]:
    """List the models of every OpenAI-format upstream that the upstream's patterns route.

    Upstreams that fail to answer or lack their key are left out. Listing is not recorded.
    """
    client: httpx.AsyncClient = request.app.state.http
    data: list[dict[str, Any]] = []
    seen: set[str] = set()
    for upstream in request.app.state.upstreams:
        if upstream.dialect != "openai" or upstream.missing_key:
            continue
        try:
            reply = await client.get(
                upstream.endpoint("/models"),
                headers={"accept": "application/json", **upstream.request_headers()},
            )
            items = sequence(reply.json().get("data")) if reply.is_success else []
        except (httpx.HTTPError, ValueError, AttributeError):
            continue
        for item in map(mapping, items):
            model_id = item.get("id")
            if isinstance(model_id, str) and model_id not in seen and upstream.serves(model_id):
                seen.add(model_id)
                data.append(item)
    return {"object": "list", "data": data}
