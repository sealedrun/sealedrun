"""Ollama native wire format: `/api/chat`, `/api/generate`, `/api/embed` and model metadata.

For the Ollama SDKs and tools that speak only the native API. They reach the recorder through
`OLLAMA_HOST` and send the recorder token as a bearer token (`OLLAMA_API_KEY` in the Python
SDK, or explicit client headers). Model management (`pull`, `push`, `create`, `delete`) is not
proxied.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from fastapi import APIRouter, Depends, Request, Response

from sealedrun_recorder.proxy.core import (
    JSON,
    Dialect,
    Operation,
    error,
    forward,
    integer,
    mapping,
    require_proxy_token,
    sequence,
    temperature_field,
)


def _error_body(status: int, message: str) -> bytes:
    return json.dumps({"error": message}).encode()


def _options_temperature(call: dict[str, Any]) -> dict[str, Any]:
    return temperature_field(mapping(call.get("options")).get("temperature"))


def generation_usage(reply: dict[str, Any]) -> dict[str, Any]:
    """Read model, token counts, done reason and requested tools from a chat or generate reply."""
    llm = embed_usage(reply)
    output = integer(reply.get("eval_count"))
    if output is not None:
        llm["output_tokens"] = output
    if isinstance(reply.get("done_reason"), str):
        llm["finish_reason"] = reply["done_reason"]
    names = [
        name
        for call in sequence(mapping(reply.get("message")).get("tool_calls"))
        if isinstance(name := mapping(mapping(call).get("function")).get("name"), str)
    ]
    if names:
        llm["tool_calls_requested"] = names
    return llm


def embed_usage(reply: dict[str, Any]) -> dict[str, Any]:
    """Read model and prompt token count from an Ollama reply."""
    llm: dict[str, Any] = {}
    if isinstance(reply.get("model"), str) and reply["model"]:
        llm["model"] = reply["model"]
    prompt = integer(reply.get("prompt_eval_count"))
    if prompt is not None:
        llm["input_tokens"] = prompt
    return llm


OLLAMA = Dialect("ollama", _error_body)
CHAT = Operation(
    OLLAMA,
    "chat",
    "/api/chat",
    generation_usage,
    stream_default=True,
    sampling=_options_temperature,
)
GENERATE = Operation(
    OLLAMA,
    "generate",
    "/api/generate",
    generation_usage,
    stream_default=True,
    sampling=_options_temperature,
)
EMBED = Operation(OLLAMA, "embeddings", "/api/embed", embed_usage)
LEGACY_EMBEDDINGS = Operation(OLLAMA, "embeddings", "/api/embeddings", embed_usage)

router = APIRouter(prefix="/api", dependencies=[Depends(require_proxy_token)])


@router.post("/chat")
async def chat(request: Request) -> Response:
    """Forward a native chat call and record it as an `llm_call`."""
    return await forward(request, CHAT)


@router.post("/generate")
async def generate(request: Request) -> Response:
    """Forward a native generate call and record it as an `llm_call`."""
    return await forward(request, GENERATE)


@router.post("/embed")
async def embed(request: Request) -> Response:
    """Forward a native embed call and record it as an `llm_call`."""
    return await forward(request, EMBED)


@router.post("/embeddings")
async def embeddings(request: Request) -> Response:
    """Forward a call to the older single-prompt embeddings endpoint and record it."""
    return await forward(request, LEGACY_EMBEDDINGS)


@router.get("/tags")
async def tags(request: Request) -> dict[str, Any]:
    """List the models of every Ollama-format upstream that the upstream's patterns route.

    Upstreams that fail to answer or lack their key are left out. Listing is not recorded.
    """
    client: httpx.AsyncClient = request.app.state.http
    models: list[dict[str, Any]] = []
    seen: set[str] = set()
    for upstream in request.app.state.upstreams:
        if upstream.dialect != "ollama" or upstream.missing_key:
            continue
        try:
            reply = await client.get(
                upstream.endpoint("/api/tags"),
                headers={"accept": JSON, **upstream.request_headers()},
            )
            items = sequence(reply.json().get("models")) if reply.is_success else []
        except (httpx.HTTPError, ValueError, AttributeError):
            continue
        for item in map(mapping, items):
            name = item.get("name") or item.get("model")
            if isinstance(name, str) and name not in seen and upstream.serves(name):
                seen.add(name)
                models.append(item)
    return {"models": models}


@router.get("/version")
async def version(request: Request) -> Response:
    """Report the version of the first reachable Ollama-format upstream."""
    for upstream in request.app.state.upstreams:
        if upstream.dialect != "ollama" or upstream.missing_key:
            continue
        try:
            reply = await request.app.state.http.get(
                upstream.endpoint("/api/version"),
                headers={"accept": JSON, **upstream.request_headers()},
            )
        except httpx.HTTPError:
            continue
        if reply.is_success:
            return Response(reply.content, media_type=JSON)
    return error(OLLAMA, 503, "no Ollama upstream reachable")


@router.post("/show")
async def show(request: Request) -> Response:
    """Forward a model details request to the upstream serving the model, without recording.

    Details are model metadata, not a model call.
    """
    body = await request.body()
    if len(body) > 64 * 1024:
        return error(OLLAMA, 413, "request body exceeds size limit")
    try:
        call = mapping(json.loads(body))
    except ValueError:
        return error(OLLAMA, 400, "request body must be JSON")
    model = call.get("model") or call.get("name")
    if not isinstance(model, str) or not model:
        return error(OLLAMA, 400, "request needs a model")
    upstream = request.app.state.upstreams.route("ollama", model)
    if upstream is None:
        return error(OLLAMA, 404, f"no upstream configured for model {model}")
    if upstream.missing_key:
        return error(OLLAMA, 503, f"upstream {upstream.name}: {upstream.key_env} is not set")
    try:
        reply = await request.app.state.http.post(
            upstream.endpoint("/api/show"),
            content=body,
            headers={"content-type": JSON, "accept": JSON, **upstream.request_headers()},
        )
    except httpx.HTTPError:
        return error(OLLAMA, 502, f"upstream {upstream.name} unreachable")
    return Response(reply.content, status_code=reply.status_code, media_type=JSON)
