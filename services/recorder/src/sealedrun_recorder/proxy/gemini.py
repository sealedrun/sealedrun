"""Gemini native wire format: `models/{model}:generateContent` and friends.

For the Google Gen AI SDKs, Gemini CLI and ADK. They reach the recorder through the SDK's
`http_options.base_url` (or `GOOGLE_GEMINI_BASE_URL` in Gemini CLI) and send the recorder token
as `x-goog-api-key` or in the `key` query parameter; the parameter is never forwarded or
recorded. The model sits in the URL, and the API version of the request (`v1beta` or `v1`) is
kept upstream.
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
    StreamSummary,
    client_credentials,
    error,
    forward,
    integer,
    mapping,
    require_proxy_token,
    sequence,
    sse_data,
    temperature_field,
)

STATUS_NAMES = {
    400: "INVALID_ARGUMENT",
    401: "UNAUTHENTICATED",
    403: "PERMISSION_DENIED",
    404: "NOT_FOUND",
    413: "INVALID_ARGUMENT",
    429: "RESOURCE_EXHAUSTED",
    502: "UNAVAILABLE",
    503: "UNAVAILABLE",
}


def _error_body(status: int, message: str) -> bytes:
    body = {"code": status, "message": message, "status": STATUS_NAMES.get(status, "INTERNAL")}
    return json.dumps({"error": body}).encode()


def _generation_temperature(call: dict[str, Any]) -> dict[str, Any]:
    return temperature_field(mapping(call.get("generationConfig")).get("temperature"))


def generate_usage(reply: dict[str, Any]) -> dict[str, Any]:
    """Read model, token counts, finish reason and requested tools from a generateContent reply.

    `output_tokens` includes thinking tokens, which the other formats count as output too.
    """
    llm: dict[str, Any] = {}
    if isinstance(reply.get("modelVersion"), str) and reply["modelVersion"]:
        llm["model"] = reply["modelVersion"]
    usage = mapping(reply.get("usageMetadata"))
    prompt = integer(usage.get("promptTokenCount"))
    if prompt is not None:
        llm["input_tokens"] = prompt
    parts = [integer(usage.get(f)) for f in ("candidatesTokenCount", "thoughtsTokenCount")]
    if any(p is not None for p in parts):
        llm["output_tokens"] = sum(p for p in parts if p is not None)
    candidates = sequence(reply.get("candidates"))
    if candidates:
        first = mapping(candidates[0])
        if isinstance(first.get("finishReason"), str):
            llm["finish_reason"] = first["finishReason"]
        names = [
            name
            for part in sequence(mapping(first.get("content")).get("parts"))
            if isinstance(name := mapping(mapping(part).get("functionCall")).get("name"), str)
        ]
        if names:
            llm["tool_calls_requested"] = names
    return llm


def count_tokens_usage(reply: dict[str, Any]) -> dict[str, Any]:
    """Read the counted prompt size from a countTokens reply."""
    counted = integer(reply.get("totalTokens"))
    return {} if counted is None else {"input_tokens": counted}


def embed_usage(reply: dict[str, Any]) -> dict[str, Any]:
    """Read the prompt token count from an embedding reply when the API reports one."""
    prompt = integer(mapping(reply.get("usageMetadata")).get("promptTokenCount"))
    return {} if prompt is None else {"input_tokens": prompt}


def generate_stream(raw: bytes) -> StreamSummary:
    """Read the same fields from a streamed generateContent call (`alt=sse`).

    Every chunk is a partial reply in the plain shape; the last one carries the finish reason
    and the usage. Function calls may arrive in any chunk. A chunk with `error` marks the stream
    failed.
    """
    llm: dict[str, Any] = {}
    names: list[str] = []
    failed = False
    complete = False
    for chunk in sse_data(raw):
        if "error" in chunk:
            failed = True
        fields = generate_usage(chunk)
        names.extend(fields.pop("tool_calls_requested", []))
        llm.update(fields)
        if "finish_reason" in fields:
            complete = True
    if names:
        llm["tool_calls_requested"] = names
    return StreamSummary(llm, failed, complete)


GEMINI = Dialect("gemini", _error_body)
OPERATIONS = {
    "generateContent": Operation(
        GEMINI, "generate", "", generate_usage, sampling=_generation_temperature
    ),
    "streamGenerateContent": Operation(
        GEMINI,
        "generate",
        "",
        generate_usage,
        sampling=_generation_temperature,
        stream=generate_stream,
    ),
    "countTokens": Operation(GEMINI, "count_tokens", "", count_tokens_usage),
    "embedContent": Operation(GEMINI, "embeddings", "", embed_usage),
    "batchEmbedContents": Operation(GEMINI, "embeddings", "", embed_usage),
}
STREAMING = frozenset({"streamGenerateContent"})

router = APIRouter(dependencies=[Depends(require_proxy_token)])


@router.post("/{version}/models/{target}")
async def model_action(version: str, target: str, request: Request) -> Response:
    """Forward `models/{model}:{action}` to the upstream serving the model and record it."""
    if version not in ("v1beta", "v1"):
        return error(GEMINI, 404, "unknown API version")
    model, _, action = target.rpartition(":")
    streaming = action in STREAMING
    if streaming and request.query_params.get("alt") != "sse":
        return error(GEMINI, 400, "streamGenerateContent is supported with alt=sse only")
    operation = OPERATIONS.get(action)
    if operation is None or not model:
        return error(GEMINI, 404, f"unsupported method {action or target}")
    return await forward(
        request, operation, model=model, path=f"/{version}/models/{target}", stream=streaming
    )


@router.get("/v1beta/models")
async def list_models(request: Request) -> dict[str, Any]:
    """List the models of every Gemini-format upstream that the upstream's patterns route.

    Answers as one page. Upstreams that fail to answer or lack their key are left out. Listing
    is not recorded.
    """
    client: httpx.AsyncClient = request.app.state.http
    models: list[dict[str, Any]] = []
    seen: set[str] = set()
    for upstream in request.app.state.upstreams:
        if upstream.dialect != "gemini" or not upstream.ready(client_credentials(request)):
            continue
        try:
            reply = await client.get(
                upstream.endpoint("/v1beta/models"),
                params={"pageSize": 1000},
                headers={"accept": JSON, **upstream.request_headers(client_credentials(request))},
            )
            items = sequence(reply.json().get("models")) if reply.is_success else []
        except (httpx.HTTPError, ValueError, AttributeError):
            continue
        for item in map(mapping, items):
            name = item.get("name")
            model_id = name.removeprefix("models/") if isinstance(name, str) else None
            if model_id and model_id not in seen and upstream.serves(model_id):
                seen.add(model_id)
                models.append(item)
    return {"models": models}


@router.get("/v1beta/models/{model}")
async def get_model(model: str, request: Request) -> Response:
    """Forward a model details request to the upstream serving the model, without recording."""
    upstream = request.app.state.upstreams.route("gemini", model)
    if upstream is None:
        return error(GEMINI, 404, f"no upstream configured for model {model}")
    if not upstream.ready(client_credentials(request)):
        return error(GEMINI, 503, f"upstream {upstream.name}: {upstream.key_env} is not set")
    try:
        reply = await request.app.state.http.get(
            upstream.endpoint(f"/v1beta/models/{model}"),
            headers={"accept": JSON, **upstream.request_headers(client_credentials(request))},
        )
    except httpx.HTTPError:
        return error(GEMINI, 502, f"upstream {upstream.name} unreachable")
    return Response(reply.content, status_code=reply.status_code, media_type=JSON)
