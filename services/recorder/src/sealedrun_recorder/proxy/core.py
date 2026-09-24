"""Forwarding and recording shared by every wire format the proxy speaks.

Clients point their SDK's base URL at the recorder and use the recorder API token as their API
key; the upstream key is swapped in here, so it never reaches the client and never enters a
record. Only request and response bodies are recorded, never headers or query strings; query
parameters other than `key` are forwarded. A call that cannot be recorded fails: the client gets
a 500 instead of an unrecorded answer.
"""

from __future__ import annotations

import hmac
import json
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx
from fastapi import HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool

from sealedrun_recorder.live import LiveRunError, LiveRuns
from sealedrun_recorder.upstreams import Upstream, Upstreams

RUN_HEADER = "x-sealedrun-run"
RUN_LABEL = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
GEMINI_PATH = re.compile(r"^/(v1beta/|v1/models/[^/]+:)")
JSON = "application/json"
CLIENT_KEY_HEADERS = ("x-api-key", "x-goog-api-key", "api-key")

BodyFields = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class Dialect:
    """A wire format: how its errors look and which client headers reach the upstream."""

    name: str
    error_body: Callable[[int, str], bytes]
    passthrough: tuple[str, ...] = ()


def top_level_temperature(call: dict[str, Any]) -> dict[str, Any]:
    """Read `temperature` from the top level of a request body."""
    return temperature_field(call.get("temperature"))


def temperature_field(value: Any) -> dict[str, Any]:
    """Return `{"temperature": value}` when `value` is a number, else nothing."""
    if isinstance(value, int | float) and not isinstance(value, bool):
        return {"temperature": value}
    return {}


@dataclass(frozen=True)
class Operation:
    """One proxied endpoint: its wire format, upstream path and body parsers.

    `usage` reads `sealedrun.llm` fields from the reply and `sampling` from the request.
    `stream_default` is what the format assumes when the body has no `stream` field.
    """

    dialect: Dialect
    name: str
    path: str
    usage: BodyFields
    stream_default: bool = False
    sampling: BodyFields = top_level_temperature


class RunGrouper:
    """Map proxy calls to live runs.

    Calls carrying the same X-SealedRun-Run label share a run. Calls without a label share one
    default run that is closed after `idle_seconds` without calls; the next call opens a new one.
    Mappings live in memory, so after a restart the next call opens a new run.
    """

    def __init__(
        self,
        live: LiveRuns,
        idle_seconds: float,
        clock: Callable[[], float] = time.monotonic,
    ):
        self._live = live
        self._idle = idle_seconds
        self._clock = clock
        self._runs: dict[str | None, tuple[str, float]] = {}
        self._lock = threading.Lock()

    def run_for(self, label: str | None, *, fresh: bool = False) -> str:
        """Return the run id for `label`, opening a run when none is current or `fresh` is set."""
        with self._lock:
            now = self._clock()
            current = self._runs.get(label)
            if current is not None and not fresh:
                run_id, last_seen = current
                if label is not None or now - last_seen <= self._idle:
                    self._runs[label] = (run_id, now)
                    return run_id
            if current is not None and label is None:
                try:
                    self._live.end(current[0])
                except LiveRunError:
                    pass
            extensions = {"sealedrun.proxy": {"run_label": label}} if label else None
            run_id = str(self._live.start(extensions=extensions)["run_id"])
            self._runs[label] = (run_id, now)
            return run_id

    def record(self, label: str | None, kind: str, **fields: Any) -> dict[str, Any]:
        """Append a record to the run for `label`.

        A run closed behind the grouper's back, for example through the API, is replaced by a
        new one.
        """
        try:
            return self._live.append(self.run_for(label), kind, **fields)
        except LiveRunError:
            return self._live.append(self.run_for(label, fresh=True), kind, **fields)


def require_proxy_token(request: Request) -> None:
    """Refuse proxy calls unless the recorder token is configured and presented.

    The token is accepted wherever the client SDKs put their API key: `Authorization: Bearer`,
    `x-api-key`, `x-goog-api-key`, `api-key`, or the `key` query parameter on Gemini paths,
    which is removed before the call is forwarded or recorded.
    The proxy spends the upstream keys, so unlike the read-only API it never runs open.
    """
    secret = request.app.state.settings.api_token
    if secret is None or not secret.get_secret_value():
        raise HTTPException(503, "the LLM proxy needs SEALEDRUN_API_TOKEN to be set")
    expected = secret.get_secret_value().encode()
    if not any(hmac.compare_digest(c.encode(), expected) for c in _presented_tokens(request)):
        raise HTTPException(401, "invalid or missing token")


def _presented_tokens(request: Request) -> list[str]:
    tokens = [request.headers.get(name, "").strip() for name in CLIENT_KEY_HEADERS]
    scheme, _, value = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() == "bearer":
        tokens.append(value.strip())
    if GEMINI_PATH.match(request.url.path):
        tokens.append(request.query_params.get("key", ""))
    return [t for t in tokens if t]


async def forward(
    request: Request,
    operation: Operation,
    *,
    model: str | None = None,
    path: str | None = None,
) -> Response:
    """Forward one call to the upstream serving its model and record it as an `llm_call`.

    `model` is taken from the JSON body unless the format carries it in the URL; `path`
    overrides the operation's upstream path for such formats.
    """
    dialect = operation.dialect
    settings = request.app.state.settings
    label = request.headers.get(RUN_HEADER)
    if label is not None and not RUN_LABEL.match(label):
        return error(dialect, 400, f"{RUN_HEADER} must match {RUN_LABEL.pattern}")
    limit = settings.proxy_max_body_bytes
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        return error(dialect, 413, "request body exceeds size limit")
    body = await request.body()
    if len(body) > limit:
        return error(dialect, 413, "request body exceeds size limit")
    try:
        call = json.loads(body)
    except ValueError:
        return error(dialect, 400, "request body must be JSON")
    if not isinstance(call, dict):
        return error(dialect, 400, "request body must be a JSON object")
    model = model or call.get("model")
    if not isinstance(model, str) or not model:
        return error(dialect, 400, "request needs a model")
    if call.get("stream", operation.stream_default):
        return error(dialect, 400, "streaming is not supported by this recorder version")

    upstreams: Upstreams = request.app.state.upstreams
    upstream = upstreams.route(dialect.name, model)
    if upstream is None:
        others = upstreams.dialects_for(model)
        if others:
            formats = ", ".join(others)
            return error(dialect, 400, f"model {model} is reachable only as: {formats}")
        return error(dialect, 404, f"no upstream configured for model {model}")
    if upstream.missing_key:
        return error(dialect, 503, f"upstream {upstream.name}: {upstream.key_env} is not set")

    endpoint = upstream.endpoint(path or operation.path)
    started = time.perf_counter()
    try:
        reply = await request.app.state.http.post(
            endpoint,
            params=[(k, v) for k, v in request.query_params.multi_items() if k != "key"],
            content=body,
            headers=upstream_headers(request, upstream, dialect),
            timeout=settings.proxy_timeout_seconds,
        )
        status, answer = reply.status_code, reply.content
        media_type = reply.headers.get("content-type", JSON)
    except httpx.HTTPError as failure:
        status = 502
        reason = f"upstream {upstream.name} unreachable: {type(failure).__name__}"
        answer = dialect.error_body(status, reason)
        media_type = JSON
    latency_ms = round((time.perf_counter() - started) * 1000, 1)

    llm: dict[str, Any] = {"model": model, "provider": upstream.name, "stream": False}
    llm.update(operation.sampling(call))
    parsed = _json_object(answer)
    if parsed is not None:
        llm.update(operation.usage(parsed))
    await run_in_threadpool(
        request.app.state.runs.record,
        label,
        "llm_call",
        target={
            "type": "model",
            "name": model,
            "endpoint": endpoint,
            "location": upstream.location,
            "provider": upstream.name,
        },
        request=body,
        response=answer,
        request_media_type=JSON,
        response_media_type=media_type.partition(";")[0].strip() or None,
        outcome="success" if 200 <= status < 300 else "error",
        extensions={
            "sealedrun.llm": llm,
            "sealedrun.proxy": {
                "upstream": upstream.name,
                "dialect": dialect.name,
                "operation": operation.name,
                "status": status,
                "latency_ms": latency_ms,
            },
        },
    )
    return Response(answer, status_code=status, media_type=media_type)


def upstream_headers(request: Request, upstream: Upstream, dialect: Dialect) -> dict[str, str]:
    """Build the upstream request headers: JSON, allowed client headers, upstream credential."""
    headers = {"content-type": JSON, "accept": JSON}
    for name in dialect.passthrough:
        value = request.headers.get(name)
        if value is not None:
            headers[name] = value
    headers.update(upstream.request_headers())
    return headers


def error(dialect: Dialect, status: int, message: str) -> Response:
    """Return a proxy-generated error in the format's own error shape."""
    return Response(dialect.error_body(status, message), status_code=status, media_type=JSON)


def integer(value: Any) -> int | None:
    """Return `value` if it is a non-negative integer, else None."""
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return None


def mapping(value: Any) -> dict[str, Any]:
    """Return `value` if it is a JSON object, else an empty one."""
    return value if isinstance(value, dict) else {}


def sequence(value: Any) -> list[Any]:
    """Return `value` if it is a JSON array, else an empty one."""
    return value if isinstance(value, list) else []


def _json_object(body: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(body)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None
