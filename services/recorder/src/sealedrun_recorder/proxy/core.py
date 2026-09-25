"""Forwarding and recording shared by every wire format the proxy speaks.

Clients point their SDK's base URL at the recorder and use the recorder API token as their API
key; the upstream key is swapped in here, so it never reaches the client and never enters a
record. Only request and response bodies are recorded, never headers or query strings; query
parameters other than `key` are forwarded. A call that cannot be recorded fails: the client gets
a 500 instead of an unrecorded answer.

A streamed reply is passed through chunk by chunk and recorded as the raw stream bytes once it
ends. A stream cut short, by the client leaving, the upstream breaking or the size cap, is still
recorded, marked `truncated` with outcome `error`.
"""

from __future__ import annotations

import hmac
import json
import re
import threading
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

import anyio
import httpx
from fastapi import HTTPException, Request, Response
from starlette.concurrency import run_in_threadpool
from starlette.responses import StreamingResponse

from sealedrun_recorder.live import LiveRunError, LiveRuns
from sealedrun_recorder.upstreams import Upstream, Upstreams

RUN_HEADER = "x-sealedrun-run"
RUN_LABEL = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
GEMINI_PATH = re.compile(r"^/(v1beta/|v1/models/[^/]+:)")
JSON = "application/json"
SSE = "text/event-stream"
NDJSON = "application/x-ndjson"
CLIENT_KEY_HEADERS = ("x-api-key", "x-goog-api-key", "api-key")

BodyFields = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class StreamSummary:
    """What a dialect reads from a stream that ended.

    `llm` holds the `sealedrun.llm` fields, `failed` says the stream carried an error, and
    `complete` says the format's own end marker was seen, so a connection closed right after it
    (which SDKs do) is not a truncation.
    """

    llm: dict[str, Any]
    failed: bool = False
    complete: bool = False


StreamFields = Callable[[bytes], StreamSummary]


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
    `stream_default` is what the format assumes when the body has no `stream` field; `stream`
    reads the fields from a finished stream, and is None for endpoints that never stream.
    `stream_media_type` is the stream's content type when the upstream does not name one.
    """

    dialect: Dialect
    name: str
    path: str
    usage: BodyFields
    stream_default: bool = False
    sampling: BodyFields = top_level_temperature
    stream: StreamFields | None = None
    stream_media_type: str = SSE


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
    stream: bool | None = None,
) -> Response:
    """Forward one call to the upstream serving its model and record it as an `llm_call`.

    `model` is taken from the JSON body unless the format carries it in the URL; `path`
    overrides the operation's upstream path for such formats; `stream` says whether the call
    streams when the format decides that by URL rather than by a body field.
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
    streaming = bool(call.get("stream", operation.stream_default)) if stream is None else stream
    if streaming and operation.stream is None:
        return error(dialect, 400, f"streaming is not supported for {operation.name}")

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

    exchange = Exchange(request, operation, upstream, label, model, call, body, streaming, path)
    if streaming:
        return await exchange.stream()
    return await exchange.buffered()


@dataclass
class Exchange:
    """One routed call: forward it, then record it with the outcome the client saw."""

    request: Request
    operation: Operation
    upstream: Upstream
    label: str | None
    model: str
    call: dict[str, Any]
    body: bytes
    streaming: bool
    path: str | None = None

    def __post_init__(self) -> None:
        settings = self.request.app.state.settings
        self.endpoint = self.upstream.endpoint(self.path or self.operation.path)
        self.timeout: float = settings.proxy_timeout_seconds
        self.limit: int = settings.proxy_max_body_bytes
        self.started = time.perf_counter()

    def _build(self) -> httpx.Request:
        http: httpx.AsyncClient = self.request.app.state.http
        headers = upstream_headers(self.request, self.upstream, self.operation.dialect)
        if self.streaming:
            headers["accept"] = f"{self.operation.stream_media_type}, {JSON}"
        return http.build_request(
            "POST",
            self.endpoint,
            params=[(k, v) for k, v in self.request.query_params.multi_items() if k != "key"],
            content=self.body,
            headers=headers,
            timeout=self.timeout,
        )

    def _unreachable(self, failure: httpx.HTTPError) -> tuple[int, bytes]:
        reason = f"upstream {self.upstream.name} unreachable: {type(failure).__name__}"
        return 502, self.operation.dialect.error_body(502, reason)

    async def buffered(self) -> Response:
        """Forward a plain call, record the reply and return it."""
        try:
            reply = await self.request.app.state.http.send(self._build())
            status, answer = reply.status_code, reply.content
            media_type = reply.headers.get("content-type", JSON)
        except httpx.HTTPError as failure:
            status, answer = self._unreachable(failure)
            media_type = JSON
        await self._record(status, answer, media_type)
        return Response(answer, status_code=status, media_type=media_type)

    async def stream(self) -> Response:
        """Forward a streamed call, pass the chunks through and record the stream when it ends.

        An upstream error status arrives as a plain body and is handled like a plain call.
        """
        http: httpx.AsyncClient = self.request.app.state.http
        try:
            reply = await http.send(self._build(), stream=True)
        except httpx.HTTPError as failure:
            status, answer = self._unreachable(failure)
            await self._record(status, answer, JSON)
            return Response(answer, status_code=status, media_type=JSON)
        media_type = reply.headers.get("content-type", self.operation.stream_media_type)
        if not reply.is_success:
            answer = await reply.aread()
            await reply.aclose()
            await self._record(reply.status_code, answer, media_type)
            return Response(answer, status_code=reply.status_code, media_type=media_type)
        return StreamingResponse(
            self._relay(reply, media_type),
            status_code=reply.status_code,
            headers={"content-type": media_type},
        )

    async def _relay(self, reply: httpx.Response, media_type: str) -> AsyncIterator[bytes]:
        """Yield the upstream chunks as they come; whatever ends the stream, record it.

        The record is written under a shielded scope so that a client disconnect, which
        cancels the response, still leaves the partial stream on the chain.
        """
        received: list[bytes] = []
        size = 0
        truncated = True
        try:
            async for chunk in reply.aiter_raw():
                if size + len(chunk) > self.limit:
                    break
                received.append(chunk)
                size += len(chunk)
                yield chunk
            else:
                truncated = False
        except httpx.HTTPError:
            pass
        finally:
            with anyio.CancelScope(shield=True):
                await reply.aclose()
                await self._record(reply.status_code, b"".join(received), media_type, truncated)

    async def _record(
        self, status: int, answer: bytes, media_type: str, truncated: bool = False
    ) -> None:
        latency_ms = round((time.perf_counter() - self.started) * 1000, 1)
        operation = self.operation
        llm: dict[str, Any] = {
            "model": self.model,
            "provider": self.upstream.name,
            "stream": self.streaming,
        }
        llm.update(operation.sampling(self.call))
        if self.streaming and status < 300 and operation.stream is not None:
            summary = operation.stream(answer)
            llm.update(summary.llm)
            truncated = truncated and not summary.complete
            failed = truncated or summary.failed
        else:
            failed = truncated or not 200 <= status < 300
            parsed = _json_object(answer)
            if parsed is not None:
                llm.update(operation.usage(parsed))
        proxy: dict[str, Any] = {
            "upstream": self.upstream.name,
            "dialect": operation.dialect.name,
            "operation": operation.name,
            "status": status,
            "latency_ms": latency_ms,
        }
        if truncated:
            proxy["truncated"] = True
        await run_in_threadpool(
            self.request.app.state.runs.record,
            self.label,
            "llm_call",
            target={
                "type": "model",
                "name": self.model,
                "endpoint": self.endpoint,
                "location": self.upstream.location,
                "provider": self.upstream.name,
            },
            request=self.body,
            response=answer,
            request_media_type=JSON,
            response_media_type=media_type.partition(";")[0].strip() or None,
            outcome="error" if failed else "success",
            extensions={"sealedrun.llm": llm, "sealedrun.proxy": proxy},
        )


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


def sse_data(raw: bytes) -> list[dict[str, Any]]:
    """Return the JSON objects carried by the `data:` fields of an SSE stream, in order.

    Events are separated by blank lines; several `data:` lines of one event are joined with a
    newline. `[DONE]` and anything that is not a JSON object are skipped.
    """
    objects = (_json_object(data) for data in sse_payloads(raw) if data.strip() != b"[DONE]")
    return [o for o in objects if o is not None]


def sse_payloads(raw: bytes) -> list[bytes]:
    """Return the `data:` payload of every event of an SSE stream, in order, as raw bytes."""
    payloads: list[bytes] = []
    for block in re.split(rb"\r?\n\r?\n", raw):
        lines = [line[5:].lstrip(b" ") for line in block.splitlines() if line.startswith(b"data:")]
        if lines:
            payloads.append(b"\n".join(lines))
    return payloads


def sse_done(raw: bytes) -> bool:
    """Whether the stream ended with the OpenAI-style `data: [DONE]` marker."""
    payloads = sse_payloads(raw)
    return bool(payloads) and payloads[-1].strip() == b"[DONE]"


def ndjson(raw: bytes) -> list[dict[str, Any]]:
    """Return the JSON objects of a newline-delimited stream, in order, skipping other lines."""
    objects = (_json_object(line) for line in raw.splitlines() if line.strip())
    return [o for o in objects if o is not None]


def _json_object(body: bytes) -> dict[str, Any] | None:
    try:
        value = json.loads(body)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None
