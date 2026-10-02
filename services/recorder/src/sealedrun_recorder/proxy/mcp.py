"""MCP proxy: Streamable HTTP servers behind `/mcp/<name>`, recorded into the same live runs.

The servers come from `mcp_servers` in the upstreams file; a client names one by path and never
supplies its URL. Access needs the recorder token, as for the LLM proxy.

Both protocol eras pass through unchanged: the stateless 2026-07-28 transport (every message its
own POST, routing headers `Mcp-Method`, `Mcp-Name`, `Mcp-Param-*`) and the 2025-03-26 to
2025-11-25 one (`initialize`, `Mcp-Session-Id`, a GET stream, DELETE to end a session). The
proxy never rewrites a body: header and body consistency is the server's to check. Replies,
JSON or SSE, are relayed chunk by chunk as they arrive.

`tools/call`, `resources/read`, `prompts/get` and `tools/list` requests that the server accepts
(2xx) are recorded as `tool_call` records holding the request body and the reply: the JSON body,
or the raw SSE stream in which the response to the request's id was found. A JSON reply is
recorded before the client gets it, so a call that cannot be recorded fails with 500. An SSE
reply is recorded when it ends; one that ends without the response is marked `truncated`.
`tools/list` is recorded once per run, server and cursor, and again only when its result
changes. Everything else is forwarded without a record: notifications, client responses,
`initialize`, `server/discover`, `subscriptions/listen`, GET streams, DELETE, and messages the
server refused.

Three shapes never reach a server, because they could carry a call past the record and the
policy rule: a JSON-RPC batch (an array body), a request whose id is not a string or an integer,
and a recorded method sent without an id. All are refused with 400. Proxy-generated JSON-RPC
errors use the application codes `40000` (proxy error) and `40003` (blocked by policy), outside
the range the MCP specification reserves.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from collections import OrderedDict
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any, TypeGuard
from urllib.parse import urlsplit

import anyio
import httpx
from fastapi import APIRouter, Depends, Request, Response
from starlette.concurrency import run_in_threadpool
from starlette.responses import StreamingResponse

from sealedrun_recorder.limits import BodyTooLargeError, parse_json, read_body, read_reply
from sealedrun_recorder.live import LiveRunError
from sealedrun_recorder.policy import Decision, Rule
from sealedrun_recorder.proxy.context import (
    AgentError,
    client_info_agent,
    header_agent,
    run_context,
    tool_inventory_digest,
)
from sealedrun_recorder.proxy.core import (
    JSON,
    RUN_HEADER,
    RUN_LABEL,
    SSE,
    client_credentials,
    mapping,
    require_proxy_token,
    sse_data,
)
from sealedrun_recorder.proxy.labels import LabelsError, header_labels, label_fields
from sealedrun_recorder.upstreams import McpServer, Upstreams

RECORDED = frozenset({"tools/call", "resources/read", "prompts/get", "tools/list"})
GOVERNED = frozenset({"tools/call", "resources/read", "prompts/get"})
PROXY_ERROR = 40000
POLICY_ERROR = 40003
NAME_PARAM = {"tools/call": "name", "resources/read": "uri", "prompts/get": "name"}
MAX_LISTS = 4096
MAX_NAME = 256

log = logging.getLogger("sealedrun.proxy")

SAME_SITE = frozenset({"same-origin", "none"})
REQUEST_HEADERS = (
    "accept",
    "content-type",
    "mcp-protocol-version",
    "mcp-method",
    "mcp-name",
    "mcp-session-id",
    "last-event-id",
    "traceparent",
    "tracestate",
)
REQUEST_PREFIXES = ("mcp-param-",)
REPLY_HEADERS = (
    "content-type",
    "mcp-session-id",
    "mcp-protocol-version",
    "www-authenticate",
    "retry-after",
    "cache-control",
)

router = APIRouter()


@router.api_route(
    "/mcp/{server}",
    methods=["POST", "GET", "DELETE"],
    dependencies=[Depends(require_proxy_token)],
)
async def mcp(server: str, request: Request) -> Response:
    """Forward one MCP message, stream or session end to the named server; record tool use."""
    if not same_origin(request):
        return error(403, "cross-site request refused")
    label = request.headers.get(RUN_HEADER)
    if label is not None and not RUN_LABEL.match(label):
        return error(400, f"{RUN_HEADER} must match {RUN_LABEL.pattern}")
    try:
        labels = header_labels(request)
        header_agent(request)
    except (LabelsError, AgentError) as problem:
        return error(400, str(problem))
    upstreams: Upstreams = request.app.state.upstreams
    target = upstreams.mcp(server)
    if target is None:
        return error(404, f"no MCP server configured as {server}")
    if not target.ready(client_credentials(request)):
        log.error("MCP server %s: %s is not set", target.name, target.key_env)
        return error(503, "MCP server is not configured on the recorder")
    limit = request.app.state.settings.proxy_max_body_bytes
    try:
        body = await read_body(request, limit)
    except BodyTooLargeError:
        return error(413, "request body exceeds size limit")
    try:
        call = McpCall.parse(request, body) if request.method == "POST" else None
    except McpRequestError as problem:
        return error(400, str(problem))
    started = time.perf_counter()
    policy = None
    if call is not None and call.method in GOVERNED:
        rule: Rule = request.app.state.policy
        policy = rule.evaluate(target.location, labels)
    if call is not None and policy is not None and policy.blocked:
        await _record(request, target, call, label, body, 403, None, "", started, labels, policy)
        message = f"blocked by policy {policy.rule_id}: {policy.reason}"
        return error(403, message, code=POLICY_ERROR, request_id=call.id)
    http: httpx.AsyncClient = request.app.state.http
    try:
        reply = await http.send(_build(request, target, body), stream=True)
    except httpx.HTTPError as failure:
        log.error("MCP server %s unreachable: %s", target.name, type(failure).__name__)
        return error(502, "MCP server unreachable")
    headers = {k: v for k, v in reply.headers.items() if k in REPLY_HEADERS}
    media_type = reply.headers.get("content-type", "")
    streamed = media_type.startswith(SSE)
    if streamed:
        headers["x-accel-buffering"] = "no"
    if call is None or not reply.is_success:
        return StreamingResponse(_relay(reply), status_code=reply.status_code, headers=headers)

    async def finish(answer: bytes) -> None:
        await _record(
            request,
            target,
            call,
            label,
            body,
            reply.status_code,
            answer,
            media_type,
            started,
            labels,
            policy,
        )

    if streamed:
        relay = _relay_recorded(reply, limit, finish)
        return StreamingResponse(relay, status_code=reply.status_code, headers=headers)
    try:
        answer = await read_reply(reply, limit)
    except httpx.HTTPError:
        answer = b""
    except BodyTooLargeError:
        await finish(b"")
        log.error("MCP server %s reply exceeds size limit", target.name)
        return error(502, "MCP server reply exceeds size limit")
    await finish(answer)
    return Response(answer, status_code=reply.status_code, headers=headers)


class McpRequestError(ValueError):
    """A POST body the proxy refuses to forward; the message says why."""


@dataclass(frozen=True)
class McpCall:
    """A client request the proxy records: its method, JSON-RPC id and the name it acts on."""

    method: str
    id: str | int
    name: str
    cursor: str | None
    protocol_version: str | None
    session: str | None

    @classmethod
    def parse(cls, request: Request, body: bytes) -> McpCall | None:
        """Read a recorded request from a POST body; None for anything forwarded unrecorded.

        Raises McpRequestError for a batch, a request whose id is not a string or an integer,
        and a recorded method sent as a notification: none can be matched to a response, so
        none is forwarded.
        """
        try:
            message = parse_json(body)
        except ValueError:
            return None
        if isinstance(message, list):
            raise McpRequestError("JSON-RPC batches are not accepted")
        if not isinstance(message, dict):
            return None
        method = message.get("method")
        request_id = message.get("id")
        if method in RECORDED and "id" not in message:
            raise McpRequestError(f"{method} must be a JSON-RPC request with an id")
        if method is not None and "id" in message and not valid_id(request_id):
            raise McpRequestError("JSON-RPC request id must be a string or an integer")
        if method not in RECORDED or not valid_id(request_id):
            return None
        params = mapping(message.get("params"))
        name = params.get(NAME_PARAM.get(method, ""))
        if isinstance(name, str) and len(name) > MAX_NAME:
            raise McpRequestError(f"{NAME_PARAM[method]} longer than {MAX_NAME} characters")
        cursor = params.get("cursor")
        session = request.headers.get("mcp-session-id")
        return cls(
            method=method,
            id=request_id,
            name=name if isinstance(name, str) and name else method,
            cursor=cursor if isinstance(cursor, str) else None,
            protocol_version=request.headers.get("mcp-protocol-version"),
            session=hashlib.sha256(session.encode()).hexdigest() if session else None,
        )

    def response_in(self, answer: bytes, media_type: str) -> dict[str, Any] | None:
        """Find the JSON-RPC response to this request in a JSON body or an SSE stream."""
        if media_type.startswith(SSE):
            messages = sse_data(answer)
        else:
            try:
                messages = [parse_json(answer)]
            except ValueError:
                return None
        for message in messages:
            if (
                isinstance(message, dict)
                and "method" not in message
                and message.get("id") == self.id
                and ("result" in message or "error" in message)
            ):
                return message
        return None


def valid_id(value: Any) -> TypeGuard[str | int]:
    """Tell whether `value` is a JSON-RPC request id the proxy can match a response to."""
    return isinstance(value, str | int) and not isinstance(value, bool)


class ListSeen:
    """The last `tools/list` result recorded per run, server, transport and cursor, as a digest.

    At most `limit` keys are kept; the least recently used is forgotten first, which at worst
    records one more `tools/list` for a very old run.
    """

    def __init__(self, limit: int = MAX_LISTS) -> None:
        self._seen: OrderedDict[tuple[str, str, str, str | None], str] = OrderedDict()
        self._limit = limit
        self._lock = threading.Lock()

    def changed(self, key: tuple[str, str, str, str | None], result: Any) -> bool:
        """Tell whether `result` differs from the last one remembered under `key`."""
        with self._lock:
            return self._seen.get(key) != _digest(result)

    def remember(self, key: tuple[str, str, str, str | None], result: Any) -> None:
        """Remember `result` under `key`, once it has been recorded."""
        with self._lock:
            self._seen[key] = _digest(result)
            self._seen.move_to_end(key)
            while len(self._seen) > self._limit:
                self._seen.popitem(last=False)


def _context(
    request: Request, target: McpServer, call: McpCall, body: bytes, result: dict[str, Any]
) -> dict[str, Any]:
    """Build the run context for a call that may open the run (SPEC 10.6).

    The agent comes from the header, else from the request's MCP clientInfo; a `tools/list`
    answer also names the inventory the agent saw.
    """
    agent, source = header_agent(request), "header"
    if agent is None:
        try:
            agent, source = client_info_agent(parse_json(body)), "mcp_client_info"
        except ValueError:
            agent = None
    tools = None
    if call.method == "tools/list":
        digest = tool_inventory_digest(result)
        if digest is not None:
            tools = (target.name, digest)
    rule: Rule = request.app.state.policy
    return run_context(rule, agent, source if agent else None, tools=tools)


def _digest(result: Any) -> str:
    return hashlib.sha256(json.dumps(result, sort_keys=True).encode()).hexdigest()


async def _record(
    request: Request,
    target: McpServer,
    call: McpCall,
    label: str | None,
    body: bytes,
    status: int,
    answer: bytes | None,
    media_type: str,
    started: float,
    labels: list[str],
    policy: Decision | None = None,
) -> None:
    """Seal the call; `answer` is None for a call the policy rule kept from the server."""
    latency_ms = round((time.perf_counter() - started) * 1000, 1)
    blocked = answer is None
    message = None if answer is None else call.response_in(answer, media_type)
    result = mapping(message.get("result")) if message is not None else {}
    runs = request.app.state.runs
    seen: ListSeen = request.app.state.mcp_lists
    context = _context(request, target, call, body, result)
    list_key = None
    if call.method == "tools/list" and message is not None and "result" in message:
        run_id = await run_in_threadpool(runs.run_for, label, context=context)
        list_key = (run_id, target.name, "http", call.cursor)
        if not seen.changed(list_key, result):
            return
    failed = not blocked and (
        message is None or "error" in message or result.get("isError") is True
    )
    if blocked:
        outcome = "blocked"
    elif failed:
        outcome = "error"
    elif result.get("resultType") == "input_required":
        outcome = "pending"
    else:
        outcome = "success"
    mcp: dict[str, Any] = {
        "server": target.name,
        "transport": "http",
        "method": call.method,
        "request_id": call.id,
        "is_error": failed,
    }
    if call.method == "tools/call":
        mcp["tool"] = call.name
    if isinstance(result.get("resultType"), str):
        mcp["result_type"] = result["resultType"]
    if call.protocol_version:
        mcp["protocol_version"] = call.protocol_version
    if call.session:
        mcp["session"] = call.session
    proxy: dict[str, Any] = {
        "upstream": target.name,
        "dialect": "mcp",
        "operation": call.method,
        "status": status,
        "latency_ms": latency_ms,
    }
    if message is None and not blocked:
        proxy["truncated"] = True
    if list_key is not None:
        seen.remember(list_key, result)
    fields = label_fields(labels, {"sealedrun.mcp": mcp, "sealedrun.proxy": proxy})
    if policy is not None:
        fields["policy"] = policy.document()
    await run_in_threadpool(
        runs.record,
        label,
        "tool_call",
        context=context,
        target={
            "type": "tool",
            "name": call.name,
            "endpoint": target.url,
            "location": target.location,
            "provider": f"mcp:{target.name}",
        },
        request=body,
        response=answer,
        request_media_type=JSON,
        response_media_type=media_type.partition(";")[0].strip() or None,
        outcome=outcome,
        **fields,
    )


def same_origin(request: Request) -> bool:
    """Tell whether a browser, if any, sent this from the recorder's own origin.

    Browsers set `Sec-Fetch-Site`; older ones only `Origin`, whose host must be ours. Clients
    that are not browsers send neither.
    """
    site = request.headers.get("sec-fetch-site")
    if site is not None:
        return site in SAME_SITE
    origin = request.headers.get("origin")
    return origin is None or urlsplit(origin).netloc == request.headers.get("host")


def _build(request: Request, target: McpServer, body: bytes) -> httpx.Request:
    """Build the upstream request: allowed client headers, server credential, same body."""
    headers = {
        name: value
        for name, value in request.headers.items()
        if name in REQUEST_HEADERS or name.startswith(REQUEST_PREFIXES)
    }
    headers.update(target.request_headers(client_credentials(request)))
    # Replies are relayed as received, so ask for them uncompressed.
    headers["accept-encoding"] = "identity"
    timeout = request.app.state.settings.proxy_timeout_seconds
    # A GET stream may stay silent for as long as the server has nothing to send.
    read = None if request.method == "GET" else timeout
    http: httpx.AsyncClient = request.app.state.http
    return http.build_request(
        request.method,
        target.url,
        params=list(request.query_params.multi_items()),
        content=body or None,
        headers=headers,
        timeout=httpx.Timeout(timeout, read=read),
    )


async def _relay(reply: httpx.Response) -> AsyncIterator[bytes]:
    """Yield the upstream chunks as they come and close the upstream when the relay ends.

    Chunks are decoded, so a server that compresses despite `accept-encoding: identity` still
    reaches the client readable; `content-encoding` is never passed on.
    """
    try:
        async for chunk in reply.aiter_bytes():
            yield chunk
    except httpx.HTTPError:
        pass
    finally:
        await reply.aclose()


async def _relay_recorded(
    reply: httpx.Response, limit: int, finish: Callable[[bytes], Awaitable[None]]
) -> AsyncIterator[bytes]:
    """Relay a recorded SSE reply and record what was relayed, however the stream ends.

    The record is written under a shielded scope so that a client leaving still leaves the
    partial stream on the chain. Past `limit` bytes the stream is cut.
    """
    received: list[bytes] = []
    size = 0
    try:
        async for chunk in reply.aiter_bytes():
            if size + len(chunk) > limit:
                break
            received.append(chunk)
            size += len(chunk)
            yield chunk
    except httpx.HTTPError:
        pass
    finally:
        with anyio.CancelScope(shield=True):
            await reply.aclose()
            try:
                await finish(b"".join(received))
            except LiveRunError:
                log.exception("stream not recorded after %d bytes were delivered", size)


def error(
    status: int, message: str, *, code: int = PROXY_ERROR, request_id: str | int | None = None
) -> Response:
    """Return a proxy-generated error as a JSON-RPC error object, without an id unless given."""
    body = {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
    return Response(json.dumps(body).encode(), status_code=status, media_type=JSON)
