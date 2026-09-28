"""A2A proxy: agents behind `/a2a/<name>`, task delegations recorded into the same live runs.

The agents come from `a2a_agents` in the upstreams file; a client names one by path and never
supplies its URL. Access needs the recorder token, as for the LLM proxy. A2A 1.0 speaks
JSON-RPC over HTTP POST at one endpoint, with Server-Sent Events for streaming replies, and a
REST binding on sub-paths (`/messages`, `/tasks/{id}`, ...); both are forwarded to the agent's
URL plus the sub-path. The mandatory `A2A-Version` and `A2A-Extensions` headers pass through.

Discovery goes through the proxy too: `GET /a2a/<name>/.well-known/agent-card.json` fetches the
agent's card and rewrites its `url` and the URLs of its interfaces that point at the agent to
the proxy address, so an SDK client that discovers the agent here keeps talking through the
recorder. A signed card no longer matches its signature after the rewrite; README says so.

Delegations are recorded as `tool_call` records with the `sealedrun.a2a` extension (SPEC 10.4):
JSON-RPC `SendMessage`, `SendStreamingMessage` and `CancelTask`, and the REST operations
`message:send`, `message:stream` and `tasks/{id}:cancel`. The request body and the reply (the
JSON body, or the raw SSE stream) are the payloads; the outcome follows the last task state in
the reply. `GetTask`, `ListTasks`, `SubscribeToTask` and push-notification configs are forwarded
unrecorded.
"""

from __future__ import annotations

import json
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx
from fastapi import APIRouter, Depends, Request, Response
from starlette.concurrency import run_in_threadpool
from starlette.responses import StreamingResponse

from sealedrun_recorder.policy import Decision, Rule
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
from sealedrun_recorder.proxy.mcp import POLICY_ERROR, _relay_recorded, same_origin
from sealedrun_recorder.upstreams import A2aAgent, Upstreams

CARD_PATH = ".well-known/agent-card.json"
REQUEST_HEADERS = (
    "accept",
    "content-type",
    "a2a-version",
    "a2a-extensions",
    "last-event-id",
    "traceparent",
    "tracestate",
)
REPLY_HEADERS = (
    "content-type",
    "a2a-version",
    "a2a-extensions",
    "www-authenticate",
    "retry-after",
    "cache-control",
)
URL_KEYS = ("url",)
INTERFACE_KEYS = ("supportedInterfaces", "additionalInterfaces", "interfaces")
RECORDED_METHODS = frozenset({"SendMessage", "SendStreamingMessage", "CancelTask"})
GOVERNED_METHODS = frozenset({"SendMessage", "SendStreamingMessage"})
REST_OPERATIONS = {"message:send": "SendMessage", "message:stream": "SendStreamingMessage"}
SUCCESS_STATES = frozenset({"TASK_STATE_COMPLETED"})
ERROR_STATES = frozenset({"TASK_STATE_FAILED", "TASK_STATE_REJECTED", "TASK_STATE_CANCELED"})

router = APIRouter()


@router.api_route(
    "/a2a/{agent}",
    methods=["POST", "GET", "DELETE", "PUT", "PATCH"],
    dependencies=[Depends(require_proxy_token)],
)
@router.api_route(
    "/a2a/{agent}/{path:path}",
    methods=["POST", "GET", "DELETE", "PUT", "PATCH"],
    dependencies=[Depends(require_proxy_token)],
)
async def a2a(agent: str, request: Request, path: str = "") -> Response:
    """Forward one A2A request to the named agent; serve its rewritten agent card."""
    if not same_origin(request):
        return error(403, "cross-site request refused")
    label = request.headers.get(RUN_HEADER)
    if label is not None and not RUN_LABEL.match(label):
        return error(400, f"{RUN_HEADER} must match {RUN_LABEL.pattern}")
    try:
        labels = header_labels(request)
    except LabelsError as problem:
        return error(400, str(problem))
    upstreams: Upstreams = request.app.state.upstreams
    target = upstreams.a2a(agent)
    if target is None:
        return error(404, f"no A2A agent configured as {agent}")
    if not target.ready(client_credentials(request)):
        return error(503, f"A2A agent {target.name}: {target.key_env} is not set")
    if request.method == "GET" and path.strip("/") == CARD_PATH:
        return await agent_card(request, target)
    limit = request.app.state.settings.proxy_max_body_bytes
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        return error(413, "request body exceeds size limit")
    body = await request.body()
    if len(body) > limit:
        return error(413, "request body exceeds size limit")
    call = A2aCall.parse(request, path, body) if request.method == "POST" else None
    started = time.perf_counter()
    policy = None
    if call is not None and call.method in GOVERNED_METHODS:
        rule: Rule = request.app.state.policy
        policy = rule.evaluate(target.location, labels)
    if call is not None and policy is not None and policy.blocked:
        await _record(request, target, call, label, body, 403, None, "", started, labels, policy)
        return policy_refusal(call, policy)
    http: httpx.AsyncClient = request.app.state.http
    try:
        reply = await http.send(_build(request, target, path, body), stream=True)
    except httpx.HTTPError as failure:
        return error(502, f"A2A agent {target.name} unreachable: {type(failure).__name__}")
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
        answer = await reply.aread()
    except httpx.HTTPError:
        answer = b""
    finally:
        await reply.aclose()
    await finish(answer)
    return Response(answer, status_code=reply.status_code, headers=headers)


@dataclass(frozen=True)
class A2aCall:
    """A client request the proxy records: its method, binding and the ids it names."""

    method: str
    binding: str
    id: str | int | None
    task_id: str | None
    context_id: str | None
    message_id: str | None
    protocol_version: str | None

    @classmethod
    def parse(cls, request: Request, path: str, body: bytes) -> A2aCall | None:
        """Read a recorded request from a POST; None for anything forwarded unrecorded."""
        try:
            document = json.loads(body) if body else {}
        except ValueError:
            return None
        if not isinstance(document, dict):
            return None
        version = request.headers.get("a2a-version")
        operation = path.strip("/").rpartition("/")[2] if path else ""
        if not path:
            method = document.get("method")
            if method not in RECORDED_METHODS:
                return None
            request_id = document.get("id")
            if not isinstance(request_id, str | int) or isinstance(request_id, bool):
                return None
            params = mapping(document.get("params"))
            task_id = params.get("id") if method == "CancelTask" else None
            return cls(
                method=str(method),
                binding="jsonrpc",
                id=request_id,
                task_id=_string(task_id),
                context_id=None,
                message_id=_string(mapping(params.get("message")).get("messageId")),
                protocol_version=version,
            )
        method = REST_OPERATIONS.get(operation)
        task_id = None
        if method is None and operation.endswith(":cancel"):
            method, task_id = "CancelTask", operation[: -len(":cancel")]
        if method is None:
            return None
        return cls(
            method=method,
            binding="rest",
            id=None,
            task_id=task_id,
            context_id=None,
            message_id=_string(mapping(document.get("message")).get("messageId")),
            protocol_version=version,
        )

    def results_in(self, answer: bytes, media_type: str) -> list[dict[str, Any]] | None:
        """Return the reply objects for this call, in order; None when there is no reply.

        A JSON-RPC reply is one object with `result` or `error`; a REST reply is the result
        itself. An SSE stream holds one such object per event.
        """
        if media_type.startswith(SSE):
            messages = sse_data(answer)
        else:
            try:
                messages = [json.loads(answer)]
            except ValueError:
                return None
        found = [m for m in messages if isinstance(m, dict)]
        if self.binding == "jsonrpc":
            found = [m for m in found if m.get("id") == self.id and ("result" in m or "error" in m)]
        return found or None


def _string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def outcome_of(
    call: A2aCall, results: list[dict[str, Any]] | None
) -> tuple[str, str | None, dict[str, str]]:
    """Return the outcome, the last task state and the ids seen in the reply objects."""
    ids: dict[str, str] = {}
    if results is None:
        return "error", None, ids
    state: str | None = None
    failed = False
    direct_message = False
    for item in results:
        if call.binding == "jsonrpc" and "error" in item:
            failed = True
            continue
        payload = mapping(item.get("result")) if call.binding == "jsonrpc" else item
        if "error" in payload and call.binding == "rest":
            failed = True
            continue
        for key in ("task", "statusUpdate", "message", "artifactUpdate"):
            value = mapping(payload.get(key))
            if not value:
                continue
            _collect_ids(value, ids)
            if key == "message":
                direct_message = True
            status_state = mapping(value.get("status")).get("state")
            if key in ("task", "statusUpdate") and isinstance(status_state, str):
                state = status_state
        if "status" in payload and isinstance(mapping(payload.get("status")).get("state"), str):
            _collect_ids(payload, ids)
            state = mapping(payload["status"])["state"]
    if failed:
        return "error", state, ids
    if state in SUCCESS_STATES or (state is None and direct_message):
        return "success", state, ids
    if state in ERROR_STATES:
        return "error", state, ids
    if state is None:
        return "error", None, ids
    return "pending", state, ids


def _collect_ids(value: dict[str, Any], ids: dict[str, str]) -> None:
    for source, key in (("id", "task_id"), ("taskId", "task_id"), ("contextId", "context_id")):
        text = value.get(source)
        if isinstance(text, str) and text:
            ids[key] = text


async def _record(
    request: Request,
    target: A2aAgent,
    call: A2aCall,
    label: str | None,
    body: bytes,
    status: int,
    answer: bytes | None,
    media_type: str,
    started: float,
    labels: list[str],
    policy: Decision | None = None,
) -> None:
    """Seal the delegation; `answer` is None for one the policy rule kept from the agent."""
    latency_ms = round((time.perf_counter() - started) * 1000, 1)
    blocked = answer is None
    results = None if answer is None else call.results_in(answer, media_type)
    outcome, state, ids = outcome_of(call, results)
    if blocked:
        outcome = "blocked"
    a2a: dict[str, Any] = {
        "agent": target.name,
        "method": call.method,
        "binding": call.binding,
        "is_error": outcome == "error",
    }
    task_id = call.task_id or ids.get("task_id")
    if task_id:
        a2a["task_id"] = task_id
    if ids.get("context_id"):
        a2a["context_id"] = ids["context_id"]
    if call.message_id:
        a2a["message_id"] = call.message_id
    if state:
        a2a["state"] = state
    if call.protocol_version:
        a2a["protocol_version"] = call.protocol_version
    proxy: dict[str, Any] = {
        "upstream": target.name,
        "dialect": "a2a",
        "operation": call.method,
        "status": status,
        "latency_ms": latency_ms,
    }
    if results is None and not blocked:
        proxy["truncated"] = True
    fields = label_fields(labels, {"sealedrun.a2a": a2a, "sealedrun.proxy": proxy})
    if policy is not None:
        fields["policy"] = policy.document()
    runs = request.app.state.runs
    await run_in_threadpool(
        runs.record,
        label,
        "tool_call",
        target={
            "type": "tool",
            "name": f"{target.name}/{'cancel' if call.method == 'CancelTask' else 'message'}",
            "endpoint": target.url,
            "location": target.location,
            "provider": f"a2a:{target.name}",
        },
        request=body,
        response=answer,
        request_media_type=JSON,
        response_media_type=media_type.partition(";")[0].strip() or None,
        outcome=outcome,
        **fields,
    )


def policy_refusal(call: A2aCall, policy: Decision) -> Response:
    """Refuse a delegation in the shape of the binding it came in.

    JSON-RPC gets an error object with the request's id; the REST binding gets the
    `google.rpc.Status` body A2A uses for HTTP errors.
    """
    message = f"blocked by policy {policy.rule_id}: {policy.reason}"
    if call.binding == "jsonrpc":
        return error(403, message, code=POLICY_ERROR, request_id=call.id)
    body = {"code": 7, "status": "PERMISSION_DENIED", "message": message}
    return Response(json.dumps(body).encode(), status_code=403, media_type=JSON)


async def agent_card(request: Request, target: A2aAgent) -> Response:
    """Fetch the agent's card and point its URLs at the proxy."""
    http: httpx.AsyncClient = request.app.state.http
    headers = target.request_headers(client_credentials(request))
    headers["accept"] = JSON
    timeout = request.app.state.settings.proxy_timeout_seconds
    try:
        reply = await http.get(card_url(target.url), headers=headers, timeout=timeout)
    except httpx.HTTPError as failure:
        return error(502, f"A2A agent {target.name} unreachable: {type(failure).__name__}")
    if not reply.is_success:
        return Response(reply.content, status_code=reply.status_code, media_type=JSON)
    try:
        card = reply.json()
    except ValueError:
        return error(502, f"A2A agent {target.name} sent a card that is not JSON")
    if not isinstance(card, dict):
        return error(502, f"A2A agent {target.name} sent a card that is not an object")
    return Response(json.dumps(rewrite_card(card, target.url, proxy_base(request, target))))


def card_url(agent_url: str) -> str:
    """Return the well-known card URL of the agent's origin."""
    parts = urlsplit(agent_url)
    return urlunsplit((parts.scheme, parts.netloc, "/" + CARD_PATH, "", ""))


def proxy_base(request: Request, target: A2aAgent) -> str:
    """Return the proxy URL the card should name for this agent."""
    host = request.headers.get("host", request.url.netloc)
    return f"{request.url.scheme}://{host}/a2a/{target.name}"


def rewrite_card(card: dict[str, Any], agent_url: str, base: str) -> dict[str, Any]:
    """Return the card with every URL under the agent's URL replaced by the proxy's."""
    out = dict(card)
    for key in URL_KEYS:
        if isinstance(out.get(key), str):
            out[key] = _rewrite_url(out[key], agent_url, base)
    for key in INTERFACE_KEYS:
        interfaces = out.get(key)
        if isinstance(interfaces, list):
            out[key] = [_rewrite_interface(i, agent_url, base) for i in interfaces]
    return out


def _rewrite_interface(interface: Any, agent_url: str, base: str) -> Any:
    if not isinstance(interface, dict) or not isinstance(interface.get("url"), str):
        return interface
    return {**interface, "url": _rewrite_url(interface["url"], agent_url, base)}


def _rewrite_url(url: str, agent_url: str, base: str) -> str:
    root = agent_url.rstrip("/")
    if url.rstrip("/") == root:
        return base
    if url.startswith(root + "/"):
        return base + url[len(root) :]
    return url


def _build(request: Request, target: A2aAgent, path: str, body: bytes) -> httpx.Request:
    headers = {n: v for n, v in request.headers.items() if n in REQUEST_HEADERS}
    headers.update(target.request_headers(client_credentials(request)))
    headers["accept-encoding"] = "identity"
    timeout = request.app.state.settings.proxy_timeout_seconds
    read = None if request.method == "GET" else timeout
    http: httpx.AsyncClient = request.app.state.http
    url = target.url.rstrip("/") + ("/" + path.lstrip("/") if path else "")
    if not path and target.url.endswith("/"):
        url = target.url
    return http.build_request(
        request.method,
        url,
        params=list(request.query_params.multi_items()),
        content=body or None,
        headers=headers,
        timeout=httpx.Timeout(timeout, read=read),
    )


async def _relay(reply: httpx.Response) -> AsyncIterator[bytes]:
    try:
        async for chunk in reply.aiter_bytes():
            yield chunk
    except httpx.HTTPError:
        pass
    finally:
        await reply.aclose()


def error(
    status: int, message: str, *, code: int = -32000, request_id: str | int | None = None
) -> Response:
    """Return a proxy-generated error as a JSON-RPC error object, without an id unless given."""
    body = {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
    return Response(json.dumps(body).encode(), status_code=status, media_type=JSON)
