"""OTLP/HTTP trace receiver: `POST /otlp/v1/traces`, GenAI spans recorded into live runs.

The body is an `ExportTraceServiceRequest` in binary protobuf (`application/x-protobuf`, the
OpenTelemetry SDK default) or proto-JSON (`application/json`), optionally gzip-encoded, as OTLP
1.11 specifies. The reply is an empty `ExportTraceServiceResponse` in the request's encoding.
The recorder token is required as for the proxies: an exporter sets it in
`OTEL_EXPORTER_OTLP_HEADERS`.

GenAI spans (SPEC 11) become records by `gen_ai.operation.name`: tool executions are
`tool_call`, model calls `llm_call`, memory operations `memory_read` / `memory_write`; every
other span is dropped. The spans of one trace share one run: the `X-SealedRun-Run` header,
else `otel:<trace id>`. `gen_ai.conversation.id` is kept on the record but does not choose the
run: batch exporters deliver child spans before the agent span that carries it, so grouping by
it would split one trace over two runs. A span whose record would not verify is
counted in the reply's `partial_success` and skipped; a span id already recorded in its run is
skipped silently, so a re-sent batch does not duplicate records.
"""

from __future__ import annotations

import base64
import gzip
import json
import re
import threading
import zlib
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from google.protobuf.json_format import MessageToJson, Parse, ParseError
from google.protobuf.message import DecodeError
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
    ExportTraceServiceResponse,
)
from opentelemetry.proto.trace.v1.trace_pb2 import Span
from sealedrun.timeutil import format_timestamp
from starlette.concurrency import run_in_threadpool

from sealedrun_recorder.live import InvalidRecordError
from sealedrun_recorder.proxy.core import RUN_HEADER, RUN_LABEL, require_proxy_token

PROTOBUF = "application/x-protobuf"
JSON = "application/json"
OPERATION = "gen_ai.operation.name"
KINDS = {
    "execute_tool": "tool_call",
    "chat": "llm_call",
    "text_completion": "llm_call",
    "generate_content": "llm_call",
    "embeddings": "llm_call",
    "fetch_response": "llm_call",
    "retrieval": "memory_read",
    "search_memory": "memory_read",
    "create_memory": "memory_write",
    "update_memory": "memory_write",
    "upsert_memory": "memory_write",
    "delete_memory": "memory_write",
}
TARGET_TYPES = {
    "tool_call": "tool",
    "llm_call": "model",
    "memory_read": "memory",
    "memory_write": "memory",
}
STATUS_ERROR = 2
CLOUD_PROVIDERS = frozenset(
    {
        "anthropic",
        "aws.bedrock",
        "azure.ai.inference",
        "azure.ai.openai",
        "cohere",
        "deepseek",
        "gcp.gemini",
        "gcp.gen_ai",
        "gcp.vertex_ai",
        "groq",
        "ibm.watsonx.ai",
        "mistral_ai",
        "moonshot_ai",
        "openai",
        "perplexity",
        "x_ai",
    }
)
LOCAL_PROVIDERS = frozenset({"ollama", "llama.cpp", "llamacpp", "vllm", "lmstudio", "localai"})
SEEN_SPANS = 10_000

router = APIRouter(prefix="/otlp", dependencies=[Depends(require_proxy_token)])


@dataclass(frozen=True)
class OtlpSpan:
    """One span with its resource and scope attributes flattened for mapping."""

    span: Span
    resource: dict[str, Any]
    scope: dict[str, Any]

    @property
    def attributes(self) -> dict[str, Any]:
        """The span's own attributes as plain Python values."""
        return attributes_of(self.span.attributes)


@router.post("/v1/traces")
async def traces(request: Request) -> Response:
    """Accept an OTLP trace export and record its GenAI spans.

    Responds 415 for an unknown content type, 400 for a body that does not decode, 413 for an
    oversize body; otherwise 200 with an empty `ExportTraceServiceResponse`.
    """
    media_type = request.headers.get("content-type", "").partition(";")[0].strip().lower()
    if media_type not in (PROTOBUF, JSON):
        raise HTTPException(415, f"content type must be {PROTOBUF} or {JSON}")
    limit = request.app.state.settings.proxy_max_body_bytes
    body = await request.body()
    if len(body) > limit:
        raise HTTPException(413, "export exceeds size limit")
    try:
        body = decompress(body, request.headers.get("content-encoding", ""), limit)
        export = decode(body, media_type)
    except ValueError as error:
        raise HTTPException(400, str(error)) from error
    label = request.headers.get(RUN_HEADER)
    if label is not None and not RUN_LABEL.match(label):
        raise HTTPException(400, f"{RUN_HEADER} must match {RUN_LABEL.pattern}")
    rejected, message = await run_in_threadpool(record_spans, request.app, spans_of(export), label)
    reply = ExportTraceServiceResponse()
    if rejected:
        reply.partial_success.rejected_spans = rejected
        reply.partial_success.error_message = message
    if media_type == JSON:
        return Response(MessageToJson(reply), media_type=JSON)
    return Response(reply.SerializeToString(), media_type=PROTOBUF)


def decompress(body: bytes, encoding: str, limit: int) -> bytes:
    """Undo a `Content-Encoding` of gzip or deflate; raises ValueError when it does not fit."""
    encoding = encoding.strip().lower()
    if not encoding or encoding == "identity":
        return body
    if encoding not in ("gzip", "deflate"):
        raise ValueError(f"unsupported content encoding {encoding}")
    try:
        decoder = zlib.decompressobj(16 + zlib.MAX_WBITS if encoding == "gzip" else zlib.MAX_WBITS)
        out = decoder.decompress(body, limit + 1)
    except (zlib.error, gzip.BadGzipFile) as error:
        raise ValueError(f"body is not valid {encoding}") from error
    if len(out) > limit or decoder.unconsumed_tail:
        raise ValueError("export exceeds size limit")
    return out


def decode(body: bytes, media_type: str) -> ExportTraceServiceRequest:
    """Parse the export in the given encoding; raises ValueError when it does not decode.

    OTLP/JSON writes trace, span and parent ids as hex strings where proto-JSON expects
    base64, so those fields are converted before the standard parser runs.
    """
    export = ExportTraceServiceRequest()
    try:
        if media_type == JSON:
            document = json.loads(body.decode())
            Parse(json.dumps(_ids_to_base64(document)), export, ignore_unknown_fields=True)
        else:
            export.ParseFromString(body)
    except (DecodeError, ParseError, UnicodeDecodeError, ValueError, TypeError) as error:
        raise ValueError(f"body is not a valid ExportTraceServiceRequest: {error}") from error
    return export


ID_FIELDS = frozenset(
    {"traceId", "spanId", "parentSpanId", "trace_id", "span_id", "parent_span_id"}
)


def _ids_to_base64(node: Any) -> Any:
    if isinstance(node, list):
        return [_ids_to_base64(item) for item in node]
    if not isinstance(node, dict):
        return node
    out = {}
    for key, value in node.items():
        if key in ID_FIELDS and isinstance(value, str) and _is_hex_id(value):
            out[key] = base64.b64encode(bytes.fromhex(value)).decode()
        else:
            out[key] = _ids_to_base64(value)
    return out


def _is_hex_id(value: str) -> bool:
    return ID_PATTERN.match(value) is not None


def spans_of(export: ExportTraceServiceRequest) -> list[OtlpSpan]:
    """Flatten an export into spans with their resource and scope attributes."""
    spans: list[OtlpSpan] = []
    for resource_spans in export.resource_spans:
        resource = attributes_of(resource_spans.resource.attributes)
        for scope_spans in resource_spans.scope_spans:
            scope = attributes_of(scope_spans.scope.attributes)
            scope["name"] = scope_spans.scope.name
            scope["version"] = scope_spans.scope.version
            spans.extend(OtlpSpan(span, resource, scope) for span in scope_spans.spans)
    return spans


def attributes_of(entries: Any) -> dict[str, Any]:
    """Turn a repeated `KeyValue` into a dict of plain values."""
    return {entry.key: value_of(entry.value) for entry in entries}


def value_of(value: Any) -> Any:
    """Convert an `AnyValue` to str, bool, int, float, bytes, list or dict."""
    kind = value.WhichOneof("value")
    if kind is None:
        return None
    if kind == "array_value":
        return [value_of(v) for v in value.array_value.values]
    if kind == "kvlist_value":
        return attributes_of(value.kvlist_value.values)
    return getattr(value, kind)


class SpansSeen:
    """Span ids already recorded, per run, bounded so a long-lived recorder does not grow."""

    def __init__(self, limit: int = SEEN_SPANS) -> None:
        self._seen: OrderedDict[tuple[str, str], None] = OrderedDict()
        self._limit = limit
        self._lock = threading.Lock()

    def first_time(self, run_id: str, span_id: str) -> bool:
        """Remember the span; tell whether it was new for that run."""
        key = (run_id, span_id)
        with self._lock:
            if key in self._seen:
                return False
            self._seen[key] = None
            while len(self._seen) > self._limit:
                self._seen.popitem(last=False)
            return True


def record_spans(app: Any, spans: list[OtlpSpan], label: str | None) -> tuple[int, str]:
    """Record the GenAI spans in start order; return how many were rejected and why."""
    runs = app.state.runs
    seen: SpansSeen = app.state.otel_seen
    conversations = conversations_of(spans)
    rejected, message = 0, ""
    for item in sorted(spans, key=lambda s: s.span.start_time_unix_nano):
        mapped = map_span(item)
        if mapped is None:
            continue
        kind, fields = mapped
        conversation = conversations.get(item.span.span_id)
        if conversation:
            fields["extensions"]["sealedrun.otel"]["conversation"] = conversation
        run_label = label or f"otel:{item.span.trace_id.hex()}"
        run_id = runs.run_for(run_label)
        if not seen.first_time(run_id, item.span.span_id.hex()):
            continue
        try:
            runs.record(run_label, kind, check=True, **fields)
        except InvalidRecordError as error:
            rejected += 1
            message = message or f"span {item.span.name}: {error}"
    return rejected, message


def conversations_of(spans: list[OtlpSpan]) -> dict[bytes, str]:
    """Map every span id to the conversation id it or its nearest ancestor in the export carries.

    Frameworks put `gen_ai.conversation.id` on the agent span and not on the model and tool
    spans below it, so the id is inherited down the parent chain within one export.
    """
    own: dict[bytes, str] = {}
    parents: dict[bytes, bytes] = {}
    for item in spans:
        conversation = item.attributes.get("gen_ai.conversation.id")
        if isinstance(conversation, str) and conversation:
            own[item.span.span_id] = conversation[:256]
        if item.span.parent_span_id:
            parents[item.span.span_id] = item.span.parent_span_id
    resolved: dict[bytes, str] = {}
    for item in spans:
        span_id, hops = item.span.span_id, 0
        while span_id not in own and span_id in parents and hops < len(parents):
            span_id, hops = parents[span_id], hops + 1
        if span_id in own:
            resolved[item.span.span_id] = own[span_id]
    return resolved


def map_span(item: OtlpSpan) -> tuple[str, dict[str, Any]] | None:
    """Turn a GenAI span into `(kind, LiveRuns.append fields)`; None for spans not recorded."""
    span, attributes = item.span, item.attributes
    operation = attributes.get(OPERATION)
    if not isinstance(operation, str):
        operation = span.name.split(" ", 1)[0]
    kind = KINDS.get(operation)
    if kind is None:
        return None
    provider = attributes.get("gen_ai.provider.name")
    provider = provider if isinstance(provider, str) and provider else None
    name = _name(kind, operation, span.name, attributes)
    target: dict[str, Any] = {
        "type": TARGET_TYPES[kind],
        "name": name,
        "location": _location(kind, provider),
    }
    if provider:
        target["provider"] = provider
    server = attributes.get("server.address")
    if isinstance(server, str) and server:
        target["endpoint"] = server
    failed = span.status.code == STATUS_ERROR or "error.type" in attributes
    extensions: dict[str, Any] = {"sealedrun.otel": _otel(item, operation)}
    if kind == "llm_call":
        extensions["sealedrun.llm"] = _llm(name, provider, attributes)
    request, response = _payloads(kind, attributes)
    fields: dict[str, Any] = {
        "target": target,
        "outcome": "error" if failed else "success",
        "extensions": extensions,
    }
    if request is not None:
        fields["request"] = request
        fields["request_media_type"] = JSON
    if response is not None:
        fields["response"] = response
        fields["response_media_type"] = JSON
    return kind, fields


def _name(kind: str, operation: str, span_name: str, attributes: dict[str, Any]) -> str:
    if kind == "tool_call":
        candidate = attributes.get("gen_ai.tool.name")
    elif kind == "llm_call":
        candidate = _model_of(attributes)
    else:
        candidate = attributes.get("gen_ai.data_source.id")
    if isinstance(candidate, str) and candidate:
        return candidate
    remainder = span_name[len(operation) :].strip() if span_name.startswith(operation) else ""
    return remainder or span_name or operation


def _model_of(attributes: dict[str, Any]) -> str | None:
    """Return the model name, skipping the literal `unknown` some instrumentations write.

    LangChain's instrumentation keeps the real name in its `ls_model_name` metadata, which
    lands on the span as an association property, so that key is the last resort.
    """
    candidates = [attributes.get("gen_ai.request.model"), attributes.get("gen_ai.response.model")]
    candidates += [v for k, v in attributes.items() if k.endswith("ls_model_name")]
    for value in candidates:
        if isinstance(value, str) and value and value != "unknown":
            return value
    return None


def _location(kind: str, provider: str | None) -> str:
    if kind != "llm_call":
        return "local"
    if provider is None:
        return "unknown"
    if provider in LOCAL_PROVIDERS:
        return "local"
    return "cloud" if provider in CLOUD_PROVIDERS else "unknown"


def _otel(item: OtlpSpan, operation: str) -> dict[str, Any]:
    span = item.span
    otel: dict[str, Any] = {
        "trace_id": span.trace_id.hex(),
        "span_id": span.span_id.hex(),
        "operation": operation,
        "span_name": span.name,
    }
    if span.start_time_unix_nano:
        started = datetime.fromtimestamp(span.start_time_unix_nano / 1e9, tz=UTC)
        otel["started_at"] = format_timestamp(started)
        if span.end_time_unix_nano >= span.start_time_unix_nano:
            otel["duration_ms"] = round(
                (span.end_time_unix_nano - span.start_time_unix_nano) / 1e6, 3
            )
    if item.scope.get("name"):
        otel["scope"] = str(item.scope["name"])
    agent = item.attributes.get("gen_ai.agent.name")
    if isinstance(agent, str) and agent:
        otel["agent"] = agent
    return otel


def _llm(model: str, provider: str | None, attributes: dict[str, Any]) -> dict[str, Any]:
    llm: dict[str, Any] = {"model": model}
    if provider:
        llm["provider"] = provider
    for key, field in (
        ("gen_ai.usage.input_tokens", "input_tokens"),
        ("gen_ai.usage.output_tokens", "output_tokens"),
    ):
        value = attributes.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            llm[field] = value
    reasons = attributes.get("gen_ai.response.finish_reasons")
    if isinstance(reasons, list) and reasons and all(isinstance(r, str) for r in reasons):
        llm["finish_reason"] = reasons[0]
    temperature = attributes.get("gen_ai.request.temperature")
    if isinstance(temperature, int | float) and not isinstance(temperature, bool):
        llm["temperature"] = temperature
    return llm


PAYLOAD_KEYS = {
    "tool_call": ("gen_ai.tool.call.arguments", "gen_ai.tool.call.result"),
    "llm_call": ("gen_ai.input.messages", "gen_ai.output.messages"),
    "memory_read": ("gen_ai.input.messages", "gen_ai.output.messages"),
    "memory_write": ("gen_ai.input.messages", "gen_ai.output.messages"),
}


def _payloads(kind: str, attributes: dict[str, Any]) -> tuple[bytes | None, bytes | None]:
    request_key, response_key = PAYLOAD_KEYS[kind]
    return _payload(attributes.get(request_key)), _payload(attributes.get(response_key))


def _payload(value: Any) -> bytes | None:
    """Return an attribute as JSON bytes: strings that already are JSON stay as they are."""
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        try:
            json.loads(value)
            return value.encode()
        except ValueError:
            return json.dumps(value).encode()
    return json.dumps(value, sort_keys=True).encode()


ID_PATTERN = re.compile(r"^[0-9a-fA-F]{16}$|^[0-9a-fA-F]{32}$")
