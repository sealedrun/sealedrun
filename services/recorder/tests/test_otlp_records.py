import json
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceResponse
from sealedrun import verify_run
from sealedrun.schema import validate_extensions
from sealedrun_recorder.db import RecordRow, RunRow

CONFIG = "upstreams: []\n"
PROTOBUF = "application/x-protobuf"
TRACE_A = "0af7651916cd43dd8448eb211c80319c"
TRACE_B = "1bf7651916cd43dd8448eb211c80319d"


@pytest.fixture
def client(make_proxy: Callable[..., TestClient]) -> Iterator[TestClient]:
    with make_proxy(CONFIG) as client:
        yield client


@pytest.fixture
def auth(secrets: dict[str, str]) -> dict[str, str]:
    return {"X-SealedRun-Token": secrets["token"], "Content-Type": PROTOBUF}


@pytest.fixture(autouse=True)
def _builders(otlp_export: Callable[..., Any]) -> None:
    global export_with
    export_with = otlp_export


def _send(client: TestClient, spans: list[dict[str, Any]], **headers: str) -> Any:
    body = export_with(spans).SerializeToString()
    return client.post("/otlp/v1/traces", content=body, headers=headers)


def _runs(client: TestClient) -> dict[str, list[dict[str, Any]]]:
    out = {}
    with client.app.state.live._sessions() as session:  # type: ignore[attr-defined]
        for run in session.query(RunRow).all():
            rows = session.query(RecordRow).filter_by(run_id=run.run_id).order_by(RecordRow.seq)
            out[run.run_label or run.run_id] = [r.document for r in rows]
    return out


def _payload(client: TestClient, record: dict[str, Any], side: str, api: dict[str, str]) -> bytes:
    reply = client.get(f"/api/records/{record['record_id']}/payload/{side}", headers=api)
    assert reply.status_code == 200, reply.text
    return reply.content


def test_execute_tool_span_becomes_a_tool_call(
    client: TestClient, auth: dict[str, str], secrets: dict[str, str]
) -> None:
    span = {
        "name": "execute_tool add",
        "attributes": {
            "gen_ai.operation.name": "execute_tool",
            "gen_ai.tool.name": "add",
            "gen_ai.tool.call.id": "call_1",
            "gen_ai.tool.call.arguments": '{"a": 1, "b": 2}',
            "gen_ai.tool.call.result": {"sum": 3},
            "gen_ai.agent.name": "calc-agent",
            "gen_ai.conversation.id": "conv-1",
        },
        "start": 1_700_000_000_000_000_000,
        "end": 1_700_000_000_004_500_000,
    }
    reply = _send(client, [span], **auth)
    assert reply.status_code == 200, reply.text
    runs = _runs(client)
    [(label, records)] = runs.items()
    assert label == f"otel:{TRACE_A}"
    [_, record] = records
    assert record["kind"] == "tool_call"
    assert record["target"] == {"type": "tool", "name": "add", "location": "local"}
    assert record["outcome"] == "success"
    assert record["extensions"]["sealedrun.otel"] == {
        "trace_id": TRACE_A,
        "span_id": "0000000000000001",
        "operation": "execute_tool",
        "span_name": "execute_tool add",
        "started_at": "2023-11-14T22:13:20.000Z",
        "duration_ms": 4.5,
        "scope": "test-scope",
        "agent": "calc-agent",
        "conversation": "conv-1",
    }
    assert validate_extensions(record["extensions"]) == []
    api = {"Authorization": f"Bearer {secrets['token']}"}
    assert json.loads(_payload(client, record, "request", api)) == {"a": 1, "b": 2}
    assert json.loads(_payload(client, record, "response", api)) == {"sum": 3}
    delegation = client.get("/api/identity", headers=api).json()["delegation"]
    verify_run(records, {delegation["delegation_id"]: delegation})


def test_model_span_becomes_an_llm_call(client: TestClient, auth: dict[str, str]) -> None:
    span = {
        "name": "chat gpt-4.1",
        "attributes": {
            "gen_ai.operation.name": "chat",
            "gen_ai.request.model": "gpt-4.1",
            "gen_ai.response.model": "gpt-4.1-2026",
            "gen_ai.provider.name": "openai",
            "gen_ai.usage.input_tokens": 12,
            "gen_ai.usage.output_tokens": 3,
            "gen_ai.response.finish_reasons": ["stop"],
            "gen_ai.request.temperature": 0.2,
            "server.address": "api.openai.com",
            "gen_ai.input.messages": [
                {"role": "user", "parts": [{"type": "text", "content": "hi"}]}
            ],
        },
    }
    assert _send(client, [span], **auth).status_code == 200
    [(label, records)] = _runs(client).items()
    assert label == f"otel:{TRACE_A}"
    record = records[1]
    assert record["kind"] == "llm_call"
    assert record["target"] == {
        "type": "model",
        "name": "gpt-4.1",
        "location": "cloud",
        "provider": "openai",
        "endpoint": "api.openai.com",
    }
    assert record["extensions"]["sealedrun.llm"] == {
        "model": "gpt-4.1",
        "provider": "openai",
        "input_tokens": 12,
        "output_tokens": 3,
        "finish_reason": "stop",
        "temperature": 0.2,
    }
    assert record["payload"]["request_media_type"] == "application/json"
    assert "response_hash" not in record["payload"]


@pytest.mark.parametrize(
    ("operation", "kind", "target_type"),
    [
        ("text_completion", "llm_call", "model"),
        ("embeddings", "llm_call", "model"),
        ("retrieval", "memory_read", "memory"),
        ("upsert_memory", "memory_write", "memory"),
    ],
)
def test_other_operations_map_to_their_kinds(
    client: TestClient, auth: dict[str, str], operation: str, kind: str, target_type: str
) -> None:
    span = {"name": f"{operation} store-1", "attributes": {"gen_ai.operation.name": operation}}
    assert _send(client, [span], **auth).status_code == 200
    [(_, records)] = _runs(client).items()
    assert records[1]["kind"] == kind
    assert records[1]["target"]["type"] == target_type
    assert records[1]["target"]["name"] == "store-1"
    if kind == "llm_call":
        assert records[1]["target"]["location"] == "unknown"
        assert records[1]["extensions"]["sealedrun.llm"] == {"model": "store-1"}


def test_operation_is_read_from_the_span_name_when_the_attribute_is_missing(
    client: TestClient, auth: dict[str, str]
) -> None:
    spans = [{"name": "execute_tool search"}, {"name": "invoke_agent helper"}, {"name": "GET /x"}]
    assert _send(client, spans, **auth).status_code == 200
    [(_, records)] = _runs(client).items()
    assert [r["kind"] for r in records] == ["run_start", "tool_call"]
    assert records[1]["target"]["name"] == "search"


def test_non_genai_and_agent_spans_are_dropped(client: TestClient, auth: dict[str, str]) -> None:
    spans = [
        {"name": "invoke_agent a", "attributes": {"gen_ai.operation.name": "invoke_agent"}},
        {"name": "create_agent a", "attributes": {"gen_ai.operation.name": "create_agent"}},
        {"name": "HTTP GET", "attributes": {"http.request.method": "GET"}},
    ]
    assert _send(client, spans, **auth).status_code == 200
    assert _runs(client) == {}


def test_runs_are_grouped_by_header_or_trace(client: TestClient, auth: dict[str, str]) -> None:
    tool = {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "t"}
    spans = [
        {
            "name": "a",
            "attributes": {**tool, "gen_ai.conversation.id": "conv-x"},
            "trace_id": TRACE_A,
        },
        {"name": "b", "attributes": tool, "trace_id": TRACE_A, "span_id": "00000000000000aa"},
        {"name": "c", "attributes": tool, "trace_id": TRACE_B, "span_id": "00000000000000bb"},
        {
            "name": "d",
            "attributes": {**tool, "gen_ai.conversation.id": "bad label!"},
            "trace_id": TRACE_B,
            "span_id": "00000000000000cc",
        },
    ]
    assert _send(client, spans, **auth).status_code == 200
    runs = _runs(client)
    assert {k: len(v) - 1 for k, v in runs.items()} == {f"otel:{TRACE_A}": 2, f"otel:{TRACE_B}": 2}
    by_name = {r["target"]["name"]: r for run in runs.values() for r in run[1:]}
    assert by_name["t"]["extensions"]["sealedrun.otel"].get("conversation") in (
        "conv-x",
        "bad label!",
        None,
    )
    assert _send(client, spans[:2], **auth, **{"X-SealedRun-Run": "forced"}).status_code == 200
    assert len(_runs(client)["forced"]) == 3
    bad = _send(client, spans[:1], **auth, **{"X-SealedRun-Run": "a b"})
    assert bad.status_code == 400


def test_error_status_and_error_type_give_outcome_error(
    client: TestClient, auth: dict[str, str]
) -> None:
    tool = {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "t"}
    spans = [
        {"name": "a", "attributes": tool, "error": "boom"},
        {"name": "b", "attributes": {**tool, "error.type": "TimeoutError"}},
        {"name": "c", "attributes": tool},
    ]
    assert _send(client, spans, **auth).status_code == 200
    [(_, records)] = _runs(client).items()
    assert [r["outcome"] for r in records[1:]] == ["error", "error", "success"]


def test_spans_are_recorded_in_start_order_and_once(
    client: TestClient, auth: dict[str, str]
) -> None:
    tool = {"gen_ai.operation.name": "execute_tool"}
    spans = [
        {
            "name": "late",
            "attributes": {**tool, "gen_ai.tool.name": "late"},
            "start": 3_000_000_000,
        },
        {
            "name": "early",
            "attributes": {**tool, "gen_ai.tool.name": "early"},
            "start": 1_000_000_000,
        },
    ]
    assert _send(client, spans, **auth).status_code == 200
    assert _send(client, spans, **auth).status_code == 200
    [(_, records)] = _runs(client).items()
    assert [r["target"]["name"] for r in records[1:]] == ["early", "late"]


def test_a_span_that_would_not_verify_is_reported_as_partial_success(
    client: TestClient, auth: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    from sealedrun_recorder import otlp

    real = otlp.map_span

    def broken(item: otlp.OtlpSpan) -> Any:
        mapped = real(item)
        if mapped is not None and item.span.name == "bad":
            mapped[1]["target"]["name"] = ""
        return mapped

    monkeypatch.setattr(otlp, "map_span", broken)
    tool = {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "t"}
    spans = [
        {"name": "ok", "attributes": tool},
        {"name": "bad", "attributes": tool, "span_id": "00000000000000ee"},
    ]
    reply = _send(client, spans, **auth)
    assert reply.status_code == 200
    answer = ExportTraceServiceResponse()
    answer.ParseFromString(reply.content)
    assert answer.partial_success.rejected_spans == 1
    assert "would not verify" in answer.partial_success.error_message
    [(_, records)] = _runs(client).items()
    assert [r["target"]["name"] for r in records[1:]] == ["t"]


@pytest.mark.parametrize(
    ("provider", "location"),
    [("openai", "cloud"), ("ollama", "local"), ("langchain", "unknown"), (None, "unknown")],
)
def test_model_location_follows_the_provider(
    client: TestClient, auth: dict[str, str], provider: str | None, location: str
) -> None:
    attributes: dict[str, Any] = {"gen_ai.operation.name": "chat", "gen_ai.request.model": "m"}
    if provider:
        attributes["gen_ai.provider.name"] = provider
    assert _send(client, [{"name": "chat m", "attributes": attributes}], **auth).status_code == 200
    [(_, records)] = _runs(client).items()
    assert records[1]["target"]["location"] == location


def test_unknown_model_name_falls_back_to_langchain_metadata(
    client: TestClient, auth: dict[str, str]
) -> None:
    span = {
        "name": "chat unknown",
        "attributes": {
            "gen_ai.operation.name": "chat",
            "gen_ai.request.model": "unknown",
            "gen_ai.response.model": "unknown",
            "traceloop.association.properties.ls_model_name": "qwen3:8b",
        },
    }
    assert _send(client, [span], **auth).status_code == 200
    [(_, records)] = _runs(client).items()
    assert records[1]["target"]["name"] == "qwen3:8b"
    assert records[1]["extensions"]["sealedrun.llm"]["model"] == "qwen3:8b"


def test_conversation_id_is_inherited_from_parent_spans(
    client: TestClient, auth: dict[str, str], otlp_export: Callable[..., Any]
) -> None:
    export = otlp_export(
        [
            {
                "name": "invoke_agent a",
                "span_id": "00000000000000a1",
                "attributes": {
                    "gen_ai.operation.name": "invoke_agent",
                    "gen_ai.conversation.id": "thread-7",
                },
            },
            {"name": "execute_task node", "span_id": "00000000000000a2"},
            {
                "name": "execute_tool add",
                "span_id": "00000000000000a3",
                "attributes": {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "add"},
            },
            {
                "name": "chat m",
                "span_id": "00000000000000a4",
                "trace_id": TRACE_B,
                "attributes": {"gen_ai.operation.name": "chat", "gen_ai.request.model": "m"},
            },
        ]
    )
    spans = export.resource_spans[0].scope_spans[0].spans
    spans[1].parent_span_id = spans[0].span_id
    spans[2].parent_span_id = spans[1].span_id
    reply = client.post("/otlp/v1/traces", content=export.SerializeToString(), headers=auth)
    assert reply.status_code == 200
    runs = _runs(client)
    assert {k: len(v) - 1 for k, v in runs.items()} == {f"otel:{TRACE_A}": 1, f"otel:{TRACE_B}": 1}
    [tool] = runs[f"otel:{TRACE_A}"][1:]
    assert tool["extensions"]["sealedrun.otel"]["conversation"] == "thread-7"
    [chat] = runs[f"otel:{TRACE_B}"][1:]
    assert "conversation" not in chat["extensions"]["sealedrun.otel"]
