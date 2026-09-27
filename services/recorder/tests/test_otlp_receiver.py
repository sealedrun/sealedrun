import gzip
import json
import zlib
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from google.protobuf.json_format import MessageToJson
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest,
    ExportTraceServiceResponse,
)
from opentelemetry.proto.common.v1.common_pb2 import AnyValue
from sealedrun_recorder.otlp import decode, spans_of, value_of

CONFIG = "upstreams: []\n"
PROTOBUF = "application/x-protobuf"


Export = Callable[..., ExportTraceServiceRequest]


@pytest.fixture(autouse=True)
def _builders(otlp_export: Export, otlp_value: Callable[[Any], AnyValue]) -> None:
    global export_with, any_value
    export_with = otlp_export
    any_value = otlp_value


@pytest.fixture
def client(make_proxy: Callable[..., TestClient]) -> Iterator[TestClient]:
    with make_proxy(CONFIG) as client:
        yield client


@pytest.fixture
def auth(secrets: dict[str, str]) -> dict[str, str]:
    return {"X-SealedRun-Token": secrets["token"]}


def _post(client: TestClient, body: bytes, **headers: str) -> Any:
    return client.post("/otlp/v1/traces", content=body, headers=headers)


def test_protobuf_export_is_accepted(client: TestClient, auth: dict[str, str]) -> None:
    export = export_with([{"name": "execute_tool add", "attributes": {"gen_ai.tool.name": "add"}}])
    reply = _post(client, export.SerializeToString(), **auth, **{"Content-Type": PROTOBUF})
    assert reply.status_code == 200, reply.text
    assert reply.headers["content-type"].startswith(PROTOBUF)
    answer = ExportTraceServiceResponse()
    answer.ParseFromString(reply.content)
    assert not answer.HasField("partial_success")


def test_json_export_decodes_to_the_same_spans(client: TestClient, auth: dict[str, str]) -> None:
    export = export_with(
        [{"name": "chat gpt", "attributes": {"gen_ai.request.model": "gpt-4.1", "n": 2}}]
    )
    document = json.loads(MessageToJson(export))
    span = document["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    span["traceId"] = "0af7651916cd43dd8448eb211c80319c"
    span["spanId"] = "0000000000000001"
    as_json = json.dumps(document).encode()
    reply = _post(client, as_json, **auth, **{"Content-Type": "application/json; charset=utf-8"})
    assert reply.status_code == 200, reply.text
    assert reply.json() == {}
    decoded = decode(as_json, "application/json")
    binary = decode(export.SerializeToString(), PROTOBUF)
    assert [s.span.name for s in spans_of(decoded)] == [s.span.name for s in spans_of(binary)]
    assert spans_of(decoded)[0].attributes == {"gen_ai.request.model": "gpt-4.1", "n": 2}
    assert (
        spans_of(decoded)[0].span.trace_id
        == binary.resource_spans[0].scope_spans[0].spans[0].trace_id
    )


@pytest.mark.parametrize("encoding", ["gzip", "deflate"])
def test_compressed_bodies_are_accepted(
    client: TestClient, auth: dict[str, str], encoding: str
) -> None:
    raw = export_with([{"name": "a"}, {"name": "b"}]).SerializeToString()
    body = gzip.compress(raw) if encoding == "gzip" else zlib.compress(raw)
    headers = {**auth, "Content-Type": PROTOBUF, "Content-Encoding": encoding}
    assert _post(client, body, **headers).status_code == 200
    bad = {**auth, "Content-Type": PROTOBUF, "Content-Encoding": encoding}
    assert _post(client, b"not compressed", **bad).status_code == 400
    assert (
        _post(
            client, raw, **{**auth, "Content-Type": PROTOBUF, "Content-Encoding": "br"}
        ).status_code
        == 400
    )


def test_unknown_content_type_and_bad_bodies(client: TestClient, auth: dict[str, str]) -> None:
    assert _post(client, b"{}", **auth, **{"Content-Type": "text/plain"}).status_code == 415
    assert _post(client, b"\xff\xff", **auth, **{"Content-Type": PROTOBUF}).status_code == 400
    assert _post(client, b"{", **auth, **{"Content-Type": "application/json"}).status_code == 400
    bad_field = json.dumps({"resourceSpans": [{"resource": {"attributes": "x"}}]}).encode()
    assert (
        _post(client, bad_field, **auth, **{"Content-Type": "application/json"}).status_code == 400
    )


def test_token_is_required(client: TestClient, secrets: dict[str, str]) -> None:
    body = export_with([{"name": "a"}]).SerializeToString()
    assert _post(client, body, **{"Content-Type": PROTOBUF}).status_code == 401
    bearer = {"Authorization": f"Bearer {secrets['token']}", "Content-Type": PROTOBUF}
    assert _post(client, body, **bearer).status_code == 200


def test_oversize_export_is_refused(
    make_proxy: Callable[..., TestClient], auth: dict[str, str]
) -> None:
    with make_proxy(CONFIG, proxy_max_body_bytes=512) as client:
        big = export_with([{"name": "x" * 600}]).SerializeToString()
        assert _post(client, big, **auth, **{"Content-Type": PROTOBUF}).status_code == 413
        packed = gzip.compress(export_with([{"name": "y" * 4000}]).SerializeToString())
        headers = {**auth, "Content-Type": PROTOBUF, "Content-Encoding": "gzip"}
        assert len(packed) < 512
        assert _post(client, packed, **headers).status_code == 400


def test_attribute_values_convert_to_plain_python() -> None:
    nested = {"s": "x", "i": 3, "f": 1.5, "b": True, "l": [1, "a"], "m": {"k": b"\x00"}}
    assert value_of(any_value(nested)) == nested
    assert value_of(AnyValue()) is None
