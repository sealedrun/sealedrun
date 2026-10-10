import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
from opentelemetry.proto.common.v1.common_pb2 import AnyValue, KeyValue
from pydantic import SecretStr
from sealedrun_recorder.db import PayloadRow, RecordRow, RunRow
from sealedrun_recorder.main import create_app
from sealedrun_recorder.settings import Settings

VECTORS = Path(__file__).resolve().parents[3] / "spec" / "vectors" / "bundle"


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(data_dir=tmp_path, ui_dir=tmp_path / "no-ui")
    with TestClient(create_app(settings), base_url="http://localhost") as client:
        yield client


@pytest.fixture
def valid_zip() -> bytes:
    return (VECTORS / "valid.zip").read_bytes()


@pytest.fixture
def upload() -> Any:
    def _upload(client: TestClient, path: str, data: bytes) -> Any:
        return client.post(
            path,
            files={"file": ("bundle.zip", data, "application/zip")},
            headers={"Sec-Fetch-Site": "same-origin"},
        )

    return _upload


@pytest.fixture
def vectors() -> Path:
    return VECTORS


PROXY_TOKEN = "proxy-token-123"
UPSTREAM_KEY = "sk-upstream-secret-456"


class FakeUpstream:
    """Stands in for every upstream: answers by URL path suffix and keeps what it was sent."""

    def __init__(self) -> None:
        self.calls: list[httpx.Request] = []
        self.routes: dict[str, Any] = {}
        self.fail: str | None = None

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        if self.fail == "down":
            raise httpx.ConnectError("refused", request=request)
        if self.fail is not None:
            return httpx.Response(int(self.fail), json={"error": {"message": "upstream failed"}})
        for suffix, answer in self.routes.items():
            if request.url.path.endswith(suffix):
                return answer(request) if callable(answer) else httpx.Response(200, json=answer)
        return httpx.Response(404, json={"error": {"message": "no route"}})


@pytest.fixture
def upstream() -> FakeUpstream:
    return FakeUpstream()


@pytest.fixture
def make_proxy(
    tmp_path: Path, upstream: FakeUpstream, monkeypatch: pytest.MonkeyPatch
) -> Callable[..., TestClient]:
    """Build a recorder whose upstreams file is `config` and whose network is `upstream`."""
    monkeypatch.setenv("TEST_UPSTREAM_KEY", UPSTREAM_KEY)

    def _make(config: str, **overrides: Any) -> TestClient:
        app = make_proxy_app(tmp_path, upstream, config, **overrides)
        return TestClient(app, base_url="http://localhost")

    return _make


@pytest.fixture(autouse=True)
def _anchoring_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """Anchoring is on by default; tests must select anchors explicitly, never the network."""
    monkeypatch.setenv("SEALEDRUN_ANCHORS", "[]")


def make_proxy_app(tmp_path: Path, upstream: Any, config: str, **overrides: Any) -> FastAPI:
    """Build the recorder app itself, for tests that drive it as an ASGI app."""
    path = tmp_path / "upstreams.yaml"
    path.write_text(config)
    options: dict[str, Any] = {"api_token": SecretStr(PROXY_TOKEN), **overrides}
    settings = Settings(
        data_dir=tmp_path, ui_dir=tmp_path / "no-ui", upstreams_file=path, **options
    )
    return create_app(settings, http_transport=httpx.MockTransport(upstream))


@pytest.fixture
def make_app(
    tmp_path: Path, upstream: FakeUpstream, monkeypatch: pytest.MonkeyPatch
) -> Callable[..., FastAPI]:
    """Like `make_proxy` but returns the bare app; the test runs its lifespan itself."""
    monkeypatch.setenv("TEST_UPSTREAM_KEY", UPSTREAM_KEY)

    def _make(config: str, **overrides: Any) -> FastAPI:
        return make_proxy_app(tmp_path, upstream, config, **overrides)

    return _make


def _stored_text(client: TestClient) -> str:
    return stored_text_of(client.app)


def stored_text_of(app: Any) -> str:
    """Every record document and payload body `app` holds, as one string."""
    live = app.state.live
    with live._sessions() as session:
        bodies = [row.body.decode() for row in session.query(PayloadRow)]
        docs = [row.document for row in session.query(RecordRow)]
    return json.dumps(docs) + "".join(bodies)


def _proxy_records(client: TestClient) -> list[dict[str, Any]]:
    return records_of(client.app)


def records_of(app: Any) -> list[dict[str, Any]]:
    """The records of the only run of `app`, in seq order."""
    live = app.state.live
    with live._sessions() as session:
        runs = session.query(RunRow).all()
        if not runs:
            return []
        assert len(runs) == 1
        rows = session.query(RecordRow).filter_by(run_id=runs[0].run_id).order_by(RecordRow.seq)
        return [row.document for row in rows]


@pytest.fixture
def stored_text() -> Callable[[TestClient], str]:
    """Every record document and payload body the recorder holds, as one string."""
    return _stored_text


@pytest.fixture
def proxy_records() -> Callable[[TestClient], list[dict[str, Any]]]:
    """The records of the only run, in seq order."""
    return _proxy_records


@pytest.fixture
def app_records() -> Callable[[Any], list[dict[str, Any]]]:
    """Like `proxy_records`, but for a bare app."""
    return records_of


@pytest.fixture
def app_stored_text() -> Callable[[Any], str]:
    """Like `stored_text`, but for a bare app."""
    return stored_text_of


@pytest.fixture
def secrets() -> dict[str, str]:
    """The recorder token clients send and the upstream key the proxy swaps in."""
    return {"token": PROXY_TOKEN, "upstream_key": UPSTREAM_KEY}


def any_value(value: Any) -> AnyValue:
    if isinstance(value, bool):
        return AnyValue(bool_value=value)
    if isinstance(value, int):
        return AnyValue(int_value=value)
    if isinstance(value, float):
        return AnyValue(double_value=value)
    if isinstance(value, bytes):
        return AnyValue(bytes_value=value)
    if isinstance(value, list):
        out = AnyValue()
        out.array_value.values.extend(any_value(v) for v in value)
        return out
    if isinstance(value, dict):
        out = AnyValue()
        out.kvlist_value.values.extend(
            KeyValue(key=k, value=any_value(v)) for k, v in value.items()
        )
        return out
    return AnyValue(string_value=str(value))


def export_with(
    spans: list[dict[str, Any]], resource: dict[str, Any] | None = None
) -> ExportTraceServiceRequest:
    """Build an export with one resource and one scope holding `spans` (name + attributes)."""
    export = ExportTraceServiceRequest()
    rs = export.resource_spans.add()
    for key, value in (resource or {"service.name": "agent"}).items():
        rs.resource.attributes.add(key=key, value=any_value(value))
    ss = rs.scope_spans.add()
    ss.scope.name = "test-scope"
    for index, spec in enumerate(spans):
        span = ss.spans.add()
        span.name = spec["name"]
        span.trace_id = bytes.fromhex(spec.get("trace_id", "0af7651916cd43dd8448eb211c80319c"))
        span.span_id = bytes.fromhex(spec.get("span_id", f"{index + 1:016x}"))
        span.start_time_unix_nano = spec.get("start", 1_700_000_000_000_000_000 + index)
        span.end_time_unix_nano = spec.get("end", span.start_time_unix_nano + 5_000_000)
        for key, value in spec.get("attributes", {}).items():
            span.attributes.add(key=key, value=any_value(value))
        if spec.get("error"):
            span.status.code = 2
            span.status.message = spec["error"]
    return export


@pytest.fixture
def otlp_export() -> Callable[..., ExportTraceServiceRequest]:
    """Builder of OTLP exports: `otlp_export(spans, resource=None)`."""
    return export_with


@pytest.fixture
def otlp_value() -> Callable[[Any], AnyValue]:
    """Builder of OTLP `AnyValue`s from plain Python values."""
    return any_value


def load_test_tsa() -> Any:
    """Import the offline RFC 3161 authority shared with the `sealedrun` package tests."""
    import importlib.util

    path = Path(__file__).resolve().parents[3] / "packages" / "sealedrun-py" / "tests" / "tsa.py"
    spec = importlib.util.spec_from_file_location("tsa", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeTsa:
    """An RFC 3161 endpoint on the fake upstream: real tokens from the offline test authority.

    `fail` answers that many requests with 500 first; `include` is passed to the authority
    (`leaf` with a published chain like Sigstore, `chain` without one like DigiCert).
    """

    def __init__(self, authority: Any, *, fail: int = 0, include: str = "leaf") -> None:
        self.authority = authority
        self.fail = fail
        self.include = include
        self.requests = 0
        self.chain_requests = 0

    def timestamp(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        if self.fail > 0:
            self.fail -= 1
            return httpx.Response(500, text="try later")
        assert request.headers["content-type"] == "application/timestamp-query"
        body = self.authority.respond(request.content, include=self.include)
        return httpx.Response(
            200, content=body, headers={"content-type": "application/timestamp-reply"}
        )

    def certchain(self, request: httpx.Request) -> httpx.Response:
        self.chain_requests += 1
        if self.include != "leaf":
            return httpx.Response(404, text="not found")
        return httpx.Response(200, text="".join(self.authority.chain_pems))


def load_fake_rekor() -> Any:
    """Import the offline Rekor log shared with the `sealedrun` package tests."""
    import importlib.util

    path = (
        Path(__file__).resolve().parents[3]
        / "packages"
        / "sealedrun-py"
        / "tests"
        / "rekor_fake.py"
    )
    spec = importlib.util.spec_from_file_location("rekor_fake", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeRekorHttp:
    """`POST /api/v1/log/entries` on the fake upstream, answered by an offline log."""

    def __init__(self, log: Any, *, fail: int = 0) -> None:
        self.log = log
        self.fail = fail
        self.requests = 0

    def entries(self, request: httpx.Request) -> httpx.Response:
        self.requests += 1
        if self.fail > 0:
            self.fail -= 1
            return httpx.Response(500, text="try later")
        assert request.method == "POST"
        return httpx.Response(201, json=self.log.add(json.loads(request.content)))
