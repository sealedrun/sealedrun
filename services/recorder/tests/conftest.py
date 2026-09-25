import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
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
