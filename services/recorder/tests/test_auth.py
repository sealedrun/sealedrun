import base64
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sealedrun_recorder.main import create_app
from sealedrun_recorder.settings import Settings


@pytest.fixture
def secured(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(data_dir=tmp_path, ui_dir=tmp_path / "no-ui", api_token=SecretStr("s3cret"))
    with TestClient(create_app(settings), base_url="http://localhost") as client:
        yield client


def test_default_host_is_loopback() -> None:
    assert Settings().host == "127.0.0.1"


def test_open_without_token(client: TestClient) -> None:
    assert client.get("/api/runs").status_code == 200


def test_empty_token_means_no_auth(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path, ui_dir=tmp_path / "no-ui", api_token=SecretStr(""))
    with TestClient(create_app(settings), base_url="http://localhost") as client:
        assert client.get("/api/runs").status_code == 200


def test_missing_token_rejected(secured: TestClient) -> None:
    response = secured.get("/api/runs")
    assert response.status_code == 401
    assert "www-authenticate" not in response.headers


@pytest.mark.parametrize("header", ["Bearer wrong", "Bearer ", "Basic !!!", "Token s3cret"])
def test_wrong_token_rejected(secured: TestClient, header: str) -> None:
    assert secured.get("/api/runs", headers={"Authorization": header}).status_code == 401


def test_bearer_accepted(secured: TestClient) -> None:
    assert secured.get("/api/runs", headers={"Authorization": "Bearer s3cret"}).status_code == 200


def test_basic_rejected(secured: TestClient) -> None:
    value = base64.b64encode(b"anyone:s3cret").decode()
    assert secured.get("/api/runs", headers={"Authorization": f"Basic {value}"}).status_code == 401


def test_upload_requires_token(secured: TestClient) -> None:
    response = secured.post("/api/bundles", files={"file": ("b.zip", b"x", "application/zip")})
    assert response.status_code == 401


def test_health_stays_open(secured: TestClient) -> None:
    assert secured.get("/api/health").status_code == 200


FILE = {"file": ("b.zip", b"x", "application/zip")}
BEARER = {"Authorization": "Bearer s3cret"}


@pytest.mark.parametrize("site", ["cross-site", "same-site", "none", "bogus"])
def test_cross_site_upload_refused(secured: TestClient, client: TestClient, site: str) -> None:
    headers = {"Sec-Fetch-Site": site, "Origin": "https://evil.example"}
    assert client.post("/api/bundles", files=FILE, headers=headers).status_code == 403
    assert secured.post("/api/bundles", files=FILE, headers=headers | BEARER).status_code == 403


def test_upload_without_fetch_metadata_needs_token(secured: TestClient, client: TestClient) -> None:
    assert client.post("/api/bundles", files=FILE).status_code == 403
    assert secured.post("/api/bundles", files=FILE, headers=BEARER).status_code != 403


def test_same_origin_upload_passes_the_check(client: TestClient) -> None:
    response = client.post("/api/bundles", files=FILE, headers={"Sec-Fetch-Site": "same-origin"})
    assert response.status_code not in (401, 403)


def test_access_log_filter_drops_query_strings() -> None:
    import logging

    from sealedrun_recorder.main import QueryStringFilter

    record = logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        1,
        '%s - "%s %s HTTP/%s" %d',
        ("127.0.0.1:5", "GET", "/v1beta/models?key=SECRET&x=1", "1.1", 200),
        None,
    )
    assert QueryStringFilter().filter(record) is True
    assert "SECRET" not in record.getMessage()
    assert '"GET /v1beta/models HTTP/1.1" 200' in record.getMessage()


def test_client_facing_upstream_errors_are_generic(
    make_proxy: Any, upstream: Any, secrets: dict[str, str]
) -> None:
    config = """
upstreams:
  - name: secretive-vendor
    url: https://vendor.example/v1
    dialect: openai
    key_env: VENDOR_PRIVATE_KEY_ENV
    location: cloud
    models: ["gpt-*"]
  - name: dead-vendor
    url: https://dead.example/v1
    dialect: openai
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["dead-*"]
mcp_servers:
  - name: secretive-mcp
    url: https://mcp.example/mcp
    key_env: VENDOR_PRIVATE_KEY_ENV
    location: cloud
"""
    headers = {"Authorization": f"Bearer {secrets['token']}"}
    upstream.fail = "down"
    with make_proxy(config) as client:
        unset = client.post(
            "/v1/chat/completions", json={"model": "gpt-4.1", "messages": []}, headers=headers
        )
        dead = client.post(
            "/v1/chat/completions", json={"model": "dead-1", "messages": []}, headers=headers
        )
        mcp = client.post(
            "/mcp/secretive-mcp", json={"jsonrpc": "2.0", "method": "ping"}, headers=headers
        )
    assert unset.status_code == 503 and dead.status_code == 502 and mcp.status_code == 503
    for reply in (unset, dead, mcp):
        assert "VENDOR_PRIVATE_KEY_ENV" not in reply.text
        assert "secretive" not in reply.text and "dead-vendor" not in reply.text
        assert "ConnectError" not in reply.text


def test_cross_site_read_is_not_blocked_by_the_check(client: TestClient) -> None:
    assert client.get("/api/runs", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 200


@pytest.mark.parametrize("host", ["evil.example", "rebind.evil.example:8080"])
def test_unknown_host_refused(client: TestClient, host: str) -> None:
    assert client.get("/api/health", headers={"Host": host}).status_code == 400


@pytest.mark.parametrize(
    "host", ["evil.example", "rebind.evil.example:3000", "evil.example, localhost"]
)
def test_unknown_forwarded_host_refused(client: TestClient, host: str) -> None:
    """A dev proxy rewrites Host but keeps the browser's one in X-Forwarded-Host."""
    reply = client.get("/api/health", headers={"X-Forwarded-Host": host})
    assert reply.status_code == 400
    for own in ("localhost:3000", "127.0.0.1"):
        assert client.get("/api/health", headers={"X-Forwarded-Host": own}).status_code == 200


def test_allowed_hosts_setting(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path, ui_dir=tmp_path / "no-ui", allowed_hosts=["rec.example"])
    with TestClient(create_app(settings), base_url="http://rec.example") as client:
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/health", headers={"Host": "localhost"}).status_code == 400


def test_security_headers_on_ui_and_api(tmp_path: Path) -> None:
    ui = tmp_path / "ui"
    ui.mkdir()
    (ui / "index.html").write_text("<!doctype html><title>Inspector</title>")
    settings = Settings(data_dir=tmp_path, ui_dir=ui, api_token=SecretStr("s3cret"))
    with TestClient(create_app(settings), base_url="http://localhost") as client:
        for path in ("/", "/api/health", "/api/runs"):
            reply = client.get(path)
            assert reply.headers["x-content-type-options"] == "nosniff", path
            assert reply.headers["x-frame-options"] == "DENY", path
            assert "frame-ancestors 'none'" in reply.headers["content-security-policy"], path
            assert reply.headers["cross-origin-opener-policy"] == "same-origin", path
