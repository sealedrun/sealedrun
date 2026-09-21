import base64
from collections.abc import Iterator
from pathlib import Path

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


@pytest.mark.parametrize("site", ["cross-site", "none", "bogus"])
def test_cross_site_upload_refused(secured: TestClient, client: TestClient, site: str) -> None:
    headers = {"Sec-Fetch-Site": site, "Origin": "https://evil.example"}
    assert client.post("/api/bundles", files=FILE, headers=headers).status_code == 403
    assert secured.post("/api/bundles", files=FILE, headers=headers | BEARER).status_code == 403


def test_upload_without_fetch_metadata_needs_token(secured: TestClient, client: TestClient) -> None:
    assert client.post("/api/bundles", files=FILE).status_code == 403
    assert secured.post("/api/bundles", files=FILE, headers=BEARER).status_code != 403


@pytest.mark.parametrize("site", ["same-origin", "same-site"])
def test_same_site_upload_passes_the_check(client: TestClient, site: str) -> None:
    response = client.post("/api/bundles", files=FILE, headers={"Sec-Fetch-Site": site})
    assert response.status_code not in (401, 403)


def test_cross_site_read_is_not_blocked_by_the_check(client: TestClient) -> None:
    assert client.get("/api/runs", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 200


@pytest.mark.parametrize("host", ["evil.example", "rebind.evil.example:8080"])
def test_unknown_host_refused(client: TestClient, host: str) -> None:
    assert client.get("/api/health", headers={"Host": host}).status_code == 400


def test_allowed_hosts_setting(tmp_path: Path) -> None:
    settings = Settings(data_dir=tmp_path, ui_dir=tmp_path / "no-ui", allowed_hosts=["rec.example"])
    with TestClient(create_app(settings), base_url="http://rec.example") as client:
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/health", headers={"Host": "localhost"}).status_code == 400
