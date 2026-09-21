from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
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
