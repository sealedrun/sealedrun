from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient


def test_health(client: TestClient) -> None:
    assert client.get("/api/health").json() == {"status": "ok"}


def test_upload_and_browse(client: TestClient, valid_zip: bytes, upload: Any) -> None:
    response = upload(client, "/api/bundles", valid_zip)
    assert response.status_code == 201, response.text
    bundle = response.json()
    assert len(bundle["runs"]) == 1

    assert [b["bundle_id"] for b in client.get("/api/bundles").json()] == [bundle["bundle_id"]]
    detail = client.get(f"/api/bundles/{bundle['bundle_id']}").json()
    assert detail["report"]["runs"][0]["complete"] is True

    runs = client.get("/api/runs").json()
    assert len(runs) == 1
    run = runs[0]
    assert run["record_count"] == 9
    assert run["anchors"] == 1
    assert run["labels_sent_to_cloud"] == {"pii": 1}

    records = client.get(f"/api/runs/{run['run_id']}/records").json()
    assert [r["seq"] for r in records] == list(range(9))
    assert records[0]["kind"] == "run_start"

    llm = records[1]
    assert client.get(f"/api/records/{llm['record_id']}").json()["hash"] == llm["hash"]
    body = client.get(f"/api/records/{llm['record_id']}/payload/request")
    assert body.status_code == 200
    assert body.headers["content-type"].startswith("application/json")
    assert b"gpt-4.1" in body.content

    blocked = records[4]
    assert client.get(f"/api/records/{blocked['record_id']}/payload/request").status_code == 404

    archive = client.get(f"/api/bundles/{bundle['bundle_id']}/archive")
    assert archive.content == valid_zip


def test_upload_is_idempotent(client: TestClient, valid_zip: bytes, upload: Any) -> None:
    assert upload(client, "/api/bundles", valid_zip).status_code == 201
    assert upload(client, "/api/bundles", valid_zip).status_code == 201
    assert len(client.get("/api/bundles").json()) == 1
    assert len(client.get("/api/runs").json()) == 1


def test_tampered_bundle_rejected(client: TestClient, upload: Any, vectors: Path) -> None:
    data = (vectors / "tampered-record.zip").read_bytes()
    response = upload(client, "/api/bundles", data)
    assert response.status_code == 422
    assert response.json()["detail"]["check"] == "bundle"
    assert client.get("/api/bundles").json() == []


def test_verify_endpoint(client: TestClient, valid_zip: bytes, upload: Any, vectors: Path) -> None:
    ok = upload(client, "/api/verify", valid_zip).json()
    assert ok["ok"] is True
    assert ok["runs"][0]["record_count"] == 9
    bad = upload(client, "/api/verify", (vectors / "no-payloads.zip").read_bytes()).json()
    assert bad["ok"] is False
    assert (bad["check"], bad["seq"]) == ("payload", 1)
    assert client.get("/api/bundles").json() == []


def test_garbage_rejected(client: TestClient, upload: Any) -> None:
    response = upload(client, "/api/bundles", b"not a zip")
    assert response.status_code == 422
    assert response.json()["detail"]["check"] == "bundle"
    assert client.get("/api/runs/nope").status_code == 404
    assert client.get("/api/records/nope").status_code == 404
