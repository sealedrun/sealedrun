import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
from sealedrun_recorder.main import create_app
from sealedrun_recorder.settings import Settings


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
    assert body.headers["content-disposition"].startswith("attachment")
    assert body.headers["x-content-type-options"] == "nosniff"
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


def test_unsafe_payload_media_type_is_downgraded(
    client: TestClient, upload: Any, valid_zip: bytes
) -> None:
    from sealedrun_recorder.db import RecordRow

    upload(client, "/api/bundles", valid_zip)
    run_id = client.get("/api/runs").json()[0]["run_id"]
    llm = client.get(f"/api/runs/{run_id}/records").json()[1]
    with client.app.state.sessions() as session:  # type: ignore[attr-defined]
        row = session.get(RecordRow, llm["record_id"])
        document = {**row.document}
        document["payload"] = {**document["payload"], "request_media_type": "text/html"}
        row.document = document
        session.commit()
    body = client.get(f"/api/records/{llm['record_id']}/payload/request")
    assert body.headers["content-type"] == "application/octet-stream"
    assert "sandbox" in body.headers["content-security-policy"]


def test_pagination(client: TestClient, upload: Any, valid_zip: bytes) -> None:
    upload(client, "/api/bundles", valid_zip)
    run_id = client.get("/api/runs").json()[0]["run_id"]
    page = client.get(f"/api/runs/{run_id}/records", params={"limit": 2, "offset": 3}).json()
    assert [r["seq"] for r in page] == [3, 4]
    assert client.get("/api/runs", params={"limit": 1, "offset": 1}).json() == []
    assert client.get("/api/bundles", params={"limit": 0}).status_code == 422
    assert client.get("/api/runs", params={"limit": 100000}).status_code == 422


def _trusting(tmp_path: Path, principals: list[str]) -> TestClient:
    settings = Settings(data_dir=tmp_path, ui_dir=tmp_path / "no-ui", trusted_principals=principals)
    return TestClient(create_app(settings), base_url="http://localhost")


def test_unknown_principal_refused_when_trust_anchor_is_set(
    tmp_path: Path, upload: Any, vectors: Path, valid_zip: bytes
) -> None:
    genuine = json.loads((vectors.parent / "keys.json").read_text())["principal"]["kid"]
    forged = (vectors / "unknown-principal.zip").read_bytes()
    with _trusting(tmp_path, [genuine]) as client:
        refused = upload(client, "/api/bundles", forged)
        assert refused.status_code == 422
        assert refused.json()["detail"]["check"] == "trust"
        assert upload(client, "/api/verify", forged).json()["check"] == "trust"
        stored = upload(client, "/api/bundles", valid_zip)
        assert stored.status_code == 201
        assert stored.json()["principal_trusted"] is True
        assert all(run["principal_trusted"] for run in client.get("/api/runs").json())


def test_without_trust_anchor_bundles_are_stored_as_not_authenticated(
    client: TestClient, upload: Any, vectors: Path
) -> None:
    forged = (vectors / "unknown-principal.zip").read_bytes()
    stored = upload(client, "/api/bundles", forged)
    assert stored.status_code == 201
    assert stored.json()["principal_trusted"] is False
    verdict = upload(client, "/api/verify", forged).json()
    assert verdict["ok"] is True and verdict["principal_trusted"] is False
    assert verdict["principal_id"] == stored.json()["principal_id"]
