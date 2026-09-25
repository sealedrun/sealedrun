import io
import json
import zipfile
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sealedrun import read_bundle, verify_bundle
from sealedrun_recorder.db import PayloadRow
from sealedrun_recorder.main import create_app
from sealedrun_recorder.settings import Settings

SAME_SITE = {"Sec-Fetch-Site": "same-origin"}
UPSTREAMS = """
upstreams:
  - name: cloudai
    url: https://cloud.example/v1
    dialect: openai
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["gpt-*"]
"""
BODY = {
    "model": "gpt-4.1",
    "messages": [{"role": "user", "content": "hi"}],
    "stream": True,
    "stream_options": {"include_usage": True},
}
CHAT_CHUNKS = [
    b'data: {"id":"c1","model":"gpt-4.1","choices":[{"index":0,"delta":{"content":"Hi"}}]}\n\n',
    b'data: {"id":"c1","model":"gpt-4.1","choices":[{"index":0,"delta":{},'
    b'"finish_reason":"stop"}]}\n\n',
    b'data: {"id":"c1","model":"gpt-4.1","choices":[],'
    b'"usage":{"prompt_tokens":4,"completion_tokens":1,"total_tokens":5}}\n\n',
    b"data: [DONE]\n\n",
]


class Stream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            yield chunk


def _streaming_route(stream: Stream) -> Callable[..., httpx.Response]:
    def _route(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, stream=stream)

    return _route


@pytest.fixture
def auth(secrets: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {secrets['token']}"}


def _one_streamed_call(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str]
) -> tuple[TestClient, str]:
    upstream.routes["/chat/completions"] = _streaming_route(Stream(CHAT_CHUNKS))
    proxy = make_proxy(UPSTREAMS)
    proxy.__enter__()
    assert proxy.post("/v1/chat/completions", json=BODY, headers=auth).status_code == 200
    run_id = proxy.get("/api/runs", headers=auth).json()[0]["run_id"]
    return proxy, run_id


def _principal(proxy: TestClient, auth: dict[str, str]) -> str:
    return str(proxy.get("/api/identity", headers=auth).json()["principal_id"])


def test_export_of_open_run_verifies_and_reimports(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    tmp_path: Path,
    upload: Any,
) -> None:
    proxy, run_id = _one_streamed_call(make_proxy, upstream, auth)
    response = proxy.post(f"/api/runs/{run_id}/export", headers=auth)
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    assert response.headers["content-disposition"] == (
        f'attachment; filename="sealedrun-{run_id}.zip"'
    )
    report = verify_bundle(read_bundle(response.content), [_principal(proxy, auth)])
    assert report.principal_trusted
    assert report.runs[0].run_id == run_id
    assert report.runs[0].record_count == 2
    assert report.runs[0].complete is False
    manifest = json.loads(zipfile.ZipFile(io.BytesIO(response.content)).read("manifest.json"))
    assert manifest["exporter"]["software"].startswith("sealedrun-recorder/")
    assert "principal_signatures" in manifest

    with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
        bodies = {n.rsplit("/", 1)[-1]: zf.read(n) for n in zf.namelist() if "payloads/" in n}
    records = proxy.get(f"/api/runs/{run_id}/records", headers=auth).json()
    ref = records[1]["payload"]
    assert bodies[ref["response_hash"]] == b"".join(CHAT_CHUNKS)
    assert json.loads(bodies[ref["request_hash"]]) == BODY

    settings = Settings(data_dir=tmp_path / "second", ui_dir=tmp_path / "no-ui")
    with TestClient(create_app(settings), base_url="http://localhost") as other:
        stored = upload(other, "/api/bundles", response.content)
        assert stored.status_code == 201, stored.text
        copied = other.get(f"/api/runs/{run_id}/records").json()
        assert copied == records
        assert other.get(f"/api/runs/{run_id}").json()["source"] == "imported"
    proxy.__exit__(None, None, None)


def test_export_with_end_closes_the_run(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str]
) -> None:
    proxy, run_id = _one_streamed_call(make_proxy, upstream, auth)
    response = proxy.post(f"/api/runs/{run_id}/export?end=true", headers=auth)
    assert response.status_code == 200
    report = verify_bundle(read_bundle(response.content), [_principal(proxy, auth)])
    assert report.runs[0].complete is True
    assert report.runs[0].record_count == 3
    assert proxy.get(f"/api/runs/{run_id}", headers=auth).json()["complete"] is True
    assert proxy.post(f"/api/runs/{run_id}/export?end=true", headers=auth).status_code == 409
    again = proxy.post(f"/api/runs/{run_id}/export", headers=auth)
    assert verify_bundle(read_bundle(again.content)).runs[0].complete is True
    assert proxy.post("/v1/chat/completions", json=BODY, headers=auth).status_code == 200
    assert len(proxy.get("/api/runs", headers=auth).json()) == 2
    proxy.__exit__(None, None, None)


def test_export_refusals(
    make_proxy: Callable[..., TestClient],
    upstream: Any,
    auth: dict[str, str],
    valid_zip: bytes,
) -> None:
    proxy, run_id = _one_streamed_call(make_proxy, upstream, auth)
    assert proxy.post(f"/api/runs/{run_id}/export").status_code == 401
    assert proxy.post(f"/api/runs/{run_id}/export", headers=SAME_SITE).status_code == 401
    assert proxy.post("/api/runs/no-such-run/export", headers=auth).status_code == 404
    imported = proxy.post(
        "/api/bundles", files={"file": ("b.zip", valid_zip, "application/zip")}, headers=auth
    )
    assert imported.status_code == 201, imported.text
    refused = proxy.post(f"/api/runs/{imported.json()['runs'][0]}/export", headers=auth)
    assert refused.status_code == 409
    assert "original bundle" in refused.json()["detail"]
    proxy.__exit__(None, None, None)


def test_missing_payload_body_is_an_error_not_a_gap(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str]
) -> None:
    proxy, run_id = _one_streamed_call(make_proxy, upstream, auth)
    with proxy.app.state.sessions() as session:  # type: ignore[attr-defined]
        for row in session.query(PayloadRow):
            session.delete(row)
        session.commit()
    response = proxy.post(f"/api/runs/{run_id}/export", headers=auth)
    assert response.status_code == 500
    assert "payload body missing" in response.json()["detail"]
    proxy.__exit__(None, None, None)


def test_recorder_trusts_its_own_principal_only(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str], valid_zip: bytes
) -> None:
    proxy, run_id = _one_streamed_call(make_proxy, upstream, auth)
    assert proxy.get(f"/api/runs/{run_id}", headers=auth).json()["principal_trusted"] is True
    imported = proxy.post(
        "/api/bundles", files={"file": ("b.zip", valid_zip, "application/zip")}, headers=auth
    )
    other = imported.json()["runs"][0]
    assert proxy.get(f"/api/runs/{other}", headers=auth).json()["principal_trusted"] is False
    proxy.__exit__(None, None, None)
