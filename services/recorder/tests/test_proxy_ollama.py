from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sealedrun import verify_run
from sealedrun.schema import validate_extensions

UPSTREAMS = """
upstreams:
  - name: ollama-cloud
    url: https://ollama.example
    dialect: ollama
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["*-cloud"]
  - name: ollama-native
    url: http://127.0.0.1:11434
    dialect: ollama
    location: local
    models: ["*"]
  - name: openai-only
    url: https://openai.example/v1
    dialect: openai
    location: cloud
    models: ["gpt-*"]
"""

CHAT_REPLY = {
    "model": "llama3.2:3b",
    "created_at": "2026-09-24T10:00:00Z",
    "message": {
        "role": "assistant",
        "content": "",
        "tool_calls": [{"function": {"name": "get_weather", "arguments": {"city": "Riga"}}}],
    },
    "done": True,
    "done_reason": "stop",
    "total_duration": 1000,
    "prompt_eval_count": 26,
    "eval_count": 7,
}
GENERATE_REPLY = {
    "model": "llama3.2:3b",
    "response": "Hello",
    "done": True,
    "done_reason": "length",
    "prompt_eval_count": 3,
    "eval_count": 128,
}
EMBED_REPLY = {"model": "nomic-embed-text", "embeddings": [[0.1, 0.2]], "prompt_eval_count": 4}


def _tags(request: httpx.Request) -> httpx.Response:
    names = {"127.0.0.1": ["llama3.2:3b", "nomic-embed-text:latest"], "ollama.example": []}
    models = [{"name": n, "model": n, "size": 1} for n in names.get(request.url.host, [])]
    return httpx.Response(200, json={"models": models})


@pytest.fixture
def proxy(make_proxy: Callable[..., TestClient], upstream: Any) -> Iterator[TestClient]:
    upstream.routes.update(
        {
            "/api/chat": CHAT_REPLY,
            "/api/generate": GENERATE_REPLY,
            "/api/embed": EMBED_REPLY,
            "/api/embeddings": {"embedding": [0.3]},
            "/api/tags": _tags,
            "/api/version": {"version": "0.20.1"},
            "/api/show": {"details": {"family": "llama"}},
        }
    )
    with make_proxy(UPSTREAMS) as client:
        yield client


@pytest.fixture
def auth(secrets: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {secrets['token']}"}


def _chat(
    client: TestClient, auth: dict[str, str], model: str = "llama3.2:3b", **extra: Any
) -> Any:
    body = {
        "model": model,
        "messages": [{"role": "user", "content": "weather?"}],
        "stream": False,
        "options": {"temperature": 0.2},
        **extra,
    }
    return client.post("/api/chat", json=body, headers=auth)


def test_chat_is_forwarded_and_recorded(
    proxy: TestClient,
    upstream: Any,
    auth: dict[str, str],
    secrets: dict[str, str],
    proxy_records: Any,
) -> None:
    response = _chat(proxy, auth)
    assert response.status_code == 200
    assert response.json() == CHAT_REPLY
    sent = upstream.calls[0]
    assert str(sent.url) == "http://127.0.0.1:11434/api/chat"
    assert "authorization" not in sent.headers

    records = proxy_records(proxy)
    call = records[1]
    assert call["target"]["location"] == "local"
    assert call["extensions"]["sealedrun.llm"] == {
        "model": "llama3.2:3b",
        "provider": "ollama-native",
        "stream": False,
        "temperature": 0.2,
        "input_tokens": 26,
        "output_tokens": 7,
        "finish_reason": "stop",
        "tool_calls_requested": ["get_weather"],
    }
    assert call["extensions"]["sealedrun.proxy"]["dialect"] == "ollama"
    assert validate_extensions(call["extensions"]) == []
    identity = proxy.get("/api/identity", headers=auth).json()["delegation"]
    verify_run(records, {identity["delegation_id"]: identity})


def test_generate_recorded(proxy: TestClient, auth: dict[str, str], proxy_records: Any) -> None:
    body = {"model": "llama3.2:3b", "prompt": "Hi", "stream": False}
    assert proxy.post("/api/generate", json=body, headers=auth).json() == GENERATE_REPLY
    llm = proxy_records(proxy)[1]["extensions"]["sealedrun.llm"]
    assert (llm["input_tokens"], llm["output_tokens"], llm["finish_reason"]) == (3, 128, "length")
    assert proxy_records(proxy)[1]["extensions"]["sealedrun.proxy"]["operation"] == "generate"


@pytest.mark.parametrize(
    ("path", "body", "tokens"),
    [
        ("/api/embed", {"model": "nomic-embed-text", "input": ["a"]}, 4),
        ("/api/embeddings", {"model": "nomic-embed-text", "prompt": "a"}, None),
    ],
)
def test_embeddings_recorded(
    proxy: TestClient,
    upstream: Any,
    auth: dict[str, str],
    proxy_records: Any,
    path: str,
    body: dict[str, Any],
    tokens: int | None,
) -> None:
    assert proxy.post(path, json=body, headers=auth).status_code == 200
    assert upstream.calls[0].url.path == path
    call = proxy_records(proxy)[1]
    assert call["extensions"]["sealedrun.proxy"]["operation"] == "embeddings"
    assert call["extensions"]["sealedrun.llm"].get("input_tokens") == tokens


def test_cloud_upstream_gets_the_key(
    proxy: TestClient, upstream: Any, auth: dict[str, str], secrets: dict[str, str]
) -> None:
    assert _chat(proxy, auth, model="gpt-oss:120b-cloud").status_code == 200
    sent = upstream.calls[0]
    assert str(sent.url) == "https://ollama.example/api/chat"
    assert sent.headers["authorization"] == f"Bearer {secrets['upstream_key']}"


def test_credentials_never_recorded(
    proxy: TestClient, auth: dict[str, str], secrets: dict[str, str], stored_text: Any
) -> None:
    _chat(proxy, auth)
    _chat(proxy, auth, model="gpt-oss:120b-cloud")
    stored = stored_text(proxy)
    assert secrets["token"] not in stored
    assert secrets["upstream_key"] not in stored


def test_upstream_error_passed_through_and_recorded(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.fail = "404"
    assert _chat(proxy, auth, model="missing:latest").status_code == 404
    call = proxy_records(proxy)[1]
    assert call["outcome"] == "error"
    assert call["extensions"]["sealedrun.proxy"]["status"] == 404


def test_unreachable_upstream_in_ollama_shape(
    proxy: TestClient, upstream: Any, auth: dict[str, str]
) -> None:
    upstream.fail = "down"
    response = _chat(proxy, auth)
    assert response.status_code == 502
    assert isinstance(response.json()["error"], str)


def test_bad_bodies_refused(proxy: TestClient, upstream: Any, auth: dict[str, str]) -> None:
    assert (
        proxy.post("/api/chat", json={"model": "", "stream": False}, headers=auth).status_code
        == 400
    )
    assert proxy.post("/api/chat", content=b"{", headers=auth).status_code == 400
    assert upstream.calls == []


def test_version_without_reachable_upstream(
    proxy: TestClient, upstream: Any, auth: dict[str, str]
) -> None:
    upstream.fail = "down"
    response = proxy.get("/api/version", headers=auth)
    assert response.status_code == 503
    assert "error" in response.json()


def test_native_calls_need_the_token(proxy: TestClient, upstream: Any) -> None:
    body = {"model": "llama3.2:3b", "messages": [], "stream": False}
    assert proxy.post("/api/chat", json=body).status_code == 401
    assert proxy.get("/api/tags").status_code == 401
    assert proxy.get("/api/version").status_code == 401
    assert proxy.post("/api/show", json={"model": "llama3.2:3b"}).status_code == 401
    assert upstream.calls == []


def test_tags_merged_and_filtered(proxy: TestClient, auth: dict[str, str]) -> None:
    response = proxy.get("/api/tags", headers=auth)
    assert [m["name"] for m in response.json()["models"]] == [
        "llama3.2:3b",
        "nomic-embed-text:latest",
    ]


def test_version_and_show_are_not_recorded(
    proxy: TestClient, upstream: Any, auth: dict[str, str]
) -> None:
    assert proxy.get("/api/version", headers=auth).json() == {"version": "0.20.1"}
    show = proxy.post("/api/show", json={"model": "llama3.2:3b"}, headers=auth)
    assert show.json() == {"details": {"family": "llama"}}
    assert str(upstream.calls[-1].url) == "http://127.0.0.1:11434/api/show"
    assert proxy.get("/api/runs", headers=auth).json() == []


def test_show_errors(proxy: TestClient, upstream: Any, auth: dict[str, str]) -> None:
    assert proxy.post("/api/show", content=b"{", headers=auth).status_code == 400
    assert proxy.post("/api/show", json={}, headers=auth).status_code == 400
    assert proxy.post("/api/show", content=b"x" * 70000, headers=auth).status_code == 413
    upstream.fail = "down"
    assert proxy.post("/api/show", json={"model": "a"}, headers=auth).status_code == 502


def test_management_endpoints_not_proxied(proxy: TestClient, auth: dict[str, str]) -> None:
    for path in ("/api/pull", "/api/delete", "/api/create", "/api/push"):
        assert proxy.post(path, json={"model": "x"}, headers=auth).status_code in (404, 405)
