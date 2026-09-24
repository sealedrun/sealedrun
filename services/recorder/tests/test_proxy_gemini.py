from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sealedrun import verify_run
from sealedrun.schema import validate_extensions

UPSTREAMS = """
upstreams:
  - name: gemini
    url: https://gemini.example
    dialect: gemini
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["gemini-*", "text-embedding-*"]
  - name: gemini-openai
    url: https://gemini.example/v1beta/openai
    dialect: openai
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["gemini-*", "gpt-*"]
"""

GENERATE_REPLY = {
    "candidates": [
        {
            "content": {
                "role": "model",
                "parts": [
                    {"text": "Checking."},
                    {"functionCall": {"name": "lookup", "args": {"q": "x"}}},
                ],
            },
            "finishReason": "STOP",
        }
    ],
    "usageMetadata": {
        "promptTokenCount": 12,
        "candidatesTokenCount": 8,
        "thoughtsTokenCount": 30,
        "totalTokenCount": 50,
    },
    "modelVersion": "gemini-3-flash-001",
}
PATH = "/v1beta/models/gemini-3-flash:generateContent"


def _models(request: httpx.Request) -> httpx.Response:
    names = ["models/gemini-3-flash", "models/imagen-4", "models/text-embedding-005"]
    return httpx.Response(200, json={"models": [{"name": n} for n in names]})


@pytest.fixture
def proxy(make_proxy: Callable[..., TestClient], upstream: Any) -> Iterator[TestClient]:
    upstream.routes.update(
        {
            ":generateContent": GENERATE_REPLY,
            ":countTokens": {"totalTokens": 77},
            ":embedContent": {"embedding": {"values": [0.1]}},
            ":batchEmbedContents": {"embeddings": [{"values": [0.1]}]},
            "/v1beta/models": _models,
            "/v1beta/models/gemini-3-flash": {"name": "models/gemini-3-flash"},
        }
    )
    with make_proxy(UPSTREAMS) as client:
        yield client


@pytest.fixture
def auth(secrets: dict[str, str]) -> dict[str, str]:
    return {"x-goog-api-key": secrets["token"]}


def _generate(client: TestClient, url: str = PATH, **headers: str) -> httpx.Response:
    body = {
        "contents": [{"role": "user", "parts": [{"text": "look up x"}]}],
        "generationConfig": {"temperature": 0.7},
    }
    return client.post(url, json=body, headers=headers)


def test_generate_is_forwarded_and_recorded(
    proxy: TestClient,
    upstream: Any,
    auth: dict[str, str],
    secrets: dict[str, str],
    proxy_records: Any,
) -> None:
    response = _generate(proxy, **auth)
    assert response.status_code == 200
    assert response.json() == GENERATE_REPLY
    sent = upstream.calls[0]
    assert str(sent.url) == f"https://gemini.example{PATH}"
    assert sent.headers["x-goog-api-key"] == secrets["upstream_key"]
    assert "authorization" not in sent.headers

    records = proxy_records(proxy)
    call = records[1]
    assert call["target"]["name"] == "gemini-3-flash"
    assert call["target"]["endpoint"] == f"https://gemini.example{PATH}"
    assert call["extensions"]["sealedrun.llm"] == {
        "model": "gemini-3-flash-001",
        "provider": "gemini",
        "stream": False,
        "temperature": 0.7,
        "input_tokens": 12,
        "output_tokens": 38,
        "finish_reason": "STOP",
        "tool_calls_requested": ["lookup"],
    }
    assert call["extensions"]["sealedrun.proxy"]["dialect"] == "gemini"
    assert call["extensions"]["sealedrun.proxy"]["operation"] == "generate"
    assert validate_extensions(call["extensions"]) == []
    bearer = {"Authorization": f"Bearer {secrets['token']}"}
    delegation = proxy.get("/api/identity", headers=bearer).json()["delegation"]
    verify_run(records, {delegation["delegation_id"]: delegation})


def test_query_key_accepted_stripped_and_never_recorded(
    proxy: TestClient,
    upstream: Any,
    secrets: dict[str, str],
    stored_text: Any,
) -> None:
    response = _generate(proxy, f"{PATH}?key={secrets['token']}&alt=json")
    assert response.status_code == 200
    sent = upstream.calls[0]
    assert "key" not in sent.url.params
    assert sent.url.params["alt"] == "json"
    stored = stored_text(proxy)
    assert secrets["token"] not in stored
    assert secrets["upstream_key"] not in stored


def test_stable_api_version_kept(proxy: TestClient, upstream: Any, auth: dict[str, str]) -> None:
    url = "/v1/models/gemini-3-flash:generateContent"
    assert _generate(proxy, url, **auth).status_code == 200
    assert upstream.calls[0].url.path == url


def test_query_key_on_stable_version(proxy: TestClient, secrets: dict[str, str]) -> None:
    url = f"/v1/models/gemini-3-flash:generateContent?key={secrets['token']}"
    assert _generate(proxy, url).status_code == 200


@pytest.mark.parametrize(
    ("action", "body", "operation", "tokens"),
    [
        ("countTokens", {"contents": []}, "count_tokens", 77),
        ("embedContent", {"content": {"parts": [{"text": "a"}]}}, "embeddings", None),
        ("batchEmbedContents", {"requests": []}, "embeddings", None),
    ],
)
def test_other_methods_recorded(
    proxy: TestClient,
    auth: dict[str, str],
    proxy_records: Any,
    action: str,
    body: dict[str, Any],
    operation: str,
    tokens: int | None,
) -> None:
    model = "text-embedding-005" if "mbed" in action else "gemini-3-flash"
    url = f"/v1beta/models/{model}:{action}"
    assert proxy.post(url, json=body, headers=auth).status_code == 200
    call = proxy_records(proxy)[1]
    assert call["extensions"]["sealedrun.proxy"]["operation"] == operation
    assert call["extensions"]["sealedrun.llm"].get("input_tokens") == tokens


def test_same_model_through_openai_compat(
    proxy: TestClient, upstream: Any, secrets: dict[str, str]
) -> None:
    upstream.routes["/chat/completions"] = {"model": "gemini-3-flash", "choices": []}
    body = {"model": "gemini-3-flash", "messages": []}
    headers = {"Authorization": f"Bearer {secrets['token']}"}
    assert proxy.post("/v1/chat/completions", json=body, headers=headers).status_code == 200
    sent = upstream.calls[0]
    assert str(sent.url) == "https://gemini.example/v1beta/openai/chat/completions"
    assert sent.headers["authorization"] == f"Bearer {secrets['upstream_key']}"


def test_upstream_error_passed_through_and_recorded(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.fail = "429"
    assert _generate(proxy, **auth).status_code == 429
    call = proxy_records(proxy)[1]
    assert call["outcome"] == "error"
    assert call["extensions"]["sealedrun.proxy"]["status"] == 429


def test_unreachable_upstream_in_gemini_shape(
    proxy: TestClient, upstream: Any, auth: dict[str, str]
) -> None:
    upstream.fail = "down"
    response = _generate(proxy, **auth)
    assert response.status_code == 502
    assert response.json()["error"]["status"] == "UNAVAILABLE"


@pytest.mark.parametrize(
    ("url", "status", "name"),
    [
        ("/v1beta/models/gemini-3-flash:streamGenerateContent?alt=sse", 400, "INVALID_ARGUMENT"),
        ("/v1beta/models/gemini-3-flash:tuneModel", 404, "NOT_FOUND"),
        ("/v1beta/models/:generateContent", 404, "NOT_FOUND"),
        ("/v2/models/gemini-3-flash:generateContent", 404, "NOT_FOUND"),
        ("/v1beta/models/gpt-4.1:generateContent", 400, "INVALID_ARGUMENT"),
        ("/v1beta/models/claude-5:generateContent", 404, "NOT_FOUND"),
    ],
)
def test_proxy_errors_in_gemini_shape(
    proxy: TestClient, upstream: Any, auth: dict[str, str], url: str, status: int, name: str
) -> None:
    response = _generate(proxy, url, **auth)
    assert response.status_code == status
    assert response.json()["error"]["status"] == name
    assert response.json()["error"]["code"] == status
    assert upstream.calls == []


@pytest.mark.parametrize(
    ("url", "headers"),
    [
        (PATH, {}),
        (PATH, {"x-goog-api-key": "wrong"}),
        (f"{PATH}?key=wrong", {}),
    ],
)
def test_gemini_calls_need_the_token(
    proxy: TestClient, upstream: Any, url: str, headers: dict[str, str]
) -> None:
    assert _generate(proxy, url, **headers).status_code == 401
    assert proxy.get("/v1beta/models", headers=headers).status_code == 401
    assert upstream.calls == []


def test_models_listed_and_filtered(proxy: TestClient, auth: dict[str, str]) -> None:
    response = proxy.get("/v1beta/models", headers=auth)
    names = [m["name"] for m in response.json()["models"]]
    assert names == ["models/gemini-3-flash", "models/text-embedding-005"]


def test_model_details_not_recorded(
    proxy: TestClient, upstream: Any, auth: dict[str, str], secrets: dict[str, str]
) -> None:
    response = proxy.get("/v1beta/models/gemini-3-flash", headers=auth)
    assert response.json() == {"name": "models/gemini-3-flash"}
    assert proxy.get("/v1beta/models/claude-5", headers=auth).status_code == 404
    upstream.fail = "down"
    assert proxy.get("/v1beta/models/gemini-3-flash", headers=auth).status_code == 502
    bearer = {"Authorization": f"Bearer {secrets['token']}"}
    assert proxy.get("/api/runs", headers=bearer).json() == []
