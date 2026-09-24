from collections.abc import Callable, Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sealedrun import verify_run
from sealedrun.schema import validate_extensions

UPSTREAMS = """
upstreams:
  - name: anthropic
    url: https://anthropic.example
    dialect: anthropic
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["claude-*"]
  - name: kimi-anthropic
    url: https://kimi.example/anthropic
    dialect: anthropic
    key_env: TEST_UPSTREAM_KEY
    auth: bearer
    location: cloud
    models: ["kimi-*"]
  - name: local-anthropic
    url: http://127.0.0.1:11434
    dialect: anthropic
    location: local
    models: ["*:*"]
  - name: openai-only
    url: https://openai.example/v1
    dialect: openai
    location: cloud
    models: ["gpt-*"]
"""

MESSAGE_REPLY = {
    "id": "msg_1",
    "type": "message",
    "role": "assistant",
    "model": "claude-sonnet-5-20260801",
    "content": [
        {"type": "thinking", "thinking": "", "signature": "s"},
        {"type": "text", "text": "Reading it."},
        {"type": "tool_use", "id": "tu_1", "name": "read_file", "input": {"path": "a"}},
    ],
    "stop_reason": "tool_use",
    "usage": {
        "input_tokens": 20,
        "cache_creation_input_tokens": 100,
        "cache_read_input_tokens": 1000,
        "output_tokens": 15,
    },
}
VERSION = {"anthropic-version": "2023-06-01"}


def _models(request: httpx.Request) -> httpx.Response:
    ids = {"anthropic.example": ["claude-sonnet-5", "claude-opus-5-5"], "127.0.0.1": ["qwen3:8b"]}
    data = [{"type": "model", "id": i, "display_name": i} for i in ids.get(request.url.host, [])]
    return httpx.Response(200, json={"data": data, "has_more": False})


@pytest.fixture
def proxy(make_proxy: Callable[..., TestClient], upstream: Any) -> Iterator[TestClient]:
    upstream.routes.update(
        {
            "/v1/messages": MESSAGE_REPLY,
            "/v1/messages/count_tokens": {"input_tokens": 1234},
            "/v1/models": _models,
        }
    )
    with make_proxy(UPSTREAMS) as client:
        yield client


@pytest.fixture
def auth(secrets: dict[str, str]) -> dict[str, str]:
    return {"x-api-key": secrets["token"], **VERSION}


def _message(
    client: TestClient, headers: dict[str, str], model: str = "claude-sonnet-5", **extra: Any
) -> httpx.Response:
    body = {
        "model": model,
        "max_tokens": 256,
        "messages": [{"role": "user", "content": "read a"}],
        **extra,
    }
    return client.post("/v1/messages", json=body, headers=headers)


def test_message_is_forwarded_and_recorded(
    proxy: TestClient,
    upstream: Any,
    auth: dict[str, str],
    secrets: dict[str, str],
    proxy_records: Any,
) -> None:
    response = _message(proxy, {**auth, "anthropic-beta": "tools-2026"}, temperature=0.5)
    assert response.status_code == 200
    assert response.json() == MESSAGE_REPLY
    sent = upstream.calls[0]
    assert str(sent.url) == "https://anthropic.example/v1/messages"
    assert sent.headers["x-api-key"] == secrets["upstream_key"]
    assert sent.headers["anthropic-version"] == "2023-06-01"
    assert sent.headers["anthropic-beta"] == "tools-2026"
    assert "authorization" not in sent.headers

    records = proxy_records(proxy)
    call = records[1]
    assert call["kind"] == "llm_call"
    assert call["outcome"] == "success"
    assert call["target"]["endpoint"] == "https://anthropic.example/v1/messages"
    assert call["extensions"]["sealedrun.llm"] == {
        "model": "claude-sonnet-5-20260801",
        "provider": "anthropic",
        "stream": False,
        "temperature": 0.5,
        "input_tokens": 1120,
        "output_tokens": 15,
        "finish_reason": "tool_use",
        "tool_calls_requested": ["read_file"],
    }
    assert call["extensions"]["sealedrun.proxy"]["dialect"] == "anthropic"
    assert call["extensions"]["sealedrun.proxy"]["operation"] == "messages"
    assert validate_extensions(call["extensions"]) == []
    delegation = proxy.get("/api/identity", headers={"Authorization": f"Bearer {secrets['token']}"})
    identity = delegation.json()["delegation"]
    verify_run(records, {identity["delegation_id"]: identity})


def test_bearer_token_accepted_as_claude_code_sends_it(
    proxy: TestClient, upstream: Any, secrets: dict[str, str]
) -> None:
    headers = {"Authorization": f"Bearer {secrets['token']}", **VERSION}
    assert _message(proxy, headers).status_code == 200
    assert upstream.calls[0].headers["x-api-key"] == secrets["upstream_key"]


def test_upstream_with_bearer_auth(
    proxy: TestClient, upstream: Any, auth: dict[str, str], secrets: dict[str, str]
) -> None:
    assert _message(proxy, auth, model="kimi-k2.6").status_code == 200
    sent = upstream.calls[0]
    assert str(sent.url) == "https://kimi.example/anthropic/v1/messages"
    assert sent.headers["authorization"] == f"Bearer {secrets['upstream_key']}"
    assert "x-api-key" not in sent.headers


def test_local_upstream_gets_no_key(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    assert _message(proxy, auth, model="qwen3-coder:30b").status_code == 200
    sent = upstream.calls[0]
    assert str(sent.url) == "http://127.0.0.1:11434/v1/messages"
    assert "x-api-key" not in sent.headers
    assert "authorization" not in sent.headers
    assert proxy_records(proxy)[1]["target"]["location"] == "local"


def test_query_forwarded_without_key(
    proxy: TestClient, upstream: Any, auth: dict[str, str]
) -> None:
    body = {"model": "claude-sonnet-5", "max_tokens": 1, "messages": []}
    assert proxy.post("/v1/messages?beta=true&key=x", json=body, headers=auth).status_code == 200
    assert str(upstream.calls[0].url) == "https://anthropic.example/v1/messages?beta=true"


def test_credentials_never_recorded(
    proxy: TestClient, auth: dict[str, str], secrets: dict[str, str], stored_text: Any
) -> None:
    _message(proxy, auth)
    _message(proxy, {"Authorization": f"Bearer {secrets['token']}", **VERSION})
    proxy.post(
        "/v1/messages/count_tokens",
        json={"model": "claude-sonnet-5", "messages": []},
        headers=auth,
    )
    stored = stored_text(proxy)
    assert secrets["token"] not in stored
    assert secrets["upstream_key"] not in stored
    assert "x-api-key" not in stored.lower()


def test_count_tokens_recorded(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    response = proxy.post(
        "/v1/messages/count_tokens",
        json={"model": "claude-sonnet-5", "messages": [{"role": "user", "content": "x"}]},
        headers=auth,
    )
    assert response.json() == {"input_tokens": 1234}
    assert str(upstream.calls[0].url) == "https://anthropic.example/v1/messages/count_tokens"
    call = proxy_records(proxy)[1]
    assert call["extensions"]["sealedrun.proxy"]["operation"] == "count_tokens"
    assert call["extensions"]["sealedrun.llm"]["input_tokens"] == 1234


def test_upstream_error_passed_through_and_recorded(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.fail = "529"
    response = _message(proxy, auth)
    assert response.status_code == 529
    call = proxy_records(proxy)[1]
    assert call["outcome"] == "error"
    assert call["extensions"]["sealedrun.proxy"]["status"] == 529


def test_unreachable_upstream_in_anthropic_shape(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.fail = "down"
    response = _message(proxy, auth)
    assert response.status_code == 502
    assert response.json()["type"] == "error"
    assert response.json()["error"]["type"] == "api_error"
    assert proxy_records(proxy)[1]["outcome"] == "error"


@pytest.mark.parametrize(
    ("model", "extra", "status", "kind"),
    [
        ("mistral-large", {}, 404, "not_found_error"),
        ("gpt-4.1", {}, 400, "invalid_request_error"),
        ("claude-sonnet-5", {"stream": True}, 400, "invalid_request_error"),
    ],
)
def test_proxy_errors_in_anthropic_shape(
    proxy: TestClient,
    upstream: Any,
    auth: dict[str, str],
    model: str,
    extra: dict[str, Any],
    status: int,
    kind: str,
) -> None:
    response = _message(proxy, auth, model=model, **extra)
    assert response.status_code == status
    assert response.json()["type"] == "error"
    assert response.json()["error"]["type"] == kind
    assert upstream.calls == []


def test_openai_only_model_names_its_format(proxy: TestClient, auth: dict[str, str]) -> None:
    message = _message(proxy, auth, model="gpt-4.1").json()["error"]["message"]
    assert "openai" in message


@pytest.mark.parametrize(
    "headers", [VERSION, {"x-api-key": "wrong", **VERSION}, {"Authorization": "Bearer wrong"}]
)
def test_messages_need_the_token(proxy: TestClient, upstream: Any, headers: dict[str, str]) -> None:
    assert _message(proxy, headers).status_code == 401
    assert upstream.calls == []


def test_models_in_anthropic_shape(proxy: TestClient, upstream: Any, auth: dict[str, str]) -> None:
    response = proxy.get("/v1/models", headers=auth)
    assert response.status_code == 200
    listing = response.json()
    assert [m["id"] for m in listing["data"]] == ["claude-sonnet-5", "claude-opus-5-5", "qwen3:8b"]
    assert listing["has_more"] is False
    assert listing["first_id"] == "claude-sonnet-5"
    assert listing["last_id"] == "qwen3:8b"
    assert all(c.url.path.endswith("/v1/models") for c in upstream.calls)
    assert upstream.calls[0].headers["anthropic-version"] == "2023-06-01"


def test_models_without_version_header_use_openai_shape(
    proxy: TestClient, secrets: dict[str, str]
) -> None:
    listing = proxy.get("/v1/models", headers={"x-api-key": secrets["token"]}).json()
    assert listing["object"] == "list"
