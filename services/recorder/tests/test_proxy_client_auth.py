"""Client credential pass-through: Claude Code on a subscription login goes through the proxy."""

from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sealedrun_recorder.upstreams import UpstreamConfigError, load_upstreams

UPSTREAMS = """
upstreams:
  - name: anthropic-subscription
    url: https://anthropic.example
    dialect: anthropic
    client_auth: passthrough
    location: cloud
    models: ["claude-*"]
  - name: kimi-keyed
    url: https://kimi.example/anthropic
    dialect: anthropic
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["kimi-*"]
  - name: fallback
    url: https://fallback.example
    dialect: openai
    key_env: TEST_UPSTREAM_KEY
    client_auth: passthrough
    location: cloud
    models: ["gpt-*"]
"""

OAUTH = "Bearer sk-ant-oat01-subscription-login"
BETA = "oauth-2025-04-20,claude-code-20250219"
REPLY = {
    "id": "msg_1",
    "type": "message",
    "role": "assistant",
    "model": "claude-sonnet-5",
    "content": [{"type": "text", "text": "hi"}],
    "stop_reason": "end_turn",
    "usage": {"input_tokens": 5, "output_tokens": 1},
}
BODY = {"model": "claude-sonnet-5", "max_tokens": 8, "messages": [{"role": "user", "content": "x"}]}


@pytest.fixture
def proxy(make_proxy: Callable[..., TestClient], upstream: Any) -> Iterator[TestClient]:
    upstream.routes.update(
        {"/v1/messages": REPLY, "/chat/completions": {"choices": [], "model": "gpt-5"}}
    )
    with make_proxy(UPSTREAMS) as client:
        yield client


def _subscription(secrets: dict[str, str], **extra: str) -> dict[str, str]:
    return {
        "X-SealedRun-Token": secrets["token"],
        "Authorization": OAUTH,
        "anthropic-version": "2023-06-01",
        "anthropic-beta": BETA,
        **extra,
    }


def test_subscription_login_forwarded(
    proxy: TestClient,
    upstream: Any,
    secrets: dict[str, str],
    proxy_records: Any,
    stored_text: Any,
) -> None:
    response = proxy.post("/v1/messages", json=BODY, headers=_subscription(secrets))
    assert response.status_code == 200
    sent = upstream.calls[0].headers
    assert sent["authorization"] == OAUTH
    assert sent["anthropic-beta"] == BETA
    assert "x-api-key" not in sent
    assert "x-sealedrun-token" not in sent
    assert proxy_records(proxy)[1]["outcome"] == "success"
    text = stored_text(proxy)
    assert "sk-ant-oat01" not in text
    assert secrets["token"] not in text


def test_token_header_alone_is_accepted(proxy: TestClient, secrets: dict[str, str]) -> None:
    headers = {"X-SealedRun-Token": secrets["token"], "anthropic-version": "2023-06-01"}
    assert (
        proxy.post("/v1/messages", json={**BODY, "model": "kimi-k2"}, headers=headers).status_code
        == 200
    )


def test_wrong_token_header_refused(proxy: TestClient, upstream: Any) -> None:
    headers = {"X-SealedRun-Token": "wrong", "Authorization": OAUTH}
    assert proxy.post("/v1/messages", json=BODY, headers=headers).status_code == 401
    assert upstream.calls == []


def test_keyed_upstream_ignores_client_login(
    proxy: TestClient, upstream: Any, secrets: dict[str, str]
) -> None:
    body = {**BODY, "model": "kimi-k2"}
    assert proxy.post("/v1/messages", json=body, headers=_subscription(secrets)).status_code == 200
    sent = upstream.calls[0].headers
    assert sent["x-api-key"] == secrets["upstream_key"]
    assert "authorization" not in sent


def test_token_as_api_key_keeps_configured_key(
    proxy: TestClient, upstream: Any, secrets: dict[str, str]
) -> None:
    body = {"model": "gpt-5", "messages": []}
    headers = {"Authorization": f"Bearer {secrets['token']}"}
    assert proxy.post("/v1/chat/completions", json=body, headers=headers).status_code == 200
    assert upstream.calls[0].headers["authorization"] == f"Bearer {secrets['upstream_key']}"


def test_passthrough_without_client_login_has_no_key(
    proxy: TestClient, upstream: Any, secrets: dict[str, str]
) -> None:
    headers = {"x-api-key": secrets["token"], "anthropic-version": "2023-06-01"}
    assert proxy.post("/v1/messages", json=BODY, headers=headers).status_code == 200
    sent = upstream.calls[0].headers
    assert "authorization" not in sent
    assert "x-api-key" not in sent


def test_recorder_token_never_forwarded(
    proxy: TestClient, upstream: Any, secrets: dict[str, str]
) -> None:
    headers = _subscription(secrets, Authorization=f"Bearer {secrets['token']}")
    assert proxy.post("/v1/messages", json=BODY, headers=headers).status_code == 200
    sent = upstream.calls[0].headers
    assert "authorization" not in sent
    assert all(secrets["token"] not in value for value in sent.values())


def test_client_login_used_for_model_list(
    proxy: TestClient, upstream: Any, secrets: dict[str, str]
) -> None:
    proxy.get("/v1/models", headers=_subscription(secrets))
    listed = [c for c in upstream.calls if c.url.host == "anthropic.example"]
    assert listed and listed[0].headers["authorization"] == OAUTH


def test_bad_client_auth_value(tmp_path: Any) -> None:
    path = tmp_path / "u.yaml"
    path.write_text("upstreams:\n  - {name: a, url: 'https://a.example', client_auth: always}\n")
    with pytest.raises(UpstreamConfigError, match="client_auth"):
        load_upstreams(path, {})
