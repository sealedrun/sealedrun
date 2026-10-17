import json
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sealedrun.schema import validate_extensions

UPSTREAMS = """
upstreams:
  - name: router
    url: https://router.example/api/v1
    dialect: systemone
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["typesafe/*"]
    headers:
      X-Title: SealedRun
  - name: foundry
    url: https://foundry.example/providers/microsoft/v1
    dialect: systemone
    key_env: TEST_UPSTREAM_KEY
    auth: api-key
    client_auth: passthrough
    location: cloud
    models: ["decision-*"]
  - name: chat
    url: https://cloud.example/v1
    dialect: openai
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["gpt-*"]
"""

BODY = {
    "model": "typesafe/jev-1.13",
    "state": {"tool": "shell", "command": "rm -rf /var/lib/postgres", "host": "prod-db-1"},
    "questions": {
        "touches_prod": {
            "type": "noul",
            "instructions": "Does the command touch production data?",
            "criteria": {"true": "destroys or alters prod data", "false": "otherwise"},
        },
        "severity": {
            "type": "score",
            "instructions": "How severe is the action?",
            "criteria": ["harmless", "recoverable", "destructive"],
        },
    },
}
# Shape of a live OpenRouter reply (2026-10-16): `noul` is a probability, `score` indexes the
# criteria, `legend` and `probabilities` are maps keyed by that index.
REPLY = {
    "model": "typesafe/jev-1.13-20260917",
    "answers": {
        "touches_prod": {"type": "noul", "noul": 0.97},
        "severity": {
            "type": "score",
            "score": 2,
            "legend": {"0": "harmless", "1": "recoverable", "2": "destructive"},
            "probabilities": {"0": 0, "1": 0, "2": 1},
            "confidence": 1,
        },
    },
    "usage": {"input_tokens": 383, "output_tokens": 36, "cost": 0.000016086},
    "id": "gen-dec-1792165764-oS1XxxgLZyu4aN0cUvNM",
    "provider": "TypeSafe",
}
PATHS = ["/api/alpha/decisions", "/api/v1/systemone", "/providers/microsoft/v1/systemone"]


@pytest.fixture
def proxy(make_proxy: Callable[..., TestClient], upstream: Any) -> Iterator[TestClient]:
    upstream.routes["/systemone"] = REPLY
    with make_proxy(UPSTREAMS) as client:
        yield client


@pytest.fixture
def auth(secrets: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {secrets['token']}"}


@pytest.mark.parametrize("path", PATHS)
def test_each_public_path_forwards_to_systemone_and_records(
    path: str, proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    response = proxy.post(path, json=BODY, headers=auth)
    assert response.status_code == 200
    assert response.json() == REPLY
    sent = upstream.calls[0]
    assert str(sent.url) == "https://router.example/api/v1/systemone"
    assert json.loads(sent.content) == BODY
    assert sent.headers["x-title"] == "SealedRun"
    call = proxy_records(proxy)[1]
    assert call["kind"] == "llm_call"
    assert call["outcome"] == "success"
    assert call["target"]["endpoint"] == "https://router.example/api/v1/systemone"
    assert call["extensions"]["sealedrun.llm"] == {
        "model": "typesafe/jev-1.13-20260917",
        "provider": "router",
        "stream": False,
        "input_tokens": 383,
        "output_tokens": 36,
    }
    proxy_ext = call["extensions"]["sealedrun.proxy"]
    assert proxy_ext["dialect"] == "systemone"
    assert proxy_ext["operation"] == "decisions"
    assert proxy_ext["status"] == 200
    assert validate_extensions(call["extensions"]) == []
    stored = proxy.get(f"/api/records/{call['record_id']}/payload/response", headers=auth)
    assert json.loads(stored.content) == REPLY


def test_answers_are_normalised_with_the_legend(
    proxy: TestClient, auth: dict[str, str], proxy_records: Any
) -> None:
    response = proxy.post(PATHS[1], json=BODY, headers=auth)
    call = proxy_records(proxy)[1]
    assert response.headers["x-sealedrun-record"] == call["record_id"]
    assert call["extensions"]["sealedrun.decision"] == {
        "answers": [
            {"name": "touches_prod", "type": "predicate", "value": 0.97},
            {
                "name": "severity",
                "type": "score",
                "value": 2,
                "confidence": 1,
                "probabilities": {"harmless": 0, "recoverable": 0, "destructive": 1},
            },
        ]
    }
    assert validate_extensions(call["extensions"]) == []


def test_choice_without_legend_and_refused_answer(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/systemone"] = {
        "answers": {
            "team": {
                "type": "choice",
                "choice": "engineering",
                "probabilities": {"billing": 0.05, "engineering": 0.95},
            },
            "touches_prod": {"type": "noul", "refused": True},
            "severity": {"type": "score", "score": 1, "probabilities": {"0": 0.2, "1": 0.8}},
        }
    }
    proxy.post(PATHS[0], json=BODY, headers=auth)
    assert proxy_records(proxy)[1]["extensions"]["sealedrun.decision"]["answers"] == [
        {
            "name": "team",
            "type": "choice",
            "value": "engineering",
            "probabilities": {"billing": 0.05, "engineering": 0.95},
        },
        {"name": "touches_prod", "type": "predicate", "refused": True},
        {"name": "severity", "type": "score", "value": 1, "probabilities": {"0": 0.2, "1": 0.8}},
    ]


def test_missing_usage_and_model_are_tolerated(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/systemone"] = {"answers": {"touches_prod": {"type": "noul", "noul": False}}}
    assert proxy.post(PATHS[1], json=BODY, headers=auth).status_code == 200
    llm = proxy_records(proxy)[1]["extensions"]["sealedrun.llm"]
    assert llm == {"model": "typesafe/jev-1.13", "provider": "router", "stream": False}


def test_foundry_api_key_passthrough(
    proxy: TestClient, upstream: Any, auth: dict[str, str], secrets: dict[str, str]
) -> None:
    body = {**BODY, "model": "decision-1"}
    headers = {"X-SealedRun-Token": secrets["token"], "api-key": "client-foundry-key"}
    assert proxy.post(PATHS[2], json=body, headers=headers).status_code == 200
    sent = upstream.calls[0]
    assert str(sent.url) == "https://foundry.example/providers/microsoft/v1/systemone"
    assert sent.headers["api-key"] == "client-foundry-key"
    assert "authorization" not in sent.headers
    assert proxy.post(PATHS[2], json=body, headers=auth).status_code == 200
    assert upstream.calls[1].headers["api-key"] == secrets["upstream_key"]


def test_streaming_refused_and_errors_recorded(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    response = proxy.post(PATHS[0], json={**BODY, "stream": True}, headers=auth)
    assert response.status_code == 400
    assert "streaming is not supported" in response.json()["error"]["message"]
    upstream.fail = "502"
    assert proxy.post(PATHS[0], json=BODY, headers=auth).status_code == 502
    call = proxy_records(proxy)[1]
    assert call["outcome"] == "error"
    assert call["extensions"]["sealedrun.proxy"]["status"] == 502
    assert call["extensions"]["sealedrun.proxy"]["dialect"] == "systemone"


def test_model_of_another_format_and_unknown_model(
    proxy: TestClient, upstream: Any, auth: dict[str, str]
) -> None:
    response = proxy.post(PATHS[1], json={**BODY, "model": "gpt-6-luna"}, headers=auth)
    assert response.status_code == 400
    assert "reachable only as: openai" in response.json()["error"]["message"]
    assert proxy.post(PATHS[1], json={**BODY, "model": "other/x"}, headers=auth).status_code == 404
    assert upstream.calls == []


def test_needs_the_token(proxy: TestClient, upstream: Any) -> None:
    assert proxy.post(PATHS[0], json=BODY).status_code == 401
    assert proxy.post(PATHS[0], json=BODY, headers={"api-key": "wrong"}).status_code == 401
    assert upstream.calls == []
