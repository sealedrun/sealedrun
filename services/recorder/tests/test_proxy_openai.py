import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sealedrun import verify_run
from sealedrun.schema import validate_extensions
from sealedrun_recorder.db import make_engine, session_factory
from sealedrun_recorder.keystore import load_identity
from sealedrun_recorder.live import LiveRunError, LiveRuns
from sealedrun_recorder.proxy import RunGrouper

UPSTREAMS = """
upstreams:
  - name: cloudai
    url: https://cloud.example/v1
    dialect: openai
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["gpt-*", "text-embedding-*", "kimi-*"]
  - name: claude
    url: https://anthropic.example
    dialect: anthropic
    location: cloud
    models: ["claude-*", "kimi-*"]
  - name: local
    url: http://127.0.0.1:11434/v1
    dialect: openai
    location: local
    models: ["*:*"]
  - name: keyless
    url: https://nokey.example/v1
    dialect: openai
    key_env: SEALEDRUN_TEST_UNSET_KEY
    location: cloud
    models: ["nokey-*"]
  - name: routed
    url: https://router.example/api/v1
    dialect: openai
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["*/*"]
    headers:
      X-Title: SealedRun
"""

CHAT_REPLY = {
    "id": "chatcmpl-1",
    "object": "chat.completion",
    "model": "gpt-4.1-2025-04-14",
    "choices": [
        {
            "index": 0,
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "read_file"}}],
            },
        }
    ],
    "usage": {"prompt_tokens": 41, "completion_tokens": 12, "total_tokens": 53},
}
RESPONSES_REPLY = {
    "id": "resp_1",
    "object": "response",
    "model": "gpt-5-2026-01-01",
    "status": "completed",
    "output": [
        {"type": "reasoning", "id": "rs_1", "summary": []},
        {
            "type": "function_call",
            "id": "fc_1",
            "call_id": "c1",
            "name": "search",
            "arguments": "{}",
        },
        {"type": "message", "id": "m1", "role": "assistant", "content": []},
    ],
    "usage": {"input_tokens": 30, "output_tokens": 9, "total_tokens": 39},
}
DECISIONS_REPLY = {
    "answers": [
        {"type": "predicate", "name": "touches_prod", "probability": 0.93},
        {
            "type": "choice",
            "name": "team",
            "choice": "engineering",
            "probabilities": [
                {"value": "billing", "probability": 0.05},
                {"value": "engineering", "probability": 0.95},
            ],
            "confidence": 0.9,
        },
    ]
}
DECISIONS_BODY = {
    "model": "gpt-6-luna",
    "input": "rm -rf /var/lib/postgres on prod-db-1",
    "questions": [
        {"type": "predicate", "name": "touches_prod", "instructions": "Touches production?"},
        {
            "type": "choice",
            "name": "team",
            "instructions": "Which team?",
            "choices": [{"value": "billing"}, {"value": "engineering"}],
        },
    ],
}
EMBEDDINGS_REPLY = {
    "object": "list",
    "data": [{"object": "embedding", "index": 0, "embedding": [0.1, 0.2]}],
    "model": "text-embedding-3-small",
    "usage": {"prompt_tokens": 5, "total_tokens": 5},
}


def _models(request: httpx.Request) -> httpx.Response:
    ids = {"cloud.example": ["gpt-4.1", "dall-e-3"], "127.0.0.1": ["llama3.2:3b"]}
    data = [{"id": i} for i in ids.get(request.url.host, [])]
    return httpx.Response(200, json={"object": "list", "data": data})


@pytest.fixture
def proxy(make_proxy: Callable[..., TestClient], upstream: Any) -> Iterator[TestClient]:
    upstream.routes.update(
        {
            "/chat/completions": CHAT_REPLY,
            "/responses": RESPONSES_REPLY,
            "/embeddings": EMBEDDINGS_REPLY,
            "/decisions": DECISIONS_REPLY,
            "/models": _models,
        }
    )
    with make_proxy(UPSTREAMS) as client:
        yield client


@pytest.fixture
def auth(secrets: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {secrets['token']}"}


def _chat(
    client: TestClient, auth: dict[str, str], model: str = "gpt-4.1", **headers: str
) -> httpx.Response:
    body = {"model": model, "messages": [{"role": "user", "content": "hi"}], "temperature": 0}
    return client.post("/v1/chat/completions", json=body, headers={**auth, **headers})


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
    assert str(sent.url) == "https://cloud.example/v1/chat/completions"
    assert sent.headers["authorization"] == f"Bearer {secrets['upstream_key']}"

    records = proxy_records(proxy)
    assert [r["kind"] for r in records] == ["run_start", "llm_call"]
    call = records[1]
    assert call["outcome"] == "success"
    assert call["target"] == {
        "type": "model",
        "name": "gpt-4.1",
        "endpoint": "https://cloud.example/v1/chat/completions",
        "location": "cloud",
        "provider": "cloudai",
    }
    assert call["extensions"]["sealedrun.llm"] == {
        "model": "gpt-4.1-2025-04-14",
        "provider": "cloudai",
        "stream": False,
        "temperature": 0,
        "input_tokens": 41,
        "output_tokens": 12,
        "finish_reason": "tool_calls",
        "tool_calls_requested": ["read_file"],
    }
    assert call["extensions"]["sealedrun.proxy"]["status"] == 200
    assert call["extensions"]["sealedrun.proxy"]["operation"] == "chat"
    assert validate_extensions(call["extensions"]) == []

    stored = proxy.get(f"/api/records/{call['record_id']}/payload/request", headers=auth)
    assert json.loads(stored.content)["messages"][0]["content"] == "hi"
    stored = proxy.get(f"/api/records/{call['record_id']}/payload/response", headers=auth)
    assert json.loads(stored.content) == CHAT_REPLY
    delegation = proxy.get("/api/identity", headers=auth).json()["delegation"]
    verify_run(records, {delegation["delegation_id"]: delegation})


def test_responses_api_recorded_with_usage(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    body = {"model": "gpt-5", "input": "find it", "tools": [{"type": "function", "name": "search"}]}
    response = proxy.post("/v1/responses", json=body, headers=auth)
    assert response.status_code == 200
    assert str(upstream.calls[0].url) == "https://cloud.example/v1/responses"
    call = proxy_records(proxy)[1]
    assert call["extensions"]["sealedrun.llm"] == {
        "model": "gpt-5-2026-01-01",
        "provider": "cloudai",
        "stream": False,
        "input_tokens": 30,
        "output_tokens": 9,
        "finish_reason": "completed",
        "tool_calls_requested": ["search"],
    }
    assert call["extensions"]["sealedrun.proxy"]["operation"] == "responses"
    assert validate_extensions(call["extensions"]) == []


def test_incomplete_response_reason(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/responses"] = {
        "model": "gpt-5",
        "status": "incomplete",
        "incomplete_details": {"reason": "max_output_tokens"},
        "output": [],
    }
    proxy.post("/v1/responses", json={"model": "gpt-5", "input": "x"}, headers=auth)
    assert proxy_records(proxy)[1]["extensions"]["sealedrun.llm"]["finish_reason"] == (
        "max_output_tokens"
    )


def test_credentials_never_recorded(
    proxy: TestClient, auth: dict[str, str], secrets: dict[str, str], stored_text: Any
) -> None:
    _chat(proxy, auth)
    proxy.post(
        "/v1/embeddings", json={"model": "text-embedding-3-small", "input": "x"}, headers=auth
    )
    proxy.post("/v1/responses", json={"model": "gpt-5", "input": "x"}, headers=auth)
    stored = stored_text(proxy)
    assert secrets["token"] not in stored
    assert secrets["upstream_key"] not in stored
    assert "authorization" not in stored.lower()


def test_embeddings_recorded_with_usage(
    proxy: TestClient, auth: dict[str, str], proxy_records: Any
) -> None:
    response = proxy.post(
        "/v1/embeddings", json={"model": "text-embedding-3-small", "input": "x"}, headers=auth
    )
    assert response.status_code == 200
    llm = proxy_records(proxy)[1]["extensions"]["sealedrun.llm"]
    assert llm["input_tokens"] == 5
    assert "output_tokens" not in llm
    assert "finish_reason" not in llm


def test_decisions_forwarded_unchanged_and_recorded(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    response = proxy.post("/v1/decisions", json=DECISIONS_BODY, headers=auth)
    assert response.status_code == 200
    assert response.json() == DECISIONS_REPLY
    sent = upstream.calls[0]
    assert str(sent.url) == "https://cloud.example/v1/decisions"
    assert json.loads(sent.content) == DECISIONS_BODY
    call = proxy_records(proxy)[1]
    assert call["kind"] == "llm_call"
    assert call["outcome"] == "success"
    assert call["target"]["endpoint"] == "https://cloud.example/v1/decisions"
    assert call["extensions"]["sealedrun.llm"] == {
        "model": "gpt-6-luna",
        "provider": "cloudai",
        "stream": False,
    }
    assert call["extensions"]["sealedrun.proxy"]["operation"] == "decisions"
    assert validate_extensions(call["extensions"]) == []
    stored = proxy.get(f"/api/records/{call['record_id']}/payload/response", headers=auth)
    assert json.loads(stored.content) == DECISIONS_REPLY


def test_decisions_answers_are_extracted_and_the_record_id_returned(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    response = proxy.post("/v1/decisions", json=DECISIONS_BODY, headers=auth)
    call = proxy_records(proxy)[1]
    assert response.headers["x-sealedrun-record"] == call["record_id"]
    assert call["extensions"]["sealedrun.decision"] == {
        "answers": [
            {"name": "touches_prod", "type": "predicate", "value": 0.93},
            {
                "name": "team",
                "type": "choice",
                "value": "engineering",
                "confidence": 0.9,
                "probabilities": {"billing": 0.05, "engineering": 0.95},
            },
        ]
    }
    assert validate_extensions(call["extensions"]) == []


def test_decisions_refusal_keeps_the_question_type_and_errors_carry_no_answers(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/decisions"] = {
        "answers": [
            {"type": "refusal", "name": "team", "refusal": "unsafe"},
            {"type": "score", "name": "severity", "score": 3, "confidence": 0.8},
            {"type": "mystery", "name": "x"},
        ]
    }
    proxy.post("/v1/decisions", json=DECISIONS_BODY, headers=auth)
    assert proxy_records(proxy)[1]["extensions"]["sealedrun.decision"]["answers"] == [
        {"name": "team", "type": "choice", "refused": True},
        {"name": "severity", "type": "score", "value": 3, "confidence": 0.8},
    ]
    upstream.routes["/decisions"] = {"error": {"message": "overloaded"}}
    upstream.fail = "500"
    proxy.post("/v1/decisions", json=DECISIONS_BODY, headers=auth)
    assert "sealedrun.decision" not in proxy_records(proxy)[2]["extensions"]


def test_decisions_usage_and_refusal_when_present(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.routes["/decisions"] = {
        "model": "gpt-6-luna-2026-09-22",
        "answers": [{"type": "refusal", "name": "touches_prod", "refusal": "unsafe"}],
        "usage": {"input_tokens": 77, "output_tokens": 0},
    }
    response = proxy.post("/v1/decisions", json=DECISIONS_BODY, headers=auth)
    assert response.status_code == 200
    llm = proxy_records(proxy)[1]["extensions"]["sealedrun.llm"]
    assert llm["model"] == "gpt-6-luna-2026-09-22"
    assert llm["input_tokens"] == 77
    assert llm["output_tokens"] == 0
    assert llm["finish_reason"] == "refusal"


def test_decisions_never_stream(proxy: TestClient, auth: dict[str, str]) -> None:
    response = proxy.post("/v1/decisions", json={**DECISIONS_BODY, "stream": True}, headers=auth)
    assert response.status_code == 400
    assert "streaming is not supported" in response.json()["error"]["message"]


def test_decisions_upstream_error_and_unknown_model(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.fail = "503"
    response = proxy.post("/v1/decisions", json=DECISIONS_BODY, headers=auth)
    assert response.status_code == 503
    call = proxy_records(proxy)[1]
    assert call["outcome"] == "error"
    assert call["extensions"]["sealedrun.proxy"] | {"latency_ms": 0} == {
        "upstream": "cloudai",
        "dialect": "openai",
        "operation": "decisions",
        "status": 503,
        "latency_ms": 0,
    }
    upstream.fail = None
    body = {**DECISIONS_BODY, "model": "luna-unknown"}
    assert proxy.post("/v1/decisions", json=body, headers=auth).status_code == 404


def test_upstream_error_passed_through_and_recorded(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.fail = "429"
    response = _chat(proxy, auth)
    assert response.status_code == 429
    assert response.json()["error"]["message"] == "upstream failed"
    call = proxy_records(proxy)[1]
    assert call["outcome"] == "error"
    assert call["extensions"]["sealedrun.proxy"]["status"] == 429


def test_unreachable_upstream_is_502_and_recorded(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    upstream.fail = "down"
    response = _chat(proxy, auth)
    assert response.status_code == 502
    assert "unreachable" in response.json()["error"]["message"]
    call = proxy_records(proxy)[1]
    assert call["outcome"] == "error"
    assert call["extensions"]["sealedrun.proxy"]["status"] == 502


def test_model_of_another_format_refused(
    proxy: TestClient, upstream: Any, auth: dict[str, str]
) -> None:
    response = _chat(proxy, auth, model="claude-sonnet-5")
    assert response.status_code == 400
    assert "anthropic" in response.json()["error"]["message"]
    assert upstream.calls == []


def test_same_model_reachable_through_its_openai_upstream(
    proxy: TestClient, upstream: Any, auth: dict[str, str]
) -> None:
    assert _chat(proxy, auth, model="kimi-k2.6").status_code == 200
    assert upstream.calls[0].url.host == "cloud.example"


def test_missing_upstream_key_refused_without_forwarding(
    proxy: TestClient, upstream: Any, auth: dict[str, str]
) -> None:
    response = _chat(proxy, auth, model="nokey-1")
    assert response.status_code == 503
    assert "SEALEDRUN_TEST_UNSET_KEY" not in response.text
    assert "not configured" in response.json()["error"]["message"]
    assert upstream.calls == []


def test_static_headers_and_passthrough(
    proxy: TestClient, upstream: Any, auth: dict[str, str], secrets: dict[str, str]
) -> None:
    _chat(proxy, auth, model="vendor/model-x", **{"OpenAI-Beta": "assistants=v2", "Cookie": "a=b"})
    sent = upstream.calls[0]
    assert str(sent.url) == "https://router.example/api/v1/chat/completions"
    assert sent.headers["x-title"] == "SealedRun"
    assert sent.headers["openai-beta"] == "assistants=v2"
    assert sent.headers["authorization"] == f"Bearer {secrets['upstream_key']}"
    assert "cookie" not in sent.headers
    assert "x-sealedrun-run" not in sent.headers


def test_unknown_model_and_bad_bodies(
    proxy: TestClient, upstream: Any, auth: dict[str, str]
) -> None:
    assert _chat(proxy, auth, model="mistral-large").status_code == 404
    post = proxy.post
    assert post("/v1/chat/completions", content=b"{", headers=auth).status_code == 400
    assert post("/v1/chat/completions", content=b"[1]", headers=auth).status_code == 400
    assert post("/v1/chat/completions", json={"x": 1}, headers=auth).status_code == 400
    assert upstream.calls == []
    assert proxy.get("/api/runs", headers=auth).json() == []


def test_body_size_limit(
    make_proxy: Callable[..., TestClient], upstream: Any, auth: dict[str, str]
) -> None:
    with make_proxy(UPSTREAMS, proxy_max_body_bytes=100) as client:
        assert _chat(client, auth, model="gpt-" + "x" * 200).status_code == 413
    assert upstream.calls == []


@pytest.mark.parametrize(
    "headers",
    [{}, {"Authorization": "Bearer wrong"}, {"x-api-key": "wrong"}, {"Authorization": "Basic x"}],
)
def test_proxy_needs_the_token(proxy: TestClient, upstream: Any, headers: dict[str, str]) -> None:
    body = {"model": "gpt-4.1", "messages": []}
    assert proxy.post("/v1/chat/completions", json=body, headers=headers).status_code == 401
    assert proxy.post("/v1/responses", json=body, headers=headers).status_code == 401
    assert proxy.get("/v1/models", headers=headers).status_code == 401
    assert upstream.calls == []


@pytest.mark.parametrize("header", ["x-api-key", "api-key", "x-goog-api-key"])
def test_token_accepted_in_sdk_key_headers(
    proxy: TestClient, secrets: dict[str, str], header: str
) -> None:
    body = {"model": "gpt-4.1", "messages": []}
    headers = {header: secrets["token"]}
    assert proxy.post("/v1/chat/completions", json=body, headers=headers).status_code == 200


def test_query_key_only_on_gemini_paths(proxy: TestClient, secrets: dict[str, str]) -> None:
    body = {"model": "gpt-4.1", "messages": []}
    url = f"/v1/chat/completions?key={secrets['token']}"
    assert proxy.post(url, json=body).status_code == 401


def test_proxy_closed_without_configured_token(
    make_proxy: Callable[..., TestClient], upstream: Any
) -> None:
    with make_proxy(UPSTREAMS, api_token=None) as client:
        body = {"model": "gpt-4.1", "messages": []}
        assert client.post("/v1/chat/completions", json=body).status_code == 503
    assert upstream.calls == []


def test_models_merged_and_filtered(proxy: TestClient, upstream: Any, auth: dict[str, str]) -> None:
    response = proxy.get("/v1/models", headers=auth)
    assert response.status_code == 200
    assert [m["id"] for m in response.json()["data"]] == ["gpt-4.1", "llama3.2:3b"]
    assert "nokey.example" not in {c.url.host for c in upstream.calls}


def test_local_upstream_gets_no_key(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    assert _chat(proxy, auth, model="llama3.2:3b").status_code == 200
    assert "authorization" not in upstream.calls[0].headers
    assert proxy_records(proxy)[1]["target"]["location"] == "local"


def test_labelled_calls_share_a_run(proxy: TestClient, auth: dict[str, str]) -> None:
    _chat(proxy, auth, **{"X-SealedRun-Run": "job-1"})
    _chat(proxy, auth, **{"X-SealedRun-Run": "job-1"})
    _chat(proxy, auth, **{"X-SealedRun-Run": "job-2"})
    runs = proxy.get("/api/runs", headers=auth).json()
    assert sorted(r["record_count"] for r in runs) == [2, 3]
    assert {r["run_label"]: r["record_count"] for r in runs} == {"job-1": 3, "job-2": 2}
    one = proxy.get(f"/api/runs/{runs[0]['run_id']}", headers=auth).json()
    assert one["run_label"] == runs[0]["run_label"]
    assert _chat(proxy, auth, **{"X-SealedRun-Run": "bad label!"}).status_code == 400
    _chat(proxy, auth)
    unlabelled = [r for r in proxy.get("/api/runs", headers=auth).json() if r["run_label"] is None]
    assert len(unlabelled) == 1


def test_record_failure_fails_the_call(
    proxy: TestClient, auth: dict[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    live: LiveRuns = proxy.app.state.live  # type: ignore[attr-defined]

    def broken(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("disk full")

    monkeypatch.setattr(live, "append", broken)
    failing = TestClient(proxy.app, base_url="http://localhost", raise_server_exceptions=False)
    assert _chat(failing, auth).status_code == 500


def test_idle_default_run_is_closed_and_replaced(tmp_path: Path) -> None:
    live = LiveRuns(
        session_factory(make_engine(f"sqlite:///{tmp_path / 'db.sqlite'}")),
        load_identity(tmp_path),
    )
    now = [0.0]
    runs = RunGrouper(live, idle_seconds=10, clock=lambda: now[0])
    first = runs.run_for(None)
    now[0] = 5
    assert runs.run_for(None) == first
    now[0] = 16
    second = runs.run_for(None)
    assert second != first
    with pytest.raises(LiveRunError, match="closed"):
        live.append(first, "note", target={"type": "none", "name": "late"})
    live.end(second)
    assert runs.record(None, "note", target={"type": "none", "name": "x"})["run_id"] != second


def test_ratelimit_headers_reach_the_client(
    proxy: TestClient, upstream: Any, auth: dict[str, str]
) -> None:
    headers = {
        "x-ratelimit-remaining-requests": "99",
        "x-ratelimit-reset-tokens": "6ms",
        "x-request-id": "req_1",
        "retry-after": "3",
        "openai-organization": "org-secret",
        "set-cookie": "sticky=1",
    }
    upstream.routes["/chat/completions"] = lambda request: httpx.Response(
        200, json=CHAT_REPLY, headers=headers
    )
    response = _chat(proxy, auth)
    assert response.status_code == 200
    assert response.headers["x-ratelimit-remaining-requests"] == "99"
    assert response.headers["x-ratelimit-reset-tokens"] == "6ms"
    assert response.headers["x-request-id"] == "req_1"
    assert response.headers["retry-after"] == "3"
    assert "openai-organization" not in response.headers
    assert "set-cookie" not in response.headers


def test_system_prompt_is_hashed_not_stored_in_the_extension(
    proxy: TestClient, upstream: Any, auth: dict[str, str], proxy_records: Any
) -> None:
    from sealedrun import payload_digest

    body = {
        "model": "gpt-4.1",
        "messages": [
            {"role": "system", "content": "You summarise contracts."},
            {"role": "user", "content": "hi"},
        ],
    }
    assert proxy.post("/v1/chat/completions", json=body, headers=auth).status_code == 200
    plain = _chat(proxy, auth)
    assert plain.status_code == 200
    records = proxy_records(proxy)
    first, second = (
        records[1]["extensions"]["sealedrun.llm"],
        records[2]["extensions"]["sealedrun.llm"],
    )
    assert first["system_prompt_hash"] == payload_digest(
        records[1]["hash_alg"], b"You summarise contracts."
    )
    assert "system_prompt_hash" not in second
    assert "You summarise contracts." not in json.dumps(first)
