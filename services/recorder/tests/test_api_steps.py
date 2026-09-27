import base64
import json
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sealedrun import verify_run
from sealedrun_recorder.db import RecordRow, RunRow

CONFIG = """
upstreams:
  - name: cloudai
    url: https://cloud.example/v1
    dialect: openai
    key_env: TEST_UPSTREAM_KEY
    location: cloud
    models: ["gpt-*"]
"""
CHAT_REPLY = {
    "id": "chatcmpl-1",
    "object": "chat.completion",
    "model": "gpt-4.1",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "ok"}}],
    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
}
REQUEST = {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "add"}}
RESPONSE = {"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": "3"}]}}


def _step(**overrides: Any) -> dict[str, Any]:
    step = {
        "kind": "tool_call",
        "target": {
            "type": "tool",
            "name": "add",
            "endpoint": "python server.py",
            "location": "local",
            "provider": "mcp:calc",
        },
        "outcome": "success",
        "request": json.dumps(REQUEST),
        "response": json.dumps(RESPONSE),
        "request_media_type": "application/json",
        "response_media_type": "application/json",
        "extensions": {
            "sealedrun.mcp": {
                "server": "calc",
                "transport": "stdio",
                "method": "tools/call",
                "request_id": 3,
                "is_error": False,
                "tool": "add",
            },
            "sealedrun.proxy": {"upstream": "calc", "dialect": "mcp", "operation": "tools/call"},
        },
    }
    step.update(overrides)
    return step


@pytest.fixture
def client(make_proxy: Callable[..., TestClient], upstream: Any) -> Iterator[TestClient]:
    upstream.routes["/chat/completions"] = CHAT_REPLY
    with make_proxy(CONFIG) as client:
        yield client


@pytest.fixture
def api(secrets: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {secrets['token']}"}


def _runs(client: TestClient) -> list[RunRow]:
    with client.app.state.live._sessions() as session:  # type: ignore[attr-defined]
        return list(session.query(RunRow).all())


def _records(client: TestClient, run_id: str) -> list[dict[str, Any]]:
    with client.app.state.live._sessions() as session:  # type: ignore[attr-defined]
        rows = session.query(RecordRow).filter_by(run_id=run_id).order_by(RecordRow.seq)
        return [row.document for row in rows]


def _post(client: TestClient, api: dict[str, str], step: dict[str, Any], **headers: str) -> Any:
    return client.post("/api/steps", json=step, headers={**api, **headers})


def test_step_is_sealed_with_its_payloads(client: TestClient, api: dict[str, str]) -> None:
    reply = _post(client, api, _step(), **{"X-SealedRun-Run": "job-1"})
    assert reply.status_code == 201, reply.text
    record = reply.json()
    assert record["kind"] == "tool_call"
    assert record["target"]["provider"] == "mcp:calc"
    assert record["extensions"]["sealedrun.mcp"]["transport"] == "stdio"
    assert record["payload"]["request_media_type"] == "application/json"
    assert record["seq"] == 1
    request = client.get(f"/api/records/{record['record_id']}/payload/request", headers=api)
    response = client.get(f"/api/records/{record['record_id']}/payload/response", headers=api)
    assert json.loads(request.content) == REQUEST
    assert json.loads(response.content) == RESPONSE
    [run] = _runs(client)
    assert run.run_label == "job-1"
    records = _records(client, run.run_id)
    delegation = client.get("/api/identity", headers=api).json()["delegation"]
    verify_run(records, {delegation["delegation_id"]: delegation})


def test_label_joins_the_run_of_a_proxied_llm_call(
    client: TestClient, api: dict[str, str], secrets: dict[str, str]
) -> None:
    body = {"model": "gpt-4.1", "messages": [{"role": "user", "content": "hi"}]}
    headers = {"X-SealedRun-Token": secrets["token"], "X-SealedRun-Run": "job-2"}
    assert client.post("/v1/chat/completions", json=body, headers=headers).status_code == 200
    assert _post(client, api, _step(), **{"X-SealedRun-Run": "job-2"}).status_code == 201
    assert _post(client, api, _step(), **{"X-SealedRun-Run": "job-3"}).status_code == 201
    runs = {run.run_label: run.run_id for run in _runs(client)}
    assert set(runs) == {"job-2", "job-3"}
    kinds = [r["kind"] for r in _records(client, runs["job-2"])]
    assert kinds == ["run_start", "llm_call", "tool_call"]


def test_run_id_alias_appends_to_that_run(client: TestClient, api: dict[str, str]) -> None:
    first = _post(client, api, _step(), **{"X-SealedRun-Run": "job-4"}).json()
    run_id = first["run_id"]
    reply = client.post(f"/api/runs/{run_id}/steps", json=_step(kind="note"), headers=api)
    assert reply.status_code == 201, reply.text
    assert reply.json()["run_id"] == run_id
    assert [r["kind"] for r in _records(client, run_id)] == ["run_start", "tool_call", "note"]
    assert client.post("/api/runs/nope/steps", json=_step(), headers=api).status_code == 404


def test_closed_and_imported_runs_are_refused(
    client: TestClient, api: dict[str, str], valid_zip: bytes
) -> None:
    run_id = _post(client, api, _step()).json()["run_id"]
    assert client.post(f"/api/runs/{run_id}/export?end=true", headers=api).status_code == 200
    closed = client.post(f"/api/runs/{run_id}/steps", json=_step(), headers=api)
    assert closed.status_code == 409
    files = {"file": ("bundle.zip", valid_zip, "application/zip")}
    uploaded = client.post("/api/bundles", files=files, headers=api)
    assert uploaded.status_code == 201, uploaded.text
    runs = client.get("/api/runs", headers=api).json()
    [foreign] = [r for r in runs if r["source"] == "imported"]
    reply = client.post(f"/api/runs/{foreign['run_id']}/steps", json=_step(), headers=api)
    assert reply.status_code == 409


@pytest.mark.parametrize(
    ("step", "fragment"),
    [
        (_step(kind="run_end"), "kind"),
        (_step(kind="anchor"), "kind"),
        (_step(outcome="maybe"), "outcome"),
        (_step(target={"type": "tool"}), "target"),
        (_step(target={"type": "robot", "name": "x"}), "target"),
        (_step(extensions={"sealedrun.mcp": {"server": "calc"}}), "sealedrun.mcp"),
        (_step(unknown_field=1), "unknown_field"),
        (_step(request_base64="not base64!"), "base64"),
        (_step(request_base64="AA==", request="x"), "exclusive"),
        (_step(data_labels=[""]), "data_labels"),
        (_step(occurred_at="2026-09-27T10:00:00Z"), "occurred_at"),
        (_step(data_labels=["PII"]), "would not verify"),
        (_step(parent_record_id="nope"), "would not verify"),
        (_step(extensions={"foo": {}}), "would not verify"),
        (_step(kind="human_approval"), "would not verify"),
        (
            _step(
                kind="human_approval", actor={"type": "human", "id": "x"}, target={"type": "tool"}
            ),
            "target",
        ),
        (
            _step(
                policy={"rule_id": "r", "decision": "block", "reason": "no"},
                outcome="success",
            ),
            "would not verify",
        ),
    ],
)
def test_bad_steps_are_refused_and_leave_the_chain_untouched(
    client: TestClient, api: dict[str, str], step: dict[str, Any], fragment: str
) -> None:
    reply = _post(client, api, step)
    assert reply.status_code == 400, reply.text
    assert fragment in reply.json()["detail"]
    for run in _runs(client):
        assert [r["kind"] for r in _records(client, run.run_id)] == ["run_start"]


def test_non_json_bodies_are_refused(client: TestClient, api: dict[str, str]) -> None:
    headers = {**api, "Content-Type": "application/json"}
    assert client.post("/api/steps", content=b"{", headers=headers).status_code == 400
    assert client.post("/api/steps", content=b"[]", headers=headers).status_code == 400
    bad_label = {**api, "X-SealedRun-Run": "a b"}
    assert client.post("/api/steps", json=_step(), headers=bad_label).status_code == 400


def test_auth_and_origin_rules_apply(client: TestClient, secrets: dict[str, str]) -> None:
    assert client.post("/api/steps", json=_step()).status_code == 401
    wrong = {"Authorization": "Bearer nope"}
    assert client.post("/api/steps", json=_step(), headers=wrong).status_code == 401
    cross = {"Authorization": f"Bearer {secrets['token']}", "Sec-Fetch-Site": "cross-site"}
    assert client.post("/api/steps", json=_step(), headers=cross).status_code == 403
    assert _runs(client) == []


def test_oversize_step_is_refused(
    make_proxy: Callable[..., TestClient], api: dict[str, str]
) -> None:
    with make_proxy(CONFIG, proxy_max_body_bytes=2048) as client:
        big = _step(response="x" * 4096)
        assert _post(client, api, big).status_code == 413
        assert _runs(client) == []


def test_base64_payload_round_trips(client: TestClient, api: dict[str, str]) -> None:
    raw = bytes(range(256))
    step = _step(
        response=None,
        response_base64=base64.b64encode(raw).decode(),
        response_media_type="application/octet-stream",
    )
    record = _post(client, api, step).json()
    stored = client.get(f"/api/records/{record['record_id']}/payload/response", headers=api)
    assert stored.content == raw
    assert record["payload"]["response_size"] == 256


def test_policy_and_labels_are_kept(client: TestClient, api: dict[str, str]) -> None:
    step = _step(
        policy={"rule_id": "default", "decision": "allow", "reason": "no labels"},
        data_labels=["pii", "pii", "nda"],
    )
    reply = _post(client, api, step)
    assert reply.status_code == 201, reply.text
    record = reply.json()
    assert record["policy"]["decision"] == "allow"
    assert record["data_labels"] == ["nda", "pii"]


def _listing(cursor: str | None = None, tools: list[str] | None = None) -> dict[str, Any]:
    params: dict[str, Any] = {"cursor": cursor} if cursor else {}
    request = {"jsonrpc": "2.0", "id": 9, "method": "tools/list", "params": params}
    response = {
        "jsonrpc": "2.0",
        "id": 9,
        "result": {"tools": [{"name": t} for t in tools or ["add"]]},
    }
    return _step(
        target={"type": "tool", "name": "tools/list", "provider": "mcp:calc"},
        request=json.dumps(request),
        response=json.dumps(response),
        extensions={
            "sealedrun.mcp": {
                "server": "calc",
                "transport": "stdio",
                "method": "tools/list",
                "request_id": 9,
                "is_error": False,
            }
        },
    )


def test_tools_list_is_recorded_once_until_it_changes(
    client: TestClient, api: dict[str, str]
) -> None:
    run = {"X-SealedRun-Run": "job-list"}
    assert _post(client, api, _listing(), **run).status_code == 201
    repeat = _post(client, api, _listing(), **run)
    assert repeat.status_code == 200
    assert repeat.json() == {"recorded": False, "reason": "tools/list result unchanged"}
    assert _post(client, api, _listing(cursor="p2"), **run).status_code == 201
    assert _post(client, api, _listing(tools=["add", "sub"]), **run).status_code == 201
    assert _post(client, api, _listing(), **{"X-SealedRun-Run": "job-other"}).status_code == 201
    run_id = next(r.run_id for r in _runs(client) if r.run_label == "job-list")
    assert [r["kind"] for r in _records(client, run_id)] == ["run_start"] + ["tool_call"] * 3
    alias = client.post(
        f"/api/runs/{run_id}/steps", json=_listing(tools=["add", "sub"]), headers=api
    )
    assert alias.status_code == 200


def test_human_approval_with_a_human_actor_is_sealed(
    client: TestClient, api: dict[str, str]
) -> None:
    step = _step(
        kind="human_approval",
        actor={"type": "human", "id": "reviewer"},
        target={"type": "human", "name": "reviewer"},
        extensions={},
        request=None,
        response=None,
        request_media_type=None,
        response_media_type=None,
    )
    reply = _post(client, api, step)
    assert reply.status_code == 201, reply.text
    assert reply.json()["actor"] == {"type": "human", "id": "reviewer"}
