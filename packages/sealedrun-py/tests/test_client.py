import asyncio
import json
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest
from sealedrun import Recorder, RecorderError


class FakeRecorder:
    def __init__(self) -> None:
        self.posts: list[tuple[dict[str, str], dict[str, Any]]] = []
        self.status = 201
        recorder = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length))
                recorder.posts.append(({k.lower(): v for k, v in self.headers.items()}, body))
                self.send_response(recorder.status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                answer = {"record_id": "r-1", "seq": len(recorder.posts)}
                if recorder.status >= 400:
                    answer = {"detail": "record would not verify: data_labels/0 bad"}
                self.wfile.write(json.dumps(answer).encode())

            def log_message(self, *args: Any) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def fake() -> Iterator[FakeRecorder]:
    server = FakeRecorder()
    yield server
    server.close()


@pytest.fixture
def recorder(fake: FakeRecorder) -> Recorder:
    return Recorder(fake.url, token="tok", run="job-1")


def test_record_posts_body_and_headers(fake: FakeRecorder, recorder: Recorder) -> None:
    record = recorder.record(
        "tool_call",
        "db.query",
        request="select 1",
        response={"rows": [1]},
        provider="postgres",
        data_labels=["pii"],
        extensions={"acme.sql": {"ms": 3}},
    )
    assert record == {"record_id": "r-1", "seq": 1}
    [(headers, body)] = fake.posts
    assert headers["authorization"] == "Bearer tok"
    assert headers["x-sealedrun-run"] == "job-1"
    assert headers["content-type"] == "application/json"
    assert body == {
        "kind": "tool_call",
        "target": {"type": "tool", "name": "db.query", "location": "local", "provider": "postgres"},
        "outcome": "success",
        "data_labels": ["pii"],
        "extensions": {"acme.sql": {"ms": 3}},
        "request": "select 1",
        "request_media_type": "text/plain",
        "response": '{"rows": [1]}',
        "response_media_type": "application/json",
    }


def test_target_type_follows_the_kind(fake: FakeRecorder, recorder: Recorder) -> None:
    recorder.record("memory_read", "vector-store", location="cloud", endpoint="https://v.example")
    recorder.record("llm_call", "gpt-4.1", target_type="model", provider="openai")
    recorder.record("human_approval", "reviewer", actor={"type": "human", "id": "alice"})
    targets = [body["target"] for _, body in fake.posts]
    assert targets[0] == {
        "type": "memory",
        "name": "vector-store",
        "location": "cloud",
        "endpoint": "https://v.example",
    }
    assert targets[1]["type"] == "model"
    assert targets[2]["type"] == "human"
    assert fake.posts[2][1]["actor"] == {"type": "human", "id": "alice"}


def test_step_context_posts_when_the_block_ends(fake: FakeRecorder, recorder: Recorder) -> None:
    with recorder.step("tool_call", "shell", provider="bash") as step:
        step.request = ["ls", "-la"]
        assert fake.posts == []
        step.response = b"total 0\n"
    assert step.record == {"record_id": "r-1", "seq": 1}
    [(_, body)] = fake.posts
    assert body["request"] == '["ls", "-la"]'
    assert body["response"] == "total 0\n"
    assert body["response_media_type"] == "text/plain"
    assert body["outcome"] == "success"


def test_exception_inside_step_is_recorded_and_reraised(
    fake: FakeRecorder, recorder: Recorder
) -> None:
    with pytest.raises(ZeroDivisionError):
        with recorder.step("tool_call", "calc") as step:
            step.request = {"expr": "1/0"}
            step.response = 1 / 0
    [(_, body)] = fake.posts
    assert body["outcome"] == "error"
    assert body["response"] == "ZeroDivisionError: division by zero"


def test_tool_decorator_records_sync_and_async(fake: FakeRecorder, recorder: Recorder) -> None:
    @recorder.tool()
    def add(a: int, b: int = 1) -> int:
        return a + b

    @recorder.tool("fetch", provider="http", location="cloud")
    async def fetch(url: str) -> object:
        return object()

    assert add(2, b=3) == 5
    assert add.__name__ == "add"
    result = asyncio.run(fetch("https://x.example"))
    assert result is not None
    (_, first), (_, second) = fake.posts
    assert first["target"]["name"] == "add"
    assert first["request"] == '{"a": 2, "b": 3}'
    assert first["response"] == "5"
    assert second["target"] == {
        "type": "tool",
        "name": "fetch",
        "location": "cloud",
        "provider": "http",
    }
    assert second["response"].startswith('"<object object at')
    assert second["response_media_type"] == "application/json"


def test_tool_decorator_records_a_failing_call(fake: FakeRecorder, recorder: Recorder) -> None:
    @recorder.tool()
    def boom() -> None:
        raise RuntimeError("no")

    with pytest.raises(RuntimeError):
        boom()
    [(_, body)] = fake.posts
    assert (body["outcome"], body["response"]) == ("error", "RuntimeError: no")


def test_refusal_and_unreachable_raise_without_the_token(fake: FakeRecorder) -> None:
    fake.status = 400
    recorder = Recorder(fake.url, token="secret-token", run="job-1")
    with pytest.raises(RecorderError) as refused:
        recorder.record("tool_call", "x", data_labels=["PII"])
    assert refused.value.status == 400
    assert "would not verify" in str(refused.value)
    down = Recorder("http://user:secret-token@127.0.0.1:9", token="secret-token")
    with pytest.raises(RecorderError) as unreachable:
        down.record("tool_call", "x")
    assert unreachable.value.status == 0
    assert "secret-token" not in str(unreachable.value)
    assert "secret-token" not in str(refused.value)


def test_no_token_or_label_sends_no_such_headers(fake: FakeRecorder) -> None:
    Recorder(fake.url + "/").record("note", "hello")
    [(headers, body)] = fake.posts
    assert "authorization" not in headers
    assert "x-sealedrun-run" not in headers
    assert body["target"] == {"type": "none", "name": "hello", "location": "local"}
    assert "request" not in body


def test_bad_url_is_refused() -> None:
    with pytest.raises(ValueError, match="http"):
        Recorder("ftp://x")
