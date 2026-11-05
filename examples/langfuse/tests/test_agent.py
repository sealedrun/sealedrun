"""The agent sends the Langfuse trace id as the run label; no model, recorder or Langfuse."""

import json
import os
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

os.environ.setdefault("LANGFUSE_PUBLIC_KEY", "pk-lf-test")
os.environ.setdefault("LANGFUSE_SECRET_KEY", "sk-lf-test")
os.environ.setdefault("LANGFUSE_BASE_URL", "http://127.0.0.1:9")

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import agent

REPLY = {
    "id": "chatcmpl-1",
    "object": "chat.completion",
    "created": 0,
    "model": "qwen3:8b",
    "choices": [
        {"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": "ok"}}
    ],
    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
}


class FakeProxy:
    """Answers `/v1/chat/completions` like the recorder's LLM proxy and keeps what it got."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str], dict[str, Any]]] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                headers = {name.lower(): value for name, value in self.headers.items()}
                fake.calls.append((self.path, headers, body))
                data = json.dumps(REPLY).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args: Any) -> None:
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()


@pytest.fixture
def proxy(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeProxy]:
    fake = FakeProxy()
    monkeypatch.setattr(agent, "RECORDER", fake.url)
    monkeypatch.setattr(agent, "TOKEN", "tok")
    yield fake
    fake.close()


def test_trace_id_is_the_run_label(proxy: FakeProxy) -> None:
    answer, trace_id = agent.ask("why?")
    [(path, headers, body)] = proxy.calls
    assert answer == "ok"
    assert path == "/v1/chat/completions"
    assert len(trace_id) == 32
    assert int(trace_id, 16) > 0
    assert headers["x-sealedrun-run"] == trace_id
    assert headers["authorization"] == "Bearer tok"
    assert body["messages"] == [{"role": "user", "content": "why?"}]


def test_each_call_gets_its_own_run(proxy: FakeProxy) -> None:
    first = agent.ask("one")[1]
    second = agent.ask("two")[1]
    assert first != second
    assert [headers["x-sealedrun-run"] for _, headers, _ in proxy.calls] == [first, second]
