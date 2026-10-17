"""The gate maps answers to verdicts and records the chain; no model or recorder needed."""

import json
import sys
import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gate

ANSWERS = {
    "touches_prod": {"type": "noul", "noul": 0.97},
    "severity": {"type": "score", "score": 1.99, "confidence": 0.99},
}


class FakeRecorder:
    """Answers the decision path like OpenRouter would and seals steps like the recorder."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.posts: list[tuple[str, dict[str, Any]]] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fake.posts.append((self.path, body))
                if self.path == "/api/v1/systemone":
                    status, reply, extra = (
                        200,
                        {"answers": answers},
                        {"X-SealedRun-Record": "dec-1"},
                    )
                else:
                    status, reply, extra = (
                        201,
                        {"record_id": f"r-{len(fake.posts)}", "seq": len(fake.posts)},
                        {},
                    )
                data = json.dumps(reply).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                for name, value in extra.items():
                    self.send_header(name, value)
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
def fake(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeRecorder]:
    server = FakeRecorder(ANSWERS)
    monkeypatch.setattr(gate, "RECORDER", server.url)
    monkeypatch.setattr(gate, "TOKEN", "change-me")
    yield server
    server.close()


def test_verdicts_follow_the_thresholds() -> None:
    assert gate.verdict_for(ANSWERS)[0] == "block"
    mild = {"touches_prod": {"noul": 0.1}, "severity": {"score": 1.8}}
    assert gate.verdict_for(mild) == ("review", "severity 1.80 above 1.5")
    safe = {"touches_prod": {"noul": 0.1}, "severity": {"score": 0.2}}
    assert gate.verdict_for(safe)[0] == "approve"


def test_blocked_command_is_recorded_and_not_run(fake: FakeRecorder, tmp_path: Path) -> None:
    marker = tmp_path / "ran"
    code = gate.main(["gate.py", f"touch {marker}", "prod-db-1"])
    assert code == 1
    assert not marker.exists()
    [decision, step, tool] = fake.posts
    assert decision[0] == "/api/v1/systemone"
    assert decision[1]["model"] == gate.MODEL
    assert set(decision[1]["questions"]) == {"touches_prod", "severity"}
    assert step[0] == "/api/steps"
    assert step[1]["kind"] == "policy_decision"
    assert step[1]["outcome"] == "blocked"
    assert step[1]["parent_record_id"] == "dec-1"
    assert step[1]["extensions"]["sealedrun.gate"]["outcome"] == "block"
    assert step[1]["extensions"]["sealedrun.gate"]["thresholds"] == gate.THRESHOLDS
    assert tool[1]["kind"] == "tool_call"
    assert tool[1]["outcome"] == "blocked"
    assert tool[1]["parent_record_id"] == "r-2"


def test_approved_command_runs_and_is_recorded(
    fake: FakeRecorder, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setitem(ANSWERS["touches_prod"], "noul", 0.02)
    monkeypatch.setitem(ANSWERS["severity"], "score", 0.1)
    marker = tmp_path / "ran"
    assert gate.main(["gate.py", f"touch {marker}", "ci-box"]) == 0
    assert marker.exists()
    [_, step, tool] = fake.posts
    assert step[1]["outcome"] == "success"
    assert step[1]["extensions"]["sealedrun.gate"]["outcome"] == "approve"
    assert tool[1]["outcome"] == "success"
    assert json.loads(tool[1]["response"])["exit_code"] == 0
