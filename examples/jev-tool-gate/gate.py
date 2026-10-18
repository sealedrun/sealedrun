"""Gate a shell command behind a decision model and leave the verdict in a signed run.

The agent wants to run a command. Before it does, Jev (TypeSafe's decision model, served by
OpenRouter) answers two typed questions about the command: does it touch production data, and
how severe is it. Both the model's answer and what this program did with it land in one run on
the recorder: the decision call as an `llm_call` with `sealedrun.decision`, the verdict as a
`policy_decision` step with `sealedrun.gate`, and the command as a `tool_call` that ran or was
refused.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import urllib.request
from typing import Any

from sealedrun import Recorder

RECORDER = os.environ.get("SEALEDRUN_URL", "http://127.0.0.1:8080")
TOKEN = os.environ.get("SEALEDRUN_TOKEN", "")
RUN = os.environ.get("SEALEDRUN_RUN", "jev-tool-gate")
MODEL = os.environ.get("MODEL", "typesafe/jev-1.14")
THRESHOLDS = {"touches_prod": 0.5, "severity": 1.5}
SEVERITY = ["harmless", "recoverable", "destructive"]


def questions_for(command: str, host: str) -> dict[str, Any]:
    """Build the decision request for `command` on `host`: state plus two typed questions."""
    return {
        "model": MODEL,
        "state": {"tool": "shell", "command": command, "host": host},
        "questions": {
            "touches_prod": {
                "type": "noul",
                "instructions": "Does the command alter or destroy production data?",
                "criteria": {
                    "true": "writes to, deletes or truncates data a production service uses",
                    "false": "reads only, or touches scratch and test data",
                },
            },
            "severity": {
                "type": "score",
                "instructions": "How severe is the worst outcome of running this command?",
                "criteria": SEVERITY,
            },
        },
    }


def ask(body: dict[str, Any]) -> tuple[dict[str, Any], str]:
    """Send the decision call through the recorder; return the answers and the record id."""
    request = urllib.request.Request(  # noqa: S310
        f"{RECORDER}/api/v1/systemone",
        data=json.dumps(body).encode(),
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
            "X-SealedRun-Run": RUN,
        },
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=30) as reply:  # noqa: S310
        answers = json.load(reply)["answers"]
        return answers, reply.headers["X-SealedRun-Record"]


def verdict_for(answers: dict[str, Any]) -> tuple[str, str]:
    """Apply the thresholds: block on production data, review on severe, approve otherwise."""
    touches_prod = float(answers["touches_prod"]["noul"])
    severity = float(answers["severity"]["score"])
    if touches_prod > THRESHOLDS["touches_prod"]:
        return "block", f"touches_prod {touches_prod:.2f} above {THRESHOLDS['touches_prod']}"
    if severity > THRESHOLDS["severity"]:
        return "review", f"severity {severity:.2f} above {THRESHOLDS['severity']}"
    return "approve", f"touches_prod {touches_prod:.2f}, severity {severity:.2f}"


def run_tool(recorder: Recorder, command: str, parent: str, verdict: str) -> int:
    """Run `command` when approved, else record it as refused; return the exit code."""
    if verdict != "approve":
        recorder.record(
            "tool_call",
            "shell",
            request=command,
            outcome="blocked",
            parent_record_id=parent,
        )
        return 1
    result = subprocess.run(  # noqa: S602
        command, shell=True, capture_output=True, text=True, check=False
    )
    recorder.record(
        "tool_call",
        "shell",
        request=command,
        response={"exit_code": result.returncode, "stdout": result.stdout[-4000:]},
        outcome="success" if result.returncode == 0 else "error",
        parent_record_id=parent,
    )
    return result.returncode


def main(argv: list[str]) -> int:
    """Gate and run the command given on the command line."""
    if len(argv) < 2:
        print("usage: gate.py <command> [host]", file=sys.stderr)
        return 2
    command, host = argv[1], argv[2] if len(argv) > 2 else "prod-db-1"
    answers, decision_id = ask(questions_for(command, host))
    verdict, reason = verdict_for(answers)
    recorder = Recorder(RECORDER, token=TOKEN, run=RUN)
    gate = recorder.record_gate(decision_id, verdict, thresholds=THRESHOLDS, reason=reason)
    print(f"{verdict}: {reason} (decision {decision_id[:8]}, gate step {gate['seq']})")
    return run_tool(recorder, command, str(gate["record_id"]), verdict)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
