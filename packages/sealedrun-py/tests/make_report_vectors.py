"""Write `spec/vectors/report`: bundles with the evidence report every implementation must give.

Run from `packages/sealedrun-py`: `uv run python tests/make_report_vectors.py`. `cases.json`
names each bundle and the trusted principals to verify it with; `<name>.json` is the report
data and `<name>.txt` its text. `incident.zip` is built here: an export by window and label
with a granted approval, a step outside the delegation's scope, a step without the approval
its policy required and an anchor no trusted witness signed. Its signatures are fresh on every
run, which is fine because only the committed output is used.
"""

from __future__ import annotations

import io
import json
import sys
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

from sealedrun import (
    RunWriter,
    create_delegation,
    evidence_report,
    file_sha256,
    payload_digest,
    payload_ref,
    read_bundle,
    render_report,
    verify_bundle,
    write_bundle,
)
from sealedrun.schema import SCHEMA_DIR

sys.path.insert(0, str(Path(__file__).parent))
from conftest import START, Clock, seeded

VECTORS = SCHEMA_DIR.parent / "vectors"
OUT = VECTORS / "report"
PREFIX = "0192b3c4-5d6e-7f80-9a1b-"
LABEL = "billing-agent"
ALG = "sha-256"
ADD = {"type": "tool", "name": "add", "location": "local"}
MAIL = {"type": "tool", "name": "mail/send", "location": "cloud", "provider": "mcp:mail"}
SHELL = {"type": "tool", "name": "shell/exec", "location": "local"}
REQUIRE = {
    "rule_id": "finance/require-approval",
    "decision": "require_approval",
    "reason": "payment instruction leaves the company",
}
APPROVED = b'{"to":"bank@example.com","amount":120}'
UNAPPROVED = b'{"to":"bank@example.com","amount":98000}'
SENT = b'{"status":"sent"}'


def _ids(start: int) -> Callable[[], str]:
    counter = iter(range(start + 1, start + 0x100))
    return lambda: f"{PREFIX}{next(counter):012x}"


def _writer(delegation: dict[str, Any], run_id: str, ids: int, minutes: int) -> RunWriter:
    writer = RunWriter(
        seeded(b"agent-"),
        delegation,
        run_id=run_id,
        clock=Clock(START + timedelta(minutes=minutes)),
        id_factory=_ids(ids),
    )
    writer.start(extensions={"sealedrun.proxy": {"run_label": LABEL}})
    return writer


def _incident() -> bytes:
    delegation = create_delegation(
        seeded(b"principal-"),
        seeded(b"agent-").public,
        not_before=START - timedelta(days=1),
        not_after=START + timedelta(days=3650),
        agent_name="billing-agent",
        scope={"allowed_targets": [{"name": "add"}, {"name": "mail/send"}]},
        delegation_id=PREFIX + "0000000000c2",
    )
    first = _writer(delegation, PREFIX + "0000000000f1", 0x400, 0)
    first.append("tool_call", target=ADD)
    first.append(
        "human_approval",
        actor={"type": "human", "id": "jane.doe@example.com"},
        target=MAIL,
        payload=payload_ref(ALG, APPROVED),
        extensions={"sealedrun.approval": {"decision": "granted"}},
    )
    first.append(
        "tool_call", target=MAIL, policy=dict(REQUIRE), payload=payload_ref(ALG, APPROVED, SENT)
    )
    first.append(
        "anchor",
        target={"type": "witness", "name": "witness.example"},
        extensions={
            "sealedrun.anchor": {
                "type": "other",
                "anchored_hash": first.head,
                "anchored_seq": 3,
                "receipt": {"digest": first.head, "log_index": 7},
                "witness": "https://witness.example",
            }
        },
    )
    first.append("tool_call", target=SHELL)
    first.append(
        "tool_call", target=MAIL, policy=dict(REQUIRE), payload=payload_ref(ALG, UNAPPROVED, SENT)
    )
    first.end()
    second = _writer(delegation, PREFIX + "0000000000f2", 0x420, 10)
    second.append("tool_call", target=ADD)
    second.append("tool_call", target=ADD)
    anchors = {
        r["record_id"]: r["extensions"]["sealedrun.anchor"]["receipt"]
        for r in first.records
        if r["kind"] == "anchor"
    }
    out = io.BytesIO()
    write_bundle(
        out,
        exporter=seeded(b"agent-"),
        software="sealedrun-vectors/0.1.0",
        delegations=[delegation],
        runs=[first.records, second.records],
        payloads={payload_digest(ALG, body): body for body in (APPROVED, UNAPPROVED, SENT)},
        anchors=anchors,
        principal=seeded(b"principal-"),
        bundle_id=PREFIX + "0000000000b2",
        created_at="2026-09-16T13:00:00.000Z",
        query={
            "since": "2026-09-16T12:00:04.000Z",
            "until": "2026-09-16T12:20:00.000Z",
            "label": LABEL,
            "note": "INC-42, exported by on-call after the 98000 transfer",
        },
    )
    return out.getvalue()


def main() -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "incident.zip").write_bytes(_incident())
    keys = json.loads((VECTORS / "keys.json").read_text())
    cases = [
        {
            "name": "valid",
            "bundle": "../bundle/valid.zip",
            "trusted_principals": [keys["principal"]["kid"]],
        },
        {"name": "window-label", "bundle": "../bundle/window-label.zip"},
        {"name": "payloads-omitted", "bundle": "../bundle/payloads-omitted.zip"},
        {
            "name": "incident",
            "bundle": "incident.zip",
            "trusted_principals": [seeded(b"principal-").public.kid],
        },
    ]
    for case in cases:
        data = (OUT / case["bundle"]).read_bytes()
        bundle = read_bundle(data)
        verified = verify_bundle(bundle, case.get("trusted_principals"))
        report = evidence_report(bundle, verified, file_sha256(data))
        (OUT / f"{case['name']}.json").write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n"
        )
        (OUT / f"{case['name']}.txt").write_text(render_report(report))
    (OUT / "cases.json").write_text(json.dumps(cases, indent=2, sort_keys=True) + "\n")
    print(f"wrote {len(cases)} reports to {OUT}")


if __name__ == "__main__":
    main()
