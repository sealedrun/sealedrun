"""Write `spec/vectors/anchors/coverage.json`: approvals a witness saw soon, late or never.

Run from `packages/sealedrun-py`: `uv run python tests/make_anchor_coverage.py`. Every verifier
must report the `expected` part of each case (SPEC 8.2): the records after the last
witness-verified anchor, the anchor lag of each `human_approval`, and the `anchor.*` findings
under the case's limit. The file carries its own throw-away trust list; the authority's keys are
fresh on every run, which is fine because only the committed output is used.
"""

from __future__ import annotations

import json
import sys
from datetime import timedelta
from pathlib import Path
from typing import Any

from sealedrun import RunWriter, create_delegation
from sealedrun.anchors import rfc3161
from sealedrun.schema import SCHEMA_DIR
from sealedrun.timeutil import format_timestamp, parse_timestamp

sys.path.insert(0, str(Path(__file__).parent))
from conftest import START, Clock, Ids, seeded
from tsa import NOT_AFTER, NOT_BEFORE, TestAuthority

OUT = SCHEMA_DIR.parent / "vectors" / "anchors" / "coverage.json"
URL = "https://coverage.test/tsa"
HUMAN = {"actor": {"type": "human", "id": "reviewer"}, "target": {"type": "human", "name": "r"}}
TOOL = {"target": {"type": "tool", "name": "add"}}
GATED = {**TOOL, "policy": {"rule_id": "r", "decision": "require_approval", "reason": "x"}}


class Run:
    """One run under construction: plain steps, approvals and anchors signed by `tsa`."""

    def __init__(self, tsa: TestAuthority, delegation: dict[str, Any]) -> None:
        self._tsa = tsa
        self._writer = RunWriter(seeded(b"agent-"), delegation, clock=Clock(), id_factory=Ids())
        self._writer.start()

    def step(self, **fields: Any) -> Run:
        self._writer.append("tool_call", **(fields or TOOL))
        return self

    def approval(self) -> Run:
        self._writer.append("human_approval", **HUMAN)
        return self

    def anchor(self, after_ms: int) -> Run:
        """Anchor the head with a token signed `after_ms` after the head's `occurred_at`."""
        head = self._writer.records[-1]
        req = rfc3161.request(head["hash"])
        signed_at = parse_timestamp(head["occurred_at"]) + timedelta(milliseconds=after_ms)
        token = self._tsa.respond(req.body, gen_time=signed_at)
        self._writer.append(
            "anchor",
            target={"type": "witness", "name": "coverage.test", "endpoint": URL},
            extensions={
                "sealedrun.anchor": {
                    "type": "rfc3161",
                    "anchored_hash": head["hash"],
                    "anchored_seq": head["seq"],
                    "receipt": rfc3161.receipt_from(req, token, self._tsa.chain_pems),
                    "witness": URL,
                }
            },
        )
        return self

    def end(self) -> Run:
        self._writer.end()
        return self

    @property
    def records(self) -> list[dict[str, Any]]:
        return self._writer.records


def _case(
    name: str,
    note: str,
    run: Run,
    *,
    unanchored: int,
    approvals: list[tuple[int, int | None]],
    findings: list[tuple[str, int]] | None = None,
    limit: float | None = None,
    trusted: bool = True,
) -> dict[str, Any]:
    return {
        "name": name,
        "note": note,
        "trusted": trusted,
        "max_approval_anchor_lag": limit,
        "records": run.records,
        "expected": {
            "unanchored_records": unanchored,
            "approval_anchors": [{"seq": seq, "lag_ms": lag} for seq, lag in approvals],
            "findings": [{"check": check, "seq": seq} for check, seq in findings or []],
        },
    }


def main() -> None:
    tsa = TestAuthority("Coverage")
    delegation = create_delegation(
        seeded(b"principal-"),
        seeded(b"agent-").public,
        not_before=START - timedelta(days=1),
        not_after=START + timedelta(days=3650),
        agent_name="coverage-agent",
        delegation_id="0192b3c4-5d6e-7f80-9a1b-0000000000c0",
    )

    def run() -> Run:
        return Run(tsa, delegation)

    cases = [
        _case(
            "anchored-at-once",
            "the anchor follows the approval within the limit; two records come after it",
            run().step().approval().anchor(2000).step().end(),
            unanchored=2,
            approvals=[(2, 2000)],
            limit=5,
        ),
        _case(
            "anchored-late-no-limit",
            "without a limit a late anchor is reported as a lag, not as a finding",
            run().approval().step().anchor(599_000),
            unanchored=0,
            approvals=[(1, 600_000)],
        ),
        _case(
            "anchored-late",
            "the same shape under a limit of five seconds",
            run().approval().step().anchor(599_000),
            unanchored=0,
            approvals=[(1, 600_000)],
            findings=[("anchor.approval_late", 1)],
            limit=5,
        ),
        _case(
            "lag-equal-to-the-limit",
            "a lag equal to the limit is within it",
            run().approval().anchor(5000),
            unanchored=0,
            approvals=[(1, 5000)],
            limit=5,
        ),
        _case(
            "approval-after-the-last-anchor",
            "an anchor before the approval does not cover it",
            run().step().anchor(1000).approval().step(),
            unanchored=2,
            approvals=[(3, None)],
            findings=[("anchor.approval_unanchored", 3)],
            limit=5,
        ),
        _case(
            "untrusted-witness",
            "the anchor is bound to the chain but its authority is not in the trust list",
            run().approval().anchor(1000),
            unanchored=2,
            approvals=[(1, None)],
            findings=[("anchor.approval_unanchored", 1)],
            limit=5,
            trusted=False,
        ),
        _case(
            "first-covering-anchor-counts",
            "each approval takes the first anchor at or after it, not a later one",
            run().approval().anchor(1000).approval().anchor(3000).anchor(50_000),
            unanchored=0,
            approvals=[(1, 1000), (3, 3000)],
            limit=5,
        ),
        _case(
            "anchor-over-a-later-record",
            "an anchor over a later record covers the approval before it",
            run().approval().step().step().anchor(1000),
            unanchored=0,
            approvals=[(1, 3000)],
            limit=5,
        ),
        _case(
            "negative-lag",
            "the authority's clock is behind the recorder's; reported as is, never a finding",
            run().approval().anchor(-400),
            unanchored=0,
            approvals=[(1, -400)],
            limit=5,
        ),
        _case(
            "findings-in-seq-order",
            "anchor findings are merged with the approval finding by seq",
            run().approval().step(**GATED).approval(),
            unanchored=4,
            approvals=[(1, None), (3, None)],
            findings=[
                ("anchor.approval_unanchored", 1),
                ("approval.missing", 2),
                ("anchor.approval_unanchored", 3),
            ],
            limit=5,
        ),
        _case(
            "no-approvals",
            "a run without approvals reports only its unanchored tail",
            run().step(),
            unanchored=2,
            approvals=[],
            limit=5,
        ),
    ]
    document = {
        "trust": [
            {
                "type": "rfc3161",
                "uri": URL,
                "subject": "Coverage Root",
                "valid_for": {
                    "start": format_timestamp(NOT_BEFORE),
                    "end": format_timestamp(NOT_AFTER),
                },
                "roots": [tsa.root_pem],
            }
        ],
        "delegation": delegation,
        "cases": cases,
    }
    OUT.write_text(json.dumps(document, indent=2) + "\n")
    print(f"wrote {OUT} ({len(cases)} cases)")


if __name__ == "__main__":
    main()
