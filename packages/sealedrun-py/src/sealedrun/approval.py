"""Approval check: binding `require_approval` steps to the human answer (SPEC 6.6)."""

from __future__ import annotations

from typing import Any

from sealedrun.scope import Finding

APPROVAL_EXTENSION = "sealedrun.approval"


class Approvals:
    """Tracks the `human_approval` records of one run and matches executed steps to them.

    Feed records in seq order through `findings`. A granted or denied answer is matched, by
    `payload.request_hash`, to the first later executed step that hashes the same request; one
    answer covers one step. A `human_approval` without `sealedrun.approval` (written before
    SPEC 6.6) matches nothing.
    """

    def __init__(self) -> None:
        self._open: dict[str, list[tuple[int, str]]] = {}

    def findings(self, record: dict[str, Any]) -> list[Finding]:
        """Return the approval findings of one record (SPEC 6.6)."""
        seq, record_id = record["seq"], record["record_id"]
        request_hash = (record.get("payload") or {}).get("request_hash")
        if record["kind"] == "human_approval":
            answer = record.get("extensions", {}).get(APPROVAL_EXTENSION)
            if isinstance(answer, dict) and request_hash:
                self._open.setdefault(request_hash, []).append((seq, answer["decision"]))
            return []
        policy = record.get("policy")
        if (
            not policy
            or policy.get("decision") != "require_approval"
            or record["outcome"] == "blocked"
        ):
            return []
        answers = self._open.get(request_hash) if request_hash else None
        if not answers:
            return [
                Finding(
                    "approval.missing",
                    seq,
                    record_id,
                    "step required approval but no human_approval for its request precedes it",
                )
            ]
        approved_at, decision = answers.pop()
        if decision == "denied":
            return [
                Finding(
                    "approval.denied_but_executed",
                    seq,
                    record_id,
                    f"human denied this request at seq {approved_at} and the step ran anyway",
                )
            ]
        return []
