import json
from typing import Any

import pytest
from sealedrun import ApprovalAnchor, verify_run
from sealedrun.schema import SCHEMA_DIR
from sealedrun.trust import Witness

VECTORS = SCHEMA_DIR.parent / "vectors"


def load_coverage() -> tuple[list[Witness], dict[str, Any], list[dict[str, Any]]]:
    document = json.loads((VECTORS / "anchors" / "coverage.json").read_text())
    trust = [Witness.from_json(entry) for entry in document["trust"]]
    return trust, document["delegation"], document["cases"]


@pytest.mark.parametrize("case", load_coverage()[2], ids=lambda c: c["name"])
def test_coverage_vectors(case: dict[str, Any]) -> None:
    trust, delegation, _ = load_coverage()
    report = verify_run(
        case["records"],
        {delegation["delegation_id"]: delegation},
        witnesses=trust if case["trusted"] else [],
        max_approval_anchor_lag=case["max_approval_anchor_lag"],
    )
    expected = case["expected"]
    assert report.unanchored_records == expected["unanchored_records"]
    assert [{"seq": a.seq, "lag_ms": a.lag_ms} for a in report.approval_anchors] == expected[
        "approval_anchors"
    ]
    assert [{"check": f.check, "seq": f.seq} for f in report.findings] == expected["findings"]
    by_seq = {r["seq"]: r["record_id"] for r in case["records"]}
    assert all(a.record_id == by_seq[a.seq] for a in report.approval_anchors)
    assert all(f.record_id == by_seq[f.seq] for f in report.findings)


def test_late_finding_names_the_lag_and_the_limit() -> None:
    trust, delegation, cases = load_coverage()
    case = next(c for c in cases if c["name"] == "anchored-late")
    report = verify_run(
        case["records"],
        {delegation["delegation_id"]: delegation},
        witnesses=trust,
        max_approval_anchor_lag=5,
    )
    assert report.findings[0].reason == (
        "a witness saw this approval 600.000 s after it was recorded, limit 5 s"
    )
    assert report.approval_anchors == [ApprovalAnchor(1, case["records"][1]["record_id"], 600_000)]


def test_reference_run_coverage() -> None:
    records = [
        json.loads(line)
        for line in (VECTORS / "records" / "valid-run.jsonl").read_text().splitlines()
        if line
    ]
    delegation = json.loads((VECTORS / "delegations" / "valid.json").read_text())
    report = verify_run(records, {delegation["delegation_id"]: delegation})
    assert [(a.seq, a.lag_ms) for a in report.approval_anchors] == [(5, 1018027000)]
    assert report.unanchored_records == 2
