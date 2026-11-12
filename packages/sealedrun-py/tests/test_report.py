import io
import json
from typing import Any

import pytest
from sealedrun import (
    PrivateKeySet,
    RunWriter,
    VerificationError,
    evidence_report,
    failure_report,
    file_sha256,
    payload_digest,
    read_bundle,
    render_report,
    verify_bundle,
    write_bundle,
)
from sealedrun.__main__ import main
from sealedrun.schema import SCHEMA_DIR

REPORTS = SCHEMA_DIR.parent / "vectors" / "report"
BUNDLES = SCHEMA_DIR.parent / "vectors" / "bundle"
CASES = json.loads((REPORTS / "cases.json").read_text())


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_report_vectors(case: dict[str, Any]) -> None:
    data = (REPORTS / case["bundle"]).read_bytes()
    bundle = read_bundle(data)
    verified = verify_bundle(bundle, case.get("trusted_principals"))
    report = evidence_report(bundle, verified, file_sha256(data))
    assert report == json.loads((REPORTS / f"{case['name']}.json").read_text())
    assert render_report(report) == (REPORTS / f"{case['name']}.txt").read_text()


def test_incident_report_names_what_a_claim_needs() -> None:
    report = json.loads((REPORTS / "incident.json").read_text())
    assert report["query"]["note"].startswith("INC-42")
    assert report["coverage"] == {
        "runs": 2,
        "runs_complete": 1,
        "records": 11,
        "first_record_at": "2026-09-16T12:00:01.000Z",
        "last_record_at": "2026-09-16T12:10:03.000Z",
        "records_outside_window": 3,
    }
    assert report["anchors"]["witness_verified"] == 0
    assert report["anchors"]["unanchored_records"] == 10
    assert [(a["actor"], a["decision"], a["anchor_lag_ms"]) for a in report["approvals"]] == [
        ("jane.doe@example.com", "granted", None)
    ]
    assert [f["check"] for f in report["findings"]] == ["scope.target", "approval.missing"]
    assert report["bundle"]["principal_trusted"] is True


def test_file_sha256_reads_a_file_and_rewinds() -> None:
    import hashlib

    data = (BUNDLES / "valid.zip").read_bytes()
    with open(BUNDLES / "valid.zip", "rb") as handle:
        handle.seek(10)
        assert file_sha256(handle) == file_sha256(data) == hashlib.sha256(data).hexdigest()
        assert handle.tell() == 0


def test_unconfirmed_principal_is_said_in_capitals() -> None:
    text = (REPORTS / "window-label.txt").read_text()
    assert "NOT CONFIRMED: the verifier was given no trusted principal" in text
    assert "confirmed: it is one of the principals" in (REPORTS / "valid.txt").read_text()


def test_omitted_payloads_are_said() -> None:
    assert "left out by the exporter" in (REPORTS / "payloads-omitted.txt").read_text()


def test_failure_report_repeats_nothing_from_the_bundle() -> None:
    data = (BUNDLES / "window-wrong-label.zip").read_bytes()
    with pytest.raises(VerificationError) as info:
        verify_bundle(read_bundle(data))
    report = failure_report(info.value, file_sha256(data))
    assert report["result"] == "failed"
    assert (report["check"], report["seq"]) == ("query", None)
    assert set(report) == {
        "report_version",
        "result",
        "file_sha256",
        "check",
        "run_id",
        "seq",
        "message",
        "limits",
    }
    text = render_report(report)
    assert "FAILED at check query, run " in text
    assert "billing-agent" not in text and "INC" not in text


def test_cli_report_text_and_json(capsys: pytest.CaptureFixture[str]) -> None:
    case = next(c for c in CASES if c["name"] == "incident")
    path = str(REPORTS / case["bundle"])
    assert main(["--report", path, *case["trusted_principals"]]) == 0
    assert capsys.readouterr().out == (REPORTS / "incident.txt").read_text()
    assert main(["--report", "--json", path, *case["trusted_principals"]]) == 0
    assert json.loads(capsys.readouterr().out) == json.loads(
        (REPORTS / "incident.json").read_text()
    )


def test_cli_report_of_a_failing_bundle(capsys: pytest.CaptureFixture[str]) -> None:
    path = str(BUNDLES / "tampered-record.zip")
    assert main(["--report", path]) == 1
    out = capsys.readouterr().out
    assert "FAILED at check bundle" in out and "File SHA-256" in out
    assert main(["--report", "--json", path]) == 1
    assert json.loads(capsys.readouterr().out)["check"] == "bundle"
    assert main(["--report", "--strict-scope", str(REPORTS / "incident.zip")]) == 1
    assert "FAILED at check scope.target, run " in capsys.readouterr().out
    assert main(["--json", path]) == 2


def test_report_strips_control_characters(
    agent: PrivateKeySet,
    delegation: dict[str, Any],
    run: RunWriter,
    payloads: dict[str, bytes],
) -> None:
    out = io.BytesIO()
    write_bundle(
        out,
        exporter=agent,
        software="evil\x1b[2K/1.0",
        delegations=[delegation],
        runs=[run.records],
        payloads={payload_digest("sha-256", body): body for body in payloads.values()},
        query={
            "since": "2026-09-16T12:00:00.000Z",
            "until": "2026-09-16T13:00:00.000Z",
            "note": "\x1b[HResult: FAILED\nResult: forged",
        },
    )
    bundle = read_bundle(out.getvalue())
    text = render_report(evidence_report(bundle, verify_bundle(bundle), "00"))
    assert "\x1b" not in text
    assert text.count("\n  Result:") == 1
