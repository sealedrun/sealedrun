"""One-page evidence report of a verified bundle, as data and as plain text.

The report restates what `verify_bundle` established in the words a claim file or an incident
notice needs: what was asked for, what the bundle covers, which witnesses saw it, who approved
what, and what the verifier flagged. `evidence_report` returns JSON-ready data with the same
keys in every implementation; `render_report` turns that data into text.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any, BinaryIO

from sealedrun.bundle import Bundle, BundleReport
from sealedrun.errors import VerificationError

REPORT_VERSION = 1
TRUST_URL = "https://github.com/sealedrun/sealedrun/blob/main/TRUST.md"
LIMITS = (
    "This report restates what the verifier checked in the bundle. It does not show that the "
    "recorder saw every action of the agent, that no run was left out of the export, or that "
    "a recorded step was right to take. A principal that is not confirmed means the bundle "
    f"is consistent, not that it comes from the party you expect. See {TRUST_URL}"
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def file_sha256(source: BinaryIO | bytes) -> str:
    """Return the SHA-256 of the archive in hex, the digest to note outside the agent's host.

    A file is read in chunks from its start and left at offset 0.
    """
    if isinstance(source, bytes):
        return hashlib.sha256(source).hexdigest()
    source.seek(0)
    digest = hashlib.file_digest(source, "sha256").hexdigest()  # type: ignore[arg-type]
    source.seek(0)
    return digest


def evidence_report(bundle: Bundle, verified: BundleReport, sha256: str) -> dict[str, Any]:
    """Build the report of a bundle that passed `verify_bundle`.

    `sha256` is the digest of the archive file as received (`file_sha256`). Times are the
    recorder's `occurred_at`; an anchor's time is that of its anchor record.
    """
    manifest = bundle.manifest
    runs = []
    approvals = []
    findings: list[dict[str, Any]] = []
    anchors = []
    for run in verified.runs:
        records = bundle.runs[run.run_id]
        times = [r["occurred_at"] for r in records]
        first = records[0]
        proxy = first.get("extensions", {}).get("sealedrun.proxy", {})
        label = proxy.get("run_label") if first["seq"] == 0 else None
        runs.append(
            {
                "run_id": run.run_id,
                "label": label,
                "records": run.record_count,
                "first_record_at": min(times),
                "last_record_at": max(times),
                "complete": run.complete,
                "parent_unresolved": run.run_id in verified.parents_unresolved,
                "outside_window": verified.outside_window.get(run.run_id),
                "anchors": run.anchors,
                "witness_verified": run.anchors_witness_verified,
                "unanchored_records": run.unanchored_records,
            }
        )
        lags = {a.seq: a.lag_ms for a in run.approval_anchors}
        for record in records:
            extensions = record.get("extensions", {})
            if record["kind"] == "human_approval":
                approvals.append(
                    {
                        "run_id": run.run_id,
                        "seq": record["seq"],
                        "at": record["occurred_at"],
                        "actor": record["actor"]["id"],
                        "decision": extensions.get("sealedrun.approval", {}).get("decision"),
                        "anchor_lag_ms": lags.get(record["seq"]),
                    }
                )
            elif record["kind"] == "anchor":
                anchor = extensions["sealedrun.anchor"]
                anchors.append(
                    {
                        "at": record["occurred_at"],
                        "type": anchor["type"],
                        "witness": anchor.get("witness"),
                    }
                )
        findings.extend(
            {"run_id": run.run_id, "seq": f.seq, "check": f.check, "reason": f.reason}
            for f in run.findings
        )
    anchors.sort(key=lambda a: a["at"])
    outside = sum(verified.outside_window.values()) if verified.query is not None else None
    return {
        "report_version": REPORT_VERSION,
        "result": "passed",
        "file_sha256": sha256,
        "bundle": {
            "bundle_id": manifest["bundle_id"],
            "created_at": manifest["created_at"],
            "software": manifest["exporter"]["software"],
            "exporter_agent_id": verified.exporter_agent_id,
            "principal_id": verified.principal_id,
            "principal_trusted": verified.principal_trusted,
            "principal_countersigned": "principal_signatures" in manifest,
            "payloads": "omitted" if verified.payloads_omitted else "included",
        },
        "query": verified.query,
        "coverage": {
            "runs": len(runs),
            "runs_complete": sum(1 for r in runs if r["complete"]),
            "records": sum(r["records"] for r in runs),
            "first_record_at": min(r["first_record_at"] for r in runs) if runs else None,
            "last_record_at": max(r["last_record_at"] for r in runs) if runs else None,
            "records_outside_window": outside,
        },
        "anchors": {
            "count": sum(r["anchors"] for r in runs),
            "witness_verified": sum(r["witness_verified"] for r in runs),
            "first": anchors[0] if anchors else None,
            "last": anchors[-1] if anchors else None,
            "unanchored_records": sum(r["unanchored_records"] for r in runs),
        },
        "approvals": approvals,
        "findings": findings,
        "runs": runs,
        "limits": LIMITS,
    }


def failure_report(error: VerificationError, sha256: str) -> dict[str, Any]:
    """Build the report of a bundle that failed verification: the failing check and nothing else.

    Nothing inside a bundle that does not verify is repeated, because none of it can be relied
    on.
    """
    return {
        "report_version": REPORT_VERSION,
        "result": "failed",
        "file_sha256": sha256,
        "check": error.check,
        "run_id": error.run_id,
        "seq": error.seq,
        "message": error.reason,
        "limits": LIMITS,
    }


def _plain(value: Any) -> str:
    """Render a value from the bundle without characters that steer a terminal."""
    return _CONTROL.sub("?", str(value))


def _row(label: str, value: Any) -> str:
    return f"  {label + ':':<22}{_plain(value)}"


def _anchor(anchor: dict[str, Any] | None) -> str:
    if anchor is None:
        return "none"
    return f"{anchor['at']} ({anchor['type']}, {anchor['witness'] or 'witness not named'})"


def render_report(report: dict[str, Any]) -> str:
    """Render the data of `evidence_report` or `failure_report` as text ending in a newline."""
    lines = ["SealedRun evidence report", "=========================", ""]
    if report["result"] != "passed":
        where = "".join(
            f", {name} {report[key]}"
            for name, key in (("run", "run_id"), ("seq", "seq"))
            if report[key] is not None
        )
        lines += [
            "Verification",
            _row("Result", f"FAILED at check {report['check']}{where}"),
            _row("Reason", report["message"]),
            _row("File SHA-256", report["file_sha256"]),
            "",
            "Nothing in a bundle that fails verification can be relied on, so nothing else",
            "from it is repeated here.",
            "",
        ]
        return "\n".join(lines)
    bundle, coverage, anchors = report["bundle"], report["coverage"], report["anchors"]
    trusted = (
        "confirmed: it is one of the principals the verifier was given"
        if bundle["principal_trusted"]
        else "NOT CONFIRMED: the verifier was given no trusted principal to compare with"
    )
    signed = (
        "exporter key and principal key"
        if bundle["principal_countersigned"]
        else "exporter key only"
    )
    bodies = (
        "included and checked against the records"
        if bundle["payloads"] == "included"
        else "left out by the exporter; the records keep their digests, the bodies were not checked"
    )
    lines += [
        "Verification",
        _row("Result", "PASSED: every hash, signature and chain link in the bundle was checked"),
        _row("Principal", bundle["principal_id"]),
        _row("Principal identity", trusted),
        _row("Manifest signed by", signed),
        _row("Payload bodies", bodies),
        "",
        "Bundle",
        _row("File SHA-256", report["file_sha256"]),
        _row("Bundle id", bundle["bundle_id"]),
        _row("Created", bundle["created_at"]),
        _row("Exported by", f"{bundle['software']}, agent {bundle['exporter_agent_id']}"),
        "",
        "What the exporter was asked for",
    ]
    query = report["query"]
    if query is None:
        lines.append("  No query: the bundle was not exported by a time window.")
    else:
        lines += [
            _row("Window", f"{query['since']} to {query['until']} (end not included)"),
            _row("Run label", query.get("label", "any")),
            _row("Exporter's note", query.get("note", "none")),
        ]
    open_runs = coverage["runs"] - coverage["runs_complete"]
    lines += [
        "",
        "What the bundle covers",
        _row("Runs", f"{coverage['runs']} ({coverage['runs_complete']} ended, {open_runs} open)"),
        _row("Records", coverage["records"]),
        _row("First record", coverage["first_record_at"] or "none"),
        _row("Last record", coverage["last_record_at"] or "none"),
    ]
    if coverage["records_outside_window"] is not None:
        lines.append(_row("Outside the window", f"{coverage['records_outside_window']} records"))
    lines += [
        "",
        "Anchors (what an outside witness saw)",
        _row("Anchor records", anchors["count"]),
        _row("Witness verified", f"{anchors['witness_verified']} of {anchors['count']}"),
        _row("First anchor", _anchor(anchors["first"])),
        _row("Last anchor", _anchor(anchors["last"])),
        _row(
            "Not anchored",
            f"{anchors['unanchored_records']} records after the last verified anchor",
        ),
        "",
        f"Human approvals: {len(report['approvals'])}",
    ]
    for approval in report["approvals"]:
        lag = approval["anchor_lag_ms"]
        seen = (
            "no verified anchor covers it"
            if lag is None
            else f"a witness saw it {lag / 1000:.3f} s later"
        )
        lines.append(
            _plain(
                f"  run {approval['run_id']} seq {approval['seq']} at {approval['at']}: "
                f"{approval['decision'] or 'decision not stated'} by {approval['actor']}; {seen}"
            )
        )
    lines += ["", f"Findings: {len(report['findings'])}"]
    lines += [
        _plain(f"  run {f['run_id']} seq {f['seq']} {f['check']}: {f['reason']}")
        for f in report["findings"]
    ]
    lines += ["", "Runs"]
    for run in report["runs"]:
        state = "ended" if run["complete"] else "open"
        parent = ", parent run not in this bundle" if run["parent_unresolved"] else ""
        lines.append(
            _plain(
                f"  {run['run_id']} label {run['label'] or 'none'}: {run['records']} records, "
                f"{run['first_record_at']} to {run['last_record_at']}, {state}{parent}"
            )
        )
    lines += ["", "Limits", *_wrap(report["limits"]), ""]
    return "\n".join(lines)


def _wrap(text: str, width: int = 76) -> list[str]:
    """Break text at spaces into indented lines of at most `width` characters where it can."""
    lines: list[str] = []
    line = ""
    for word in text.split(" "):
        if line and len(line) + 1 + len(word) > width:
            lines.append("  " + line)
            line = word
        else:
            line = f"{line} {word}" if line else word
    return [*lines, "  " + line]
