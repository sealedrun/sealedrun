"""Verify a bundle archive and write its contents to the database."""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Any

from sealedrun import Bundle, BundleReport, read_bundle, verify_bundle
from sealedrun.bundle import MAX_TOTAL_BYTES
from sealedrun.errors import VerificationError
from sealedrun.hashing import payload_digest
from sqlalchemy.orm import Session

from sealedrun_recorder.db import BundleRow, DelegationRow, PayloadRow, RecordRow, RunRow


def import_bundle(
    session: Session,
    archive: bytes,
    trusted_principals: Collection[str] | None = None,
    *,
    max_total_bytes: int = MAX_TOTAL_BYTES,
) -> BundleRow:
    """Verify the archive and store its bundle, delegations, runs, records and payloads.

    Nothing is written unless the whole bundle verifies. Importing a stored bundle again returns
    the existing row, and runs already stored from another bundle are skipped. A delegation
    already stored under the same id with a different document, for example the recorder's own
    (its id is public), fails the import: a stored delegation is never overwritten. Every payload
    body in the archive is checked against its digest, including bodies no record references.

    Raises:
        VerificationError: The bundle fails verification, a payload body does not match its
            digest, or a digest is already stored with a different body.

    """
    bundle = read_bundle(archive, max_total_bytes=max_total_bytes)
    report = verify_bundle(bundle, trusted_principals)
    existing = session.get(BundleRow, bundle.manifest["bundle_id"])
    if existing is not None:
        return existing
    row = _bundle_row(bundle, report, archive)
    session.add(row)
    for delegation in bundle.delegations.values():
        known = session.get(DelegationRow, delegation["delegation_id"])
        if known is not None:
            if known.document != delegation:
                raise VerificationError(
                    "delegation",
                    f"delegation {delegation['delegation_id']} is already stored with a "
                    "different document",
                )
            continue
        session.add(
            DelegationRow(
                delegation_id=delegation["delegation_id"],
                principal_id=delegation["principal_id"],
                agent_id=delegation["agent_id"],
                document=delegation,
            )
        )
    for run_report in report.runs:
        records = bundle.runs[run_report.run_id]
        if session.get(RunRow, run_report.run_id) is not None:
            continue
        run_row = RunRow(
            run_id=run_report.run_id,
            bundle_id=row.bundle_id,
            source="imported",
            agent_id=records[0]["agent_id"],
            principal_id=records[0]["principal_id"],
            hash_alg=records[0]["hash_alg"],
            started_at=records[0]["occurred_at"],
            ended_at=records[-1]["occurred_at"] if run_report.complete else None,
            record_count=run_report.record_count,
            first_seq=run_report.first_seq,
            last_hash=run_report.last_hash,
            complete=run_report.complete,
            anchors=run_report.anchors,
            labels_sent_to_cloud=run_report.labels_sent_to_cloud,
            labels_self_reported=_self_reported_labels(records),
        )
        run_row.records = [_record_row(r) for r in records]
        session.add(run_row)
    hash_alg = bundle.manifest["hash_alg"]
    for digest, body in bundle.payloads.items():
        if digest != payload_digest(hash_alg, body):
            raise VerificationError("bundle", f"payload body does not match its digest: {digest}")
        stored = session.get(PayloadRow, digest)
        if stored is None:
            session.add(
                PayloadRow(digest=digest, hash_alg=hash_alg, size_bytes=len(body), body=body)
            )
        elif stored.body != body:
            raise VerificationError(
                "bundle", f"payload digest collides with a different body: {digest}"
            )
    session.commit()
    return row


def _self_reported_labels(records: list[dict[str, Any]]) -> dict[str, int]:
    """Count the labels of cloud-target records that were self-reported steps."""
    counts: dict[str, int] = {}
    for record in records:
        if record["target"].get("location") != "cloud":
            continue
        if "sealedrun.step" not in record.get("extensions", {}):
            continue
        for label in record.get("data_labels", []):
            counts[label] = counts.get(label, 0) + 1
    return counts


def _bundle_row(bundle: Bundle, report: BundleReport, archive: bytes) -> BundleRow:
    manifest = bundle.manifest
    return BundleRow(
        bundle_id=manifest["bundle_id"],
        principal_id=manifest["principal_id"],
        exporter_agent_id=manifest["exporter"]["agent_id"],
        created_at=manifest["created_at"],
        imported_at=datetime.now(UTC),
        size_bytes=len(archive),
        manifest=manifest,
        report={
            "bundle_id": report.bundle_id,
            "principal_id": report.principal_id,
            "exporter_agent_id": report.exporter_agent_id,
            "principal_trusted": report.principal_trusted,
            "runs": [asdict(r) for r in report.runs],
        },
        archive=archive,
    )


def _record_row(record: dict) -> RecordRow:  # type: ignore[type-arg]
    target = record["target"]
    policy = record.get("policy")
    return RecordRow(
        record_id=record["record_id"],
        seq=record["seq"],
        kind=record["kind"],
        occurred_at=record["occurred_at"],
        target_type=target["type"],
        target_name=target["name"],
        target_location=target.get("location"),
        outcome=record["outcome"],
        decision=policy["decision"] if policy else None,
        hash=record["hash"],
        document=record,
    )
