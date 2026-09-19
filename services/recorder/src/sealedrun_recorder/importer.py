from __future__ import annotations

from dataclasses import asdict
from datetime import UTC, datetime

from sealedrun import Bundle, BundleReport, read_bundle, verify_bundle
from sqlalchemy.orm import Session

from sealedrun_recorder.db import BundleRow, DelegationRow, PayloadRow, RecordRow, RunRow


def import_bundle(session: Session, archive: bytes) -> BundleRow:
    bundle = read_bundle(archive)
    report = verify_bundle(bundle)
    existing = session.get(BundleRow, bundle.manifest["bundle_id"])
    if existing is not None:
        return existing
    row = _bundle_row(bundle, report, archive)
    session.add(row)
    for delegation in bundle.delegations.values():
        session.merge(
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
        )
        run_row.records = [_record_row(r) for r in records]
        session.add(run_row)
    for digest, body in bundle.payloads.items():
        if session.get(PayloadRow, digest) is None:
            session.add(
                PayloadRow(
                    digest=digest,
                    hash_alg=bundle.manifest["hash_alg"],
                    size_bytes=len(body),
                    body=body,
                )
            )
    session.commit()
    return row


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
        report={"bundle_id": report.bundle_id, "runs": [asdict(r) for r in report.runs]},
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
