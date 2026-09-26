"""Live runs: records signed by this recorder and committed to the database as they happen."""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any

from sealedrun import RunWriter, payload_ref
from sealedrun.hashing import payload_digest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from sealedrun_recorder.db import DelegationRow, PayloadRow, RecordRow, RunRow
from sealedrun_recorder.keystore import Identity


class LiveRunError(Exception):
    """A live run cannot take the requested operation."""


class LiveRuns:
    """One writer per run, guarded by a per-run lock so `seq` and `prev_hash` stay ordered.

    Each append commits the record, its payload bodies and the run figures in one transaction,
    so a crash leaves the chain either extended by a whole record or not at all. A run that is
    open in the database but has no writer in memory, for example after a restart, is resumed
    from its last stored record.
    """

    def __init__(self, sessions: sessionmaker[Session], identity: Identity):
        self._sessions = sessions
        self._identity = identity
        self._writers: dict[str, RunWriter] = {}
        self._locks: dict[str, threading.Lock] = defaultdict(threading.Lock)
        self._registry_lock = threading.Lock()
        self._store_delegation()

    @property
    def identity(self) -> Identity:
        """Keys and delegation the runs are signed under."""
        return self._identity

    def start(self, *, extensions: dict[str, Any] | None = None) -> dict[str, Any]:
        """Open a new run: write its `run_start` record and return that record."""
        writer = RunWriter(self._identity.agent, self._identity.delegation)
        with self._lock(writer.run_id):
            record = writer.start(extensions=extensions or {})
            with self._sessions() as session:
                session.add(
                    RunRow(
                        run_id=writer.run_id,
                        bundle_id=None,
                        source="live",
                        agent_id=writer.agent_id,
                        principal_id=writer.principal_id,
                        hash_alg=writer.hash_alg,
                        started_at=record["occurred_at"],
                        ended_at=None,
                        record_count=1,
                        first_seq=0,
                        last_hash=record["hash"],
                        complete=False,
                        anchors=0,
                        labels_sent_to_cloud={},
                        run_label=_run_label(extensions),
                    )
                )
                session.add(_record_row(record))
                session.commit()
            self._writers[writer.run_id] = writer
        return record

    def append(
        self,
        run_id: str,
        kind: str,
        *,
        target: dict[str, Any],
        request: bytes | None = None,
        response: bytes | None = None,
        request_media_type: str | None = None,
        response_media_type: str | None = None,
        **fields: Any,
    ) -> dict[str, Any]:
        """Seal one record onto the run and store it with its payload bodies.

        `fields` go to `RunWriter.append`. Raises LiveRunError when the run is unknown, closed,
        or imported rather than live.
        """
        with self._lock(run_id):
            writer = self._writer(run_id)
            payload = None
            if request is not None or response is not None:
                payload = payload_ref(
                    writer.hash_alg,
                    request,
                    response,
                    request_media_type=request_media_type,
                    response_media_type=response_media_type,
                )
            try:
                record = writer.append(kind, target=target, payload=payload, **fields)
            except ValueError as error:
                raise LiveRunError(str(error)) from error
            with self._sessions() as session:
                run = session.get(RunRow, run_id)
                if run is None:
                    raise LiveRunError("run not found")
                for body in (request, response):
                    if body is not None:
                        _store_payload(session, writer.hash_alg, body)
                session.add(_record_row(record))
                run.record_count += 1
                run.last_hash = record["hash"]
                _count_cloud_labels(run, record)
                if kind == "anchor":
                    run.anchors += 1
                session.commit()
            return record

    def end(self, run_id: str, **fields: Any) -> dict[str, Any]:
        """Write the `run_end` record, mark the run complete and drop its writer."""
        with self._lock(run_id):
            writer = self._writer(run_id)
            try:
                record = writer.end(**fields)
            except ValueError as error:
                raise LiveRunError(str(error)) from error
            with self._sessions() as session:
                run = session.get(RunRow, run_id)
                if run is None:
                    raise LiveRunError("run not found")
                session.add(_record_row(record))
                run.record_count += 1
                run.last_hash = record["hash"]
                run.ended_at = record["occurred_at"]
                run.complete = True
                session.commit()
            self._writers.pop(run_id, None)
            return record

    def _writer(self, run_id: str) -> RunWriter:
        writer = self._writers.get(run_id)
        if writer is not None:
            return writer
        with self._sessions() as session:
            run = session.get(RunRow, run_id)
            if run is None or run.source != "live":
                raise LiveRunError("run not found or not live")
            if run.complete:
                raise LiveRunError("run is closed")
            first = session.scalars(
                select(RecordRow).where(RecordRow.run_id == run_id, RecordRow.seq == 0)
            ).one()
            last = session.scalars(
                select(RecordRow)
                .where(RecordRow.run_id == run_id)
                .order_by(RecordRow.seq.desc())
                .limit(1)
            ).one()
        binding = first.document.get("extensions", {}).get("sealedrun.delegation", {})
        if binding.get("delegation_id") != self._identity.delegation["delegation_id"]:
            raise LiveRunError("run was started under a different delegation")
        writer = RunWriter.resume(
            self._identity.agent,
            self._identity.delegation,
            run_id=run_id,
            seq=last.seq + 1,
            head=last.hash,
        )
        self._writers[run_id] = writer
        return writer

    def _lock(self, run_id: str) -> threading.Lock:
        with self._registry_lock:
            return self._locks[run_id]

    def _store_delegation(self) -> None:
        delegation = self._identity.delegation
        with self._sessions() as session:
            session.merge(
                DelegationRow(
                    delegation_id=delegation["delegation_id"],
                    principal_id=delegation["principal_id"],
                    agent_id=delegation["agent_id"],
                    document=delegation,
                )
            )
            session.commit()


def _store_payload(session: Session, hash_alg: str, body: bytes) -> None:
    digest = payload_digest(hash_alg, body)
    if session.get(PayloadRow, digest) is None:
        session.add(PayloadRow(digest=digest, hash_alg=hash_alg, size_bytes=len(body), body=body))


def _count_cloud_labels(run: RunRow, record: dict[str, Any]) -> None:
    if record["target"].get("location") != "cloud" or record["outcome"] == "blocked":
        return
    counts = dict(run.labels_sent_to_cloud)
    for label in record["data_labels"]:
        counts[label] = counts.get(label, 0) + 1
    run.labels_sent_to_cloud = counts


def _record_row(record: dict[str, Any]) -> RecordRow:
    target = record["target"]
    policy = record.get("policy")
    return RecordRow(
        record_id=record["record_id"],
        run_id=record["run_id"],
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


def _run_label(extensions: dict[str, Any] | None) -> str | None:
    label = ((extensions or {}).get("sealedrun.proxy") or {}).get("run_label")
    return label if isinstance(label, str) and label else None
