"""Live runs: records signed by this recorder and committed to the database as they happen."""

from __future__ import annotations

import threading
from collections import OrderedDict, defaultdict
from typing import Any

from sealedrun import RunWriter, payload_ref
from sealedrun.hashing import payload_digest
from sealedrun.schema import validate
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from sealedrun_recorder.db import DelegationRow, PayloadRow, RecordRow, RunRow
from sealedrun_recorder.keystore import Identity

MAX_WRITERS = 4096
TARGET_LIMITS = {"type": 16, "name": 256, "location": 16, "endpoint": 2048, "provider": 256}


class LiveRunError(Exception):
    """A live run cannot take the requested operation."""


class InvalidRecordError(Exception):
    """A caller-supplied record would not verify; nothing was written."""


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
        self._writers: OrderedDict[str, RunWriter] = OrderedDict()
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
                        labels_self_reported={},
                        run_label=_run_label(extensions),
                    )
                )
                session.add(_record_row(record))
                session.commit()
            self._remember(writer)
        return record

    def _remember(self, writer: RunWriter) -> None:
        """Keep the writer in memory, forgetting the least recently used past `MAX_WRITERS`.

        A forgotten writer costs one database read when its run is next appended to: the run is
        resumed from its stored head, exactly as after a restart.
        """
        with self._registry_lock:
            self._writers[writer.run_id] = writer
            self._writers.move_to_end(writer.run_id)
            while len(self._writers) > MAX_WRITERS:
                dropped, _ = self._writers.popitem(last=False)
                self._locks.pop(dropped, None)

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
        check: bool = False,
        **fields: Any,
    ) -> dict[str, Any]:
        """Seal one record onto the run and store it with its payload bodies.

        `fields` go to `RunWriter.preview`. With `check` the unsigned document is validated
        against the record schema first, so a caller-supplied record that would not verify
        never enters the chain. Raises LiveRunError when the run is unknown, closed, imported
        rather than live; InvalidRecordError when the document fails that check.
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
            _check_target(target)
            try:
                doc = writer.preview(kind, target=target, payload=payload, **fields)
                if check:
                    problems = _schema_problems(doc)
                    if problems:
                        raise InvalidRecordError(f"record would not verify: {problems[0]}")
                record = writer.seal(doc)
            except ValueError as error:
                raise LiveRunError(str(error)) from error
            try:
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
                        run.last_anchor_at = record["occurred_at"]
                    session.commit()
            except Exception as error:
                # The record never reached the store: take it back so the head in memory
                # stays the head on disk, else every later record would chain to a ghost.
                writer.revert(record)
                if isinstance(error, LiveRunError):
                    raise
                raise LiveRunError(f"record not stored: {type(error).__name__}") from error
            return record

    def head(self, run_id: str) -> tuple[int, str, str]:
        """Return `(seq, hash, kind)` of the last record of an open live run.

        Raises LiveRunError when the run is unknown, imported or closed.
        """
        with self._lock(run_id):
            writer = self._writer(run_id)
            with self._sessions() as session:
                last = session.scalars(
                    select(RecordRow)
                    .where(RecordRow.run_id == run_id)
                    .order_by(RecordRow.seq.desc())
                    .limit(1)
                ).one()
            if last.hash != writer.head:
                raise LiveRunError("run head does not match the stored records")
            return last.seq, last.hash, last.kind

    def open_runs(self) -> list[str]:
        """Return the ids of live runs that are not complete."""
        with self._sessions() as session:
            rows = session.scalars(
                select(RunRow.run_id).where(RunRow.source == "live", RunRow.complete.is_(False))
            )
            return list(rows)

    def end(self, run_id: str, **fields: Any) -> dict[str, Any]:
        """Write the `run_end` record, mark the run complete and drop its writer."""
        with self._lock(run_id):
            writer = self._writer(run_id)
            try:
                record = writer.end(**fields)
            except ValueError as error:
                raise LiveRunError(str(error)) from error
            try:
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
            except Exception as error:
                writer.revert(record)
                if isinstance(error, LiveRunError):
                    raise
                raise LiveRunError(f"run_end not stored: {type(error).__name__}") from error
            with self._registry_lock:
                self._writers.pop(run_id, None)
                self._locks.pop(run_id, None)
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
        self._remember(writer)
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


def _check_target(target: dict[str, Any]) -> None:
    """Refuse a target whose text fields would not fit the record row's columns."""
    for key, limit in TARGET_LIMITS.items():
        value = target.get(key)
        if isinstance(value, str) and len(value) > limit:
            raise LiveRunError(f"target.{key} longer than {limit} characters")


def _schema_problems(doc: dict[str, Any]) -> list[str]:
    """Return the schema violations of an unsigned document, ignoring its missing signatures."""
    placeholder = {**doc, "hash": "0" * 64, "signatures": {}}
    return [e for e in validate("record.json", placeholder) if not e.startswith("signatures")]


def _store_payload(session: Session, hash_alg: str, body: bytes) -> None:
    digest = payload_digest(hash_alg, body)
    if session.get(PayloadRow, digest) is None:
        session.add(PayloadRow(digest=digest, hash_alg=hash_alg, size_bytes=len(body), body=body))


def _count_cloud_labels(run: RunRow, record: dict[str, Any]) -> None:
    """Keep the run's label counters: what the recorder saw leave, and what was only reported.

    `labels_sent_to_cloud` counts labels on non-blocked cloud-target records the recorder made
    itself. A self-reported step (`sealedrun.step`) is the caller's own account, so its labels
    go to `labels_self_reported` instead, whatever outcome the caller stated.
    """
    if record["target"].get("location") != "cloud":
        return
    if "sealedrun.step" in record.get("extensions", {}):
        counts = dict(run.labels_self_reported)
        for label in record["data_labels"]:
            counts[label] = counts.get(label, 0) + 1
        run.labels_self_reported = counts
        return
    if record["outcome"] == "blocked":
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
