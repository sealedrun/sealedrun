"""Export live runs from their database rows as a bundle archive."""

from __future__ import annotations

import tempfile
from collections.abc import Iterator, Mapping, Sequence
from typing import Any, BinaryIO, cast

from sealedrun import write_bundle
from sqlalchemy import select
from sqlalchemy.orm import Session

from sealedrun_recorder import __version__
from sealedrun_recorder.db import DelegationRow, PayloadRow, RecordRow, RunRow
from sealedrun_recorder.keystore import Identity

SOFTWARE = f"sealedrun-recorder/{__version__}"


class ExportError(Exception):
    """The run cannot be exported; `status` is the HTTP status that describes why."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


SPOOL_BYTES = 64 * 1024 * 1024
MAX_RUNS = 1024


class _StoredPayloads(Mapping[str, bytes]):
    """Payload bodies of the exported runs read from the database one at a time, in digest order."""

    def __init__(self, session: Session, digests: list[str]):
        self._session = session
        self._digests = digests

    def __getitem__(self, digest: str) -> bytes:
        row = self._session.get(PayloadRow, digest)
        if row is None:
            raise ExportError(500, f"payload body missing from the database: {digest}")
        body = row.body
        self._session.expunge(row)
        return body

    def __iter__(self) -> Iterator[str]:
        return iter(self._digests)

    def __len__(self) -> int:
        return len(self._digests)


def runs_in_window(session: Session, since: str, until: str, label: str | None) -> list[str]:
    """Return the ids of live runs with a record in `[since, until)`, earliest start first.

    `since` and `until` are SPEC 3 timestamps, which compare as text. With `label` only runs
    opened under that run label are returned. Imported runs are never returned: their original
    bundle is the record.
    """
    inside = select(RecordRow.run_id).where(
        RecordRow.occurred_at >= since, RecordRow.occurred_at < until
    )
    where = [RunRow.source == "live", RunRow.run_id.in_(inside)]
    if label is not None:
        where.append(RunRow.run_label == label)
    query = select(RunRow.run_id).where(*where).order_by(RunRow.started_at, RunRow.run_id)
    return list(session.scalars(query))


def build_bundle(
    session: Session,
    identity: Identity,
    run_ids: Sequence[str],
    *,
    payloads_omitted: bool = False,
    query: Mapping[str, str] | None = None,
) -> tempfile.SpooledTemporaryFile[bytes]:
    """Return a seekable file holding one bundle archive of the live runs, at offset 0.

    The archive is spooled to disk past `SPOOL_BYTES`, and each payload body is read from the
    database only while it is being written, so runs of gigabytes do not need that much
    memory. The caller closes the file.

    The recorder's agent key is the exporter and its principal key countersigns. An open run
    is exported as it stands, with `complete` false in the manifest. Imported runs are refused:
    their original bundle is the record. A payload body a record names but the database no
    longer holds is an error, never a silent gap. With `payloads_omitted` no body is read or
    written and the manifest says so (SPEC 13.1): the archive of a long session shrinks from
    gigabytes to the records alone. `query` becomes the manifest's `query` block.

    Raises:
        ExportError: 404 when a run is unknown, 409 when one was imported or the runs do not
            share a hash algorithm, 413 past `MAX_RUNS` runs, 500 when a payload body or a
            run's delegation is missing.

    """
    if len(run_ids) > MAX_RUNS:
        raise ExportError(
            413, f"{len(run_ids)} runs match and a bundle holds at most {MAX_RUNS}: narrow it"
        )
    runs: list[list[dict[str, Any]]] = []
    delegations: dict[str, dict[str, Any]] = {}
    digests: dict[str, None] = {}
    anchors: dict[str, dict[str, Any]] = {}
    algs: set[str] = set()
    for run_id in run_ids:
        run = session.get(RunRow, run_id)
        if run is None:
            raise ExportError(404, "run not found")
        if run.source != "live":
            raise ExportError(409, "imported run: download its original bundle instead")
        algs.add(run.hash_alg)
        records = [
            row.document
            for row in session.scalars(
                select(RecordRow).where(RecordRow.run_id == run_id).order_by(RecordRow.seq)
            )
        ]
        runs.append(records)
        delegation = _delegation_of(session, records[0])
        delegations[delegation["delegation_id"]] = delegation
        for record in records:
            if record["kind"] == "anchor":
                anchors[record["record_id"]] = record["extensions"]["sealedrun.anchor"]["receipt"]
            ref = record.get("payload") or {}
            if payloads_omitted or ref.get("storage") != "bundle":
                continue
            for side in ("request", "response"):
                digest = ref.get(f"{side}_hash")
                if digest is not None:
                    digests[digest] = None
    if len(algs) > 1:
        raise ExportError(
            409, f"runs use different hash algorithms ({', '.join(sorted(algs))}): narrow it"
        )
    stored: set[str] = set()
    names = list(digests)
    for start in range(0, len(names), 500):
        chunk = names[start : start + 500]
        stored.update(
            session.scalars(select(PayloadRow.digest).where(PayloadRow.digest.in_(chunk)))
        )
    for digest in names:
        if digest not in stored:
            raise ExportError(500, f"payload body missing from the database: {digest}")
    out = tempfile.SpooledTemporaryFile(max_size=SPOOL_BYTES)
    write_bundle(
        cast(BinaryIO, out),
        exporter=identity.agent,
        software=SOFTWARE,
        delegations=list(delegations.values()),
        runs=runs,
        payloads=_StoredPayloads(session, names),
        anchors=anchors,
        principal=identity.principal,
        hash_alg=algs.pop(),
        payloads_omitted=payloads_omitted,
        query=query,
    )
    out.seek(0)
    return out


def payload_bytes(session: Session, run_id: str) -> int:
    """Sum of the distinct payload bodies a full export of `run_id` would carry, in bytes.

    Read from the sizes the records state, not from the bodies, so the answer is cheap.
    """
    seen: dict[str, int] = {}
    query = select(RecordRow.document).where(RecordRow.run_id == run_id)
    documents: list[dict[str, Any]] = list(session.scalars(query))
    for document in documents:
        ref = document.get("payload") or {}
        if ref.get("storage") != "bundle":
            continue
        for side in ("request", "response"):
            digest = ref.get(f"{side}_hash")
            if digest is not None:
                seen[digest] = int(ref.get(f"{side}_size") or 0)
    return sum(seen.values())


def _delegation_of(session: Session, first: dict[str, Any]) -> dict[str, Any]:
    binding = first.get("extensions", {}).get("sealedrun.delegation", {})
    row = session.get(DelegationRow, binding.get("delegation_id", ""))
    if row is None:
        raise ExportError(500, "the run's delegation is not stored")
    return row.document
