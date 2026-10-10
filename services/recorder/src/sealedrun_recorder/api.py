"""HTTP API of the recorder: bundle upload, verification and read-only queries."""

from __future__ import annotations

import hmac
import re
from collections.abc import Iterator
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, UploadFile
from sealedrun import VerificationError
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.responses import JSONResponse, StreamingResponse

from sealedrun_recorder.db import BundleRow, PayloadRow, RecordRow, RunRow
from sealedrun_recorder.export import ExportError, build_bundle, payload_bytes
from sealedrun_recorder.importer import import_bundle
from sealedrun_recorder.limits import BodyTooLargeError, read_body
from sealedrun_recorder.live import InvalidRecordError, LiveRunError
from sealedrun_recorder.policy import Rule
from sealedrun_recorder.proxy.context import (
    AgentError,
    header_agent,
    run_context,
    tool_inventory_digest,
)
from sealedrun_recorder.proxy.core import RUN_HEADER, RUN_LABEL
from sealedrun_recorder.proxy.labels import LabelsError, header_labels
from sealedrun_recorder.steps import Step, StepError, parse_step

SAFE_PAYLOAD_MEDIA_TYPES = frozenset({"application/json", "text/plain", "application/octet-stream"})


SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
SAME_SITE = frozenset({"same-origin"})


def require_token(request: Request) -> None:
    """Raise 401 unless the request carries the configured bearer token.

    Does nothing when no token is configured. Bearer only, and no WWW-Authenticate challenge:
    a browser must never hold an ambient credential that it would replay on a cross-site request.
    """
    secret = request.app.state.settings.api_token
    if secret is None or not secret.get_secret_value():
        return
    if not has_valid_token(request):
        raise HTTPException(401, "invalid or missing token")


def require_same_site(request: Request) -> None:
    """Refuse state-changing requests that a foreign page made a browser send.

    Every current browser sets Sec-Fetch-Site and a page cannot forge it. Only `same-origin`
    passes: `same-site` would let a sibling subdomain post, which matters when the recorder runs
    without a token. A request without the header is not from a browser, so it is let through
    only with a valid token.
    """
    if request.method in SAFE_METHODS:
        return
    site = request.headers.get("sec-fetch-site")
    if site is None:
        if not has_valid_token(request):
            raise HTTPException(403, "request without Sec-Fetch-Site needs a bearer token")
    elif site not in SAME_SITE:
        raise HTTPException(403, "cross-site request refused")


def has_valid_token(request: Request) -> bool:
    """Tell whether a token is configured and the request carries it as a bearer token."""
    secret = request.app.state.settings.api_token
    if secret is None or not secret.get_secret_value():
        return False
    scheme, _, value = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer":
        return False
    return hmac.compare_digest(value.strip().encode(), secret.get_secret_value().encode())


public_router = APIRouter(prefix="/api")
router = APIRouter(prefix="/api", dependencies=[Depends(require_token), Depends(require_same_site)])


def get_session(request: Request) -> Any:
    """Yield a database session that is closed when the request ends."""
    with request.app.state.sessions() as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]
INFLATE_FACTOR = 4
Limit = Annotated[int, Query(ge=1, le=1000)]
Offset = Annotated[int, Query(ge=0)]


@public_router.get("/health")
def health() -> dict[str, str]:
    """Report that the service is up. Needs no token."""
    return {"status": "ok"}


@router.get("/identity")
def identity(request: Request) -> dict[str, Any]:
    """Return the ids and public keys this recorder signs live runs with, and its delegation."""
    live = request.app.state.live
    return {
        "principal_id": live.identity.principal_id,
        "agent_id": live.identity.agent_id,
        "principal_keys": live.identity.principal.public.to_json(),
        "agent_keys": live.identity.agent.public.to_json(),
        "anchor_public_key": live.identity.anchor_public_key,
        "delegation": live.identity.delegation,
        "anchors": request.app.state.anchoring.status.as_json(),
    }


@router.post("/bundles", status_code=201)
async def upload_bundle(request: Request, file: UploadFile, session: SessionDep) -> dict[str, Any]:
    """Verify a bundle archive and store it, returning its summary.

    Uploading a bundle that is already stored returns the stored one. Responds 413 when the
    archive exceeds the size limit, 400 when it cannot be parsed, and 422 with the failed check,
    run id and seq when verification fails. When trusted Principals are configured, a bundle
    from any other Principal fails verification.
    """
    archive = await _read_archive(request, file)
    try:
        row = import_bundle(
            session,
            archive,
            request.app.state.settings.trust_anchor,
            max_total_bytes=_inflated_limit(request),
        )
    except VerificationError as error:
        raise HTTPException(
            422,
            {"check": error.check, "run_id": error.run_id, "seq": error.seq, "message": str(error)},
        ) from error
    except (ValueError, KeyError, TypeError) as error:
        raise HTTPException(400, "malformed bundle") from error
    return _bundle_summary(row, request)


async def _read_archive(request: Request, file: UploadFile) -> bytes:
    """Read an uploaded archive up to `max_bundle_bytes`; 413 past it, before or while reading."""
    limit = request.app.state.settings.max_bundle_bytes
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise HTTPException(413, "bundle exceeds size limit")
    archive = await file.read(limit + 1)
    if len(archive) > limit:
        raise HTTPException(413, "bundle exceeds size limit")
    return archive


def _inflated_limit(request: Request) -> int:
    """Return the most an archive may hold once inflated: `INFLATE_FACTOR` times the cap."""
    return INFLATE_FACTOR * int(request.app.state.settings.max_bundle_bytes)


@router.post("/verify")
async def verify_only(request: Request, file: UploadFile) -> dict[str, Any]:
    """Verify a bundle archive without storing anything.

    A verification failure is a normal result: the response is 200 with `ok` false and the
    failed check, run id and seq. Responds 413 when the archive exceeds the size limit and 400
    when it cannot be parsed.
    """
    from sealedrun import read_bundle, verify_bundle

    archive = await _read_archive(request, file)
    try:
        bundle = read_bundle(archive, max_total_bytes=_inflated_limit(request))
        report = verify_bundle(bundle, request.app.state.settings.trust_anchor)
    except VerificationError as error:
        return {
            "ok": False,
            "check": error.check,
            "run_id": error.run_id,
            "seq": error.seq,
            "message": str(error),
        }
    except (ValueError, KeyError, TypeError) as error:
        raise HTTPException(400, "malformed bundle") from error
    return {
        "ok": True,
        "bundle_id": report.bundle_id,
        "principal_id": report.principal_id,
        "exporter_agent_id": report.exporter_agent_id,
        "principal_trusted": report.principal_trusted,
        "runs": [r.__dict__ for r in report.runs],
    }


@router.get("/bundles")
def list_bundles(
    request: Request, session: SessionDep, limit: Limit = 100, offset: Offset = 0
) -> list[dict[str, Any]]:
    """List stored bundles, most recently imported first."""
    query = select(BundleRow).order_by(BundleRow.imported_at.desc()).limit(limit).offset(offset)
    rows = session.scalars(query).all()
    return [_bundle_summary(r, request) for r in rows]


@router.get("/bundles/{bundle_id}")
def get_bundle(bundle_id: str, request: Request, session: SessionDep) -> dict[str, Any]:
    """Return a bundle summary with its manifest and the verification report from import.

    Responds 404 when the bundle is not stored.
    """
    row = session.get(BundleRow, bundle_id)
    if row is None:
        raise HTTPException(404, "bundle not found")
    return {**_bundle_summary(row, request), "manifest": row.manifest, "report": row.report}


@router.get("/bundles/{bundle_id}/archive")
def download_bundle(bundle_id: str, session: SessionDep) -> Response:
    """Download the bundle archive exactly as it was uploaded.

    Responds 404 when the bundle is not stored.
    """
    row = session.get(BundleRow, bundle_id)
    if row is None:
        raise HTTPException(404, "bundle not found")
    return Response(
        row.archive,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="sealedrun-{_safe_name(bundle_id)}.zip"',
            "X-Content-Type-Options": "nosniff",
        },
    )


Text = Annotated[str | None, Query(max_length=128)]
Stamp = Annotated[str | None, Query(pattern=r"^\d{4}-\d{2}-\d{2}(T[0-9:.]+Z?)?$")]


@router.get("/runs")
def list_runs(
    request: Request,
    response: Response,
    session: SessionDep,
    limit: Limit = 100,
    offset: Offset = 0,
    q: Text = None,
    since: Stamp = None,
    until: Stamp = None,
    complete: bool | None = None,
    source: Literal["live", "imported"] | None = None,
) -> list[dict[str, Any]]:
    """List stored runs, latest start time first.

    `q` matches a run id prefix or a part of the run label (case-insensitive); `since` and
    `until` bound `started_at` (ISO 8601, `until` exclusive). The `X-Total-Count` header holds
    the number of runs that match before paging.
    """
    where = []
    if q:
        needle = q.strip()
        where.append(
            or_(
                RunRow.run_id.startswith(needle, autoescape=True),
                RunRow.run_label.ilike(f"%{_escape(needle)}%", escape="\\"),
            )
        )
    if since:
        where.append(RunRow.started_at >= since)
    if until:
        where.append(RunRow.started_at < until)
    if complete is not None:
        where.append(RunRow.complete.is_(complete))
    if source:
        where.append(RunRow.source == source)
    total = session.scalar(select(func.count()).select_from(RunRow).where(*where)) or 0
    response.headers["X-Total-Count"] = str(total)
    query = (
        select(RunRow).where(*where).order_by(RunRow.started_at.desc()).limit(limit).offset(offset)
    )
    rows = session.scalars(query).all()
    return [_run_summary(r, request) for r in rows]


def _escape(needle: str) -> str:
    """Escape LIKE wildcards so a user's `%` or `_` matches itself."""
    return needle.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@router.get("/runs/{run_id}")
def get_run(run_id: str, request: Request, session: SessionDep) -> dict[str, Any]:
    """Return the summary of one run. Responds 404 when the run is not stored."""
    row = session.get(RunRow, run_id)
    if row is None:
        raise HTTPException(404, "run not found")
    summary = _run_summary(row, request)
    summary["payload_bytes"] = payload_bytes(session, run_id)
    return summary


@router.post("/runs/{run_id}/export")
async def export_run(
    run_id: str,
    request: Request,
    session: SessionDep,
    end: bool = False,
    payloads: Literal["include", "omit"] = "include",
) -> Response:
    """Export a live run as a bundle archive signed by this recorder.

    When anchoring is on, the run's head is anchored first (SPEC 8.2), so an open run leaves
    with a fresh receipt and a run ended here has its anchor right before `run_end`. With
    `end=true` the run's `run_end` record is written first, so the bundle is complete;
    otherwise an open run is exported as it stands. With `payloads=omit` the archive holds the
    records and receipts but no bodies, and its manifest says so. Responds 404 for an unknown
    run, 409 for an imported run (download its original bundle) and 409 with `end=true` on a run
    that is already closed.
    """
    await request.app.state.anchoring.anchor_run(run_id)
    if end:
        try:
            request.app.state.live.end(run_id)
        except LiveRunError as error:
            raise HTTPException(409, str(error)) from error
    session.expire_all()
    try:
        archive = build_bundle(
            session,
            request.app.state.live.identity,
            run_id,
            payloads_omitted=payloads == "omit",
        )
    except ExportError as error:
        raise HTTPException(error.status, str(error)) from error
    size = archive.seek(0, 2)
    archive.seek(0)
    suffix = "-records" if payloads == "omit" else ""

    def chunks() -> Iterator[bytes]:
        try:
            while chunk := archive.read(1 << 20):
                yield chunk
        finally:
            archive.close()

    return StreamingResponse(
        chunks(),
        media_type="application/zip",
        headers={
            "Content-Disposition": (
                f'attachment; filename="sealedrun-{_safe_name(run_id)}{suffix}.zip"'
            ),
            "Content-Length": str(size),
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/steps", status_code=201, response_model=None)
async def post_step(request: Request) -> Response | dict[str, Any]:
    """Seal a self-reported step onto the run named by `X-SealedRun-Run`, or the default run.

    Runs are joined exactly as for proxied calls: the same label shares a run with the LLM
    proxy, no label means the shared idle-closed run. `X-SealedRun-Labels` supplies
    `data_labels` when the body has none. The body is checked against the record
    schema before anything is sealed: 400 names the first problem, 413 is an oversize body.
    Returns the signed record.
    """
    label = request.headers.get(RUN_HEADER)
    if label is not None and not RUN_LABEL.match(label):
        raise HTTPException(400, f"{RUN_HEADER} must match {RUN_LABEL.pattern}")
    try:
        agent = header_agent(request)
    except AgentError as problem:
        raise HTTPException(400, str(problem)) from problem
    step = await _read_step(request)
    runs = request.app.state.runs
    listing = step.tools_list()
    tools = None
    if listing is not None:
        digest = tool_inventory_digest(listing["result"])
        if digest is not None:
            tools = (listing["server"], digest)
    rule: Rule = request.app.state.policy
    context = run_context(rule, agent, "header" if agent else None, tools=tools)
    if listing is not None:
        run_id = await run_in_threadpool(runs.run_for, label, context=context)
        if not _list_changed(request, run_id, listing):
            return _unchanged_list()
    record: dict[str, Any]
    try:
        record = await run_in_threadpool(
            runs.record, label, step.kind, context=context, **step.fields()
        )
    except InvalidRecordError as error:
        raise HTTPException(400, str(error)) from error
    if listing is not None:
        _remember_list(request, str(record["run_id"]), listing)
    return record


@router.post("/runs/{run_id}/steps", status_code=201, response_model=None)
async def post_run_step(
    run_id: str, request: Request, session: SessionDep
) -> Response | dict[str, Any]:
    """Seal a self-reported step onto one open live run by id.

    Responds 404 for an unknown run and 409 for an imported or closed one; otherwise as
    `POST /api/steps`.
    """
    row = session.get(RunRow, run_id)
    if row is None:
        raise HTTPException(404, "run not found")
    if row.source != "live":
        raise HTTPException(409, "run was imported, not recorded live")
    if row.complete:
        raise HTTPException(409, "run is closed")
    step = await _read_step(request)
    live = request.app.state.live
    listing = step.tools_list()
    if listing is not None and not _list_changed(request, run_id, listing):
        return _unchanged_list()
    record: dict[str, Any]
    try:
        record = await run_in_threadpool(live.append, run_id, step.kind, **step.fields())
    except InvalidRecordError as error:
        raise HTTPException(400, str(error)) from error
    except LiveRunError as error:
        raise HTTPException(409, str(error)) from error
    if listing is not None:
        _remember_list(request, run_id, listing)
    return record


def _list_changed(request: Request, run_id: str, listing: dict[str, Any]) -> bool:
    """Tell whether a `tools/list` step differs from the last one recorded for its key.

    Self-reported `tools/list` results are deduplicated like proxied ones: once per run,
    server, transport and cursor until the result changes.
    """
    key = (run_id, listing["server"], listing["transport"], listing["cursor"])
    return bool(request.app.state.mcp_lists.changed(key, listing["result"]))


def _remember_list(request: Request, run_id: str, listing: dict[str, Any]) -> None:
    key = (run_id, listing["server"], listing["transport"], listing["cursor"])
    request.app.state.mcp_lists.remember(key, listing["result"])


def _unchanged_list() -> Response:
    body = {"recorded": False, "reason": "tools/list result unchanged"}
    return JSONResponse(body, status_code=200)


async def _read_step(request: Request) -> Step:
    try:
        body = await read_body(request, request.app.state.settings.proxy_max_body_bytes)
    except BodyTooLargeError as error:
        raise HTTPException(413, "step exceeds size limit") from error
    try:
        step = parse_step(body)
        labels = header_labels(request)
    except (StepError, LabelsError) as error:
        raise HTTPException(400, str(error)) from error
    if labels and not step.data_labels:
        step.data_labels = labels
        step.extensions = {
            **step.extensions,
            "sealedrun.labels": {label: {"source": "header"} for label in labels},
        }
    return step


@router.get("/runs/{run_id}/records")
def list_records(
    run_id: str,
    response: Response,
    session: SessionDep,
    limit: Limit = 1000,
    offset: Offset = 0,
    kind: Text = None,
    q: Text = None,
    outcome: Text = None,
) -> list[dict[str, Any]]:
    """List the signed records of a run in seq order. Responds 404 when the run is not stored.

    `kind` keeps one record kind, `outcome` one outcome, and `q` matches a part of the target
    name (the model or tool, case-insensitive). `X-Total-Count` holds the number of records that
    match before paging; bodies are never searched.
    """
    if session.get(RunRow, run_id) is None:
        raise HTTPException(404, "run not found")
    where = [RecordRow.run_id == run_id]
    if kind:
        where.append(RecordRow.kind == kind)
    if outcome:
        where.append(RecordRow.outcome == outcome)
    if q:
        where.append(RecordRow.target_name.ilike(f"%{_escape(q.strip())}%", escape="\\"))
    total = session.scalar(select(func.count()).select_from(RecordRow).where(*where)) or 0
    response.headers["X-Total-Count"] = str(total)
    query = select(RecordRow).where(*where).order_by(RecordRow.seq).limit(limit).offset(offset)
    return [r.document for r in session.scalars(query)]


@router.get("/records/{record_id}")
def get_record(record_id: str, session: SessionDep) -> dict[str, Any]:
    """Return one signed record document. Responds 404 when the record is not stored."""
    row = session.get(RecordRow, record_id)
    if row is None:
        raise HTTPException(404, "record not found")
    return row.document


@router.get("/records/{record_id}/payload/{side}")
def get_payload(record_id: str, side: str, session: SessionDep) -> Response:
    """Download the request or response payload body of a record.

    Responds 404 when `side` is not `request` or `response`, or when the record or the payload
    body is not stored. Payload bytes come from the recorded agent and are untrusted, so the
    body is always sent as an attachment with nosniff and a sandboxing CSP, and any declared
    media type outside a short safe list is replaced by application/octet-stream.
    """
    if side not in ("request", "response"):
        raise HTTPException(404, "side must be request or response")
    row = session.get(RecordRow, record_id)
    if row is None:
        raise HTTPException(404, "record not found")
    ref = row.document.get("payload") or {}
    digest = ref.get(f"{side}_hash")
    if digest is None or ref.get("storage") not in ("bundle", "inline"):
        raise HTTPException(404, f"record has no stored {side} payload")
    payload = session.get(PayloadRow, digest)
    if payload is None:
        raise HTTPException(404, "payload body not stored")
    declared = str(ref.get(f"{side}_media_type") or "").partition(";")[0].strip().lower()
    media_type = declared if declared in SAFE_PAYLOAD_MEDIA_TYPES else "application/octet-stream"
    return Response(
        payload.body,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="{_safe_name(record_id)}-{side}"',
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; sandbox",
        },
    )


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)[:80]


def _is_trusted(request: Request, principal_id: str) -> bool:
    """Tell whether the Principal is in the trust anchor or is this recorder's own Principal.

    The recorder holds its own principal key, so runs it signed itself need no out-of-band id.
    Evaluated against the current setting, not the one in force at import time.
    """
    if principal_id == request.app.state.live.identity.principal_id:
        return True
    anchor = request.app.state.settings.trust_anchor
    return anchor is not None and principal_id in anchor


def _bundle_summary(row: BundleRow, request: Request) -> dict[str, Any]:
    return {
        "bundle_id": row.bundle_id,
        "principal_id": row.principal_id,
        "principal_trusted": _is_trusted(request, row.principal_id),
        "exporter_agent_id": row.exporter_agent_id,
        "created_at": row.created_at,
        "imported_at": row.imported_at.isoformat(),
        "size_bytes": row.size_bytes,
        "runs": [r.run_id for r in row.runs],
    }


def _run_summary(row: RunRow, request: Request) -> dict[str, Any]:
    return {
        "run_id": row.run_id,
        "bundle_id": row.bundle_id,
        "source": row.source,
        "agent_id": row.agent_id,
        "principal_id": row.principal_id,
        "principal_trusted": _is_trusted(request, row.principal_id),
        "hash_alg": row.hash_alg,
        "started_at": row.started_at,
        "ended_at": row.ended_at,
        "record_count": row.record_count,
        "first_seq": row.first_seq,
        "last_hash": row.last_hash,
        "complete": row.complete,
        "anchors": row.anchors,
        "labels_sent_to_cloud": row.labels_sent_to_cloud,
        "labels_self_reported": row.labels_self_reported,
        "run_label": row.run_label,
        "last_anchor_at": row.last_anchor_at,
    }
