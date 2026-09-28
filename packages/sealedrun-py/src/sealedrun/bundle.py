"""Bundles: a zip archive of delegations, runs, payloads and a signed manifest (SPEC 13).

The `MAX_*` limits bound what `read_bundle` accepts from an untrusted archive, so that a crafted
zip cannot exhaust memory.
"""

from __future__ import annotations

import io
import json
import zipfile
from collections.abc import Collection
from dataclasses import dataclass, field
from typing import Any, BinaryIO
from uuid import uuid4

from sealedrun.delegation import verify_delegation
from sealedrun.errors import VerificationError
from sealedrun.hashing import DEFAULT_HASH_ALG, digest, payload_digest, zero_hash
from sealedrun.keys import KeySet, PrivateKeySet
from sealedrun.schema import validate
from sealedrun.signing import DOMAIN_MANIFEST, check_hash, check_signatures, countersign, seal
from sealedrun.timeutil import format_timestamp, now
from sealedrun.trust import Witness
from sealedrun.verify import RunReport, verify_run

SPEC_VERSION = "0.1"
MANIFEST = "manifest.json"
MAX_ENTRIES = 10_000
MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024


@dataclass
class Bundle:
    """Parsed contents of a bundle archive.

    Attributes:
        delegations: Delegation objects by `delegation_id`.
        runs: Records of each run by `run_id`, in file order.
        payloads: Payload bodies by their base64url digest.
        anchors: Witness receipts by the `record_id` of their anchor record.
    """

    manifest: dict[str, Any]
    delegations: dict[str, dict[str, Any]]
    runs: dict[str, list[dict[str, Any]]]
    payloads: dict[str, bytes] = field(default_factory=dict)
    anchors: dict[str, dict[str, Any]] = field(default_factory=dict)


@dataclass
class BundleReport:
    """What `verify_bundle` established about a bundle.

    Attributes:
        principal_trusted: False means integrity only: the Principal was not compared with a
            trust anchor (SPEC 13.2).
    """

    bundle_id: str
    runs: list[RunReport]
    principal_id: str
    exporter_agent_id: str
    principal_trusted: bool


def _jsonl(records: list[dict[str, Any]]) -> bytes:
    return "".join(
        json.dumps(r, separators=(",", ":"), sort_keys=True) + "\n" for r in records
    ).encode()


def write_bundle(
    out: BinaryIO,
    *,
    exporter: PrivateKeySet,
    software: str,
    delegations: list[dict[str, Any]],
    runs: list[list[dict[str, Any]]],
    payloads: dict[str, bytes] | None = None,
    anchors: dict[str, dict[str, Any]] | None = None,
    principal: PrivateKeySet | None = None,
    hash_alg: str = DEFAULT_HASH_ALG,
    bundle_id: str | None = None,
    created_at: str | None = None,
) -> dict[str, Any]:
    """Write a bundle archive to `out` and return its sealed manifest.

    The exporter signs the manifest; `principal`, when given, countersigns it. `payloads` and
    `anchors` are keyed as in `Bundle`. Raises ValueError if a payload key is not the digest of
    its body or if the delegations name more than one principal.
    """
    files: dict[str, bytes] = {}
    for d in delegations:
        files[f"delegations/{d['delegation_id']}.json"] = json.dumps(d, sort_keys=True).encode()
    run_entries = []
    for records in runs:
        first = records[0]
        files[f"runs/{first['run_id']}.jsonl"] = _jsonl(records)
        run_entries.append(
            {
                "run_id": first["run_id"],
                "hash_alg": first["hash_alg"],
                "record_count": len(records),
                "first_seq": first["seq"],
                "first_hash": first["prev_hash"]
                if first["seq"] > 0
                else zero_hash(first["hash_alg"]),
                "last_hash": records[-1]["hash"],
                "complete": records[-1]["kind"] == "run_end",
            }
        )
    for body_hash, body in (payloads or {}).items():
        if body_hash != payload_digest(hash_alg, body):
            raise ValueError(f"payload key is not the {hash_alg} digest of its body: {body_hash}")
        files[f"payloads/{hash_alg}/{body_hash}"] = body
    for record_id, receipt in (anchors or {}).items():
        files[f"anchors/{record_id}.json"] = json.dumps(receipt, sort_keys=True).encode()

    principal_ids = {d["principal_id"] for d in delegations}
    if len(principal_ids) != 1:
        raise ValueError("bundle must contain delegations of exactly one principal")
    manifest: dict[str, Any] = {
        "spec_version": SPEC_VERSION,
        "bundle_id": bundle_id or str(uuid4()),
        "created_at": created_at or format_timestamp(now()),
        "exporter": {"agent_id": exporter.public.kid, "software": software},
        "principal_id": principal_ids.pop(),
        "delegations": [d["delegation_id"] for d in delegations],
        "runs": run_entries,
        "files": {path: payload_digest(hash_alg, data) for path, data in files.items()},
        "hash_alg": hash_alg,
    }
    manifest = seal(manifest, DOMAIN_MANIFEST, exporter)
    if principal is not None:
        manifest = countersign(manifest, DOMAIN_MANIFEST, principal)

    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(MANIFEST, json.dumps(manifest, indent=2, sort_keys=True))
        for path, data in sorted(files.items()):
            zf.writestr(path, data)
    return manifest


def read_bundle(
    source: BinaryIO | bytes,
    *,
    max_entry_bytes: int = MAX_ENTRY_BYTES,
    max_total_bytes: int = MAX_TOTAL_BYTES,
) -> Bundle:
    """Parse an untrusted bundle archive and check every file against the manifest digests.

    Entry count, per-entry size and total size are limited before anything is decompressed, and
    the file set must equal the manifest listing. Signatures are not checked here; pass the
    result to `verify_bundle`.

    Raises VerificationError for a malformed archive or any mismatch.
    """
    data = io.BytesIO(source) if isinstance(source, bytes) else source
    if not zipfile.is_zipfile(data):
        raise VerificationError("bundle", "not a zip archive")
    data.seek(0)
    try:
        return _read_archive(data, max_entry_bytes, max_total_bytes)
    except (
        zipfile.BadZipFile,
        UnicodeDecodeError,
        ValueError,
        EOFError,
        RecursionError,
        KeyError,
        TypeError,
        AttributeError,
    ) as error:
        raise VerificationError("bundle", "malformed archive") from error


def _json(content: bytes | str) -> Any:
    """Parse strict JSON: NaN and Infinity are refused, as RFC 8785 cannot represent them."""

    def constant(name: str) -> Any:
        raise ValueError(f"{name} is not JSON")

    return json.loads(content, parse_constant=constant)


def _read_archive(data: BinaryIO, max_entry_bytes: int, max_total_bytes: int) -> Bundle:
    with zipfile.ZipFile(data) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > MAX_ENTRIES:
            raise VerificationError("bundle", "too many entries")
        if len({i.filename for i in infos}) != len(infos):
            raise VerificationError("bundle", "duplicate entry names")
        data.seek(0, io.SEEK_END)
        if sum(i.compress_size for i in infos) > data.tell():
            raise VerificationError("bundle", "entries overlap or exceed the archive")
        if any(max(i.file_size, i.compress_size) > max_entry_bytes for i in infos):
            raise VerificationError("bundle", "entry exceeds size limit")
        if sum(max(i.file_size, i.compress_size) for i in infos) > max_total_bytes:
            raise VerificationError("bundle", "archive exceeds uncompressed size limit")
        names = {i.filename for i in infos}
        if MANIFEST not in names:
            raise VerificationError("bundle", "manifest.json missing")
        manifest = _json(_read_entry(zf, MANIFEST, min(max_entry_bytes, MAX_MANIFEST_BYTES)))
        errors = validate("bundle.json", manifest, first_only=True)
        if errors:
            raise VerificationError("schema", "; ".join(errors))
        listed = set(manifest["files"])
        extra = names - listed - {MANIFEST}
        if extra:
            raise VerificationError("bundle", f"files not in manifest: {sorted(extra)}")
        missing = listed - names
        if missing:
            raise VerificationError("bundle", f"files missing: {sorted(missing)}")
        bundle = Bundle(manifest, {}, {})
        for path, expected in manifest["files"].items():
            content = _read_entry(zf, path, max_entry_bytes)
            if payload_digest(manifest["hash_alg"], content) != expected:
                raise VerificationError("bundle", f"digest mismatch for {path}")
            if path.startswith("delegations/"):
                doc = _json(content)
                _must_match("delegation.json", doc, path)
                bundle.delegations[doc["delegation_id"]] = doc
            elif path.startswith("runs/"):
                records = [_json(line) for line in content.decode().splitlines() if line]
                run_id = path.removeprefix("runs/").removesuffix(".jsonl")
                for edge in (records[:1] + records[-1:]) if records else []:
                    _must_match("record.json", edge, path)
                    if edge["run_id"] != run_id:
                        raise VerificationError(
                            "run", f"{path} holds records of run {edge['run_id']}", run_id
                        )
                bundle.runs[run_id] = records
            elif path.startswith("payloads/"):
                bundle.payloads[_payload_key(path, content, manifest["hash_alg"])] = content
            elif path.startswith("anchors/"):
                bundle.anchors[path.removeprefix("anchors/").removesuffix(".json")] = _json(content)
    return bundle


def _must_match(schema: str, doc: Any, path: str) -> None:
    """Refuse a document that does not satisfy `schema` before any field is read."""
    if not isinstance(doc, dict):
        raise VerificationError("schema", f"{path}: not a JSON object")
    errors = validate(schema, doc, first_only=True)
    if errors:
        raise VerificationError("schema", f"{path}: {errors[0]}")


def _payload_key(path: str, content: bytes, hash_alg: str) -> str:
    parts = path.split("/")
    if len(parts) != 3 or parts[1] != hash_alg:
        raise VerificationError("bundle", f"malformed payload path {path}")
    if parts[2] != payload_digest(hash_alg, content):
        raise VerificationError("bundle", f"payload name is not the digest of its content: {path}")
    return parts[2]


def _read_entry(zf: zipfile.ZipFile, name: str, limit: int) -> bytes:
    with zf.open(name) as entry:
        content = entry.read(limit + 1)
    if len(content) > limit:
        raise VerificationError("bundle", "entry exceeds size limit")
    return content


def verify_bundle(
    bundle: Bundle,
    trusted_principals: Collection[str] | None = None,
    *,
    witnesses: list[Witness] | None = None,
    strict_witness: bool = False,
) -> BundleReport:
    """Verify a bundle per SPEC 13.2.

    The keys inside a bundle are not a root of trust. Pass the principal ids obtained out of band
    as ``trusted_principals``; without them the report has ``principal_trusted=False`` and only
    says the bundle is internally consistent. ``witnesses`` and ``strict_witness`` go to
    `verify_run` for the anchor receipts.
    """
    manifest = bundle.manifest
    if not check_hash(manifest):
        raise VerificationError("manifest", "manifest hash mismatch")
    for delegation in bundle.delegations.values():
        problem = verify_delegation(delegation)
        if problem is not None:
            raise VerificationError("delegation", problem)
        if delegation["principal_id"] != manifest["principal_id"]:
            raise VerificationError("manifest", "delegation principal differs from manifest")
    if trusted_principals is not None and manifest["principal_id"] not in trusted_principals:
        raise VerificationError("trust", "principal is not in the trusted set")
    exporter = _find_delegation(bundle, manifest["exporter"]["agent_id"])
    if exporter is None:
        raise VerificationError("manifest", "exporter has no delegation in bundle")
    if not check_signatures(manifest, DOMAIN_MANIFEST, KeySet.from_json(exporter["agent_keys"])):
        raise VerificationError("manifest", "exporter signature invalid")
    if "principal_signatures" in manifest:
        principal_keys = KeySet.from_json(exporter["principal_keys"])
        if not check_signatures(manifest, DOMAIN_MANIFEST, principal_keys, "principal_signatures"):
            raise VerificationError("manifest", "principal signature invalid")
    if set(manifest["delegations"]) != set(bundle.delegations):
        raise VerificationError("manifest", "delegation list does not match files")
    if {r["run_id"] for r in manifest["runs"]} != set(bundle.runs):
        raise VerificationError("manifest", "run list does not match files")

    reports = []
    for entry in manifest["runs"]:
        records = bundle.runs[entry["run_id"]]
        expected_prev = entry["first_hash"] if entry["first_seq"] > 0 else None
        report = verify_run(
            records,
            bundle.delegations,
            payloads=bundle.payloads,
            expected_prev_hash=expected_prev,
            witnesses=witnesses,
            strict_witness=strict_witness,
        )
        if report.record_count != entry["record_count"] or report.last_hash != entry["last_hash"]:
            raise VerificationError("manifest", "run entry does not match records", entry["run_id"])
        if report.complete != entry["complete"] or report.first_seq != entry["first_seq"]:
            raise VerificationError(
                "manifest", "run entry flags do not match records", entry["run_id"]
            )
        if records[0]["hash_alg"] != manifest["hash_alg"]:
            raise VerificationError(
                "hash_alg", "run hash algorithm differs from the manifest", entry["run_id"]
            )
        reports.append(report)
    _check_anchor_files(bundle)
    return BundleReport(
        manifest["bundle_id"],
        reports,
        manifest["principal_id"],
        manifest["exporter"]["agent_id"],
        trusted_principals is not None,
    )


def _check_anchor_files(bundle: Bundle) -> None:
    """Every anchors/<record_id>.json must be the receipt of that anchor record (SPEC 13)."""
    receipts = {
        r["record_id"]: r.get("extensions", {}).get("sealedrun.anchor", {}).get("receipt")
        for records in bundle.runs.values()
        for r in records
        if r.get("kind") == "anchor"
    }
    for record_id, receipt in bundle.anchors.items():
        if record_id not in receipts:
            raise VerificationError("anchor", f"receipt file for unknown anchor record {record_id}")
        if receipt != receipts[record_id]:
            raise VerificationError(
                "anchor", f"receipt file differs from anchor record {record_id}"
            )


def _find_delegation(bundle: Bundle, agent_id: str) -> dict[str, Any] | None:
    for d in bundle.delegations.values():
        if d["agent_id"] == agent_id:
            return d
    return None


def file_digest(hash_alg: str, data: bytes) -> str:
    """Return the lowercase hex digest of `data`."""
    return digest(hash_alg, data).hex()
