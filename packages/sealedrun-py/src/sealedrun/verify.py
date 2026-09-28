"""Verification of a single run (SPEC 13.2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sealedrun.anchors import rekor, rfc3161
from sealedrun.delegation import covers, verify_delegation
from sealedrun.errors import VerificationError
from sealedrun.hashing import digest_size, payload_digest, zero_hash
from sealedrun.keys import KeySet
from sealedrun.schema import validate, validate_extensions
from sealedrun.signing import DOMAIN_RECORD, check_hash, check_signatures
from sealedrun.timeutil import parse_timestamp
from sealedrun.trust import Witness, load_witnesses


@dataclass
class RunReport:
    """What `verify_run` established about a run.

    Attributes:
        first_seq: Sequence number of the first record; above 0 for a partial run.
        last_hash: Hash of the last record, the value a continuation must chain from.
        complete: True when the run ends with `run_end`.
        anchors: Number of anchor records whose reference into the chain was checked.
        anchors_witness_verified: Anchors whose receipt was verified offline against a witness
            in the trust list (SPEC 8.4); `rfc3161` receipts in this version.
        labels_sent_to_cloud: Per data label, the count of non-blocked records with a cloud target.
    """

    run_id: str
    record_count: int
    first_seq: int
    last_hash: str
    complete: bool
    anchors: int = 0
    anchors_witness_verified: int = 0
    labels_sent_to_cloud: dict[str, int] = field(default_factory=dict)


def verify_run(
    records: list[dict[str, Any]],
    delegations: dict[str, dict[str, Any]],
    *,
    payloads: dict[str, bytes] | None = None,
    expected_prev_hash: str | None = None,
    witnesses: list[Witness] | None = None,
    strict_witness: bool = False,
) -> RunReport:
    """Verify schema, chain, hashes, delegation and signatures of one run, in record order.

    `delegations` maps `delegation_id` to the delegation object. When `payloads` (digest to body)
    is given, bodies stored in the bundle or inline are checked against their references. A run
    that starts above seq 0 chains from `expected_prev_hash` and takes the first delegation issued
    to its agent, since it has no `run_start` to name one. Anchor receipts are verified against
    `witnesses` (the shipped trust list by default); an anchor that does not verify only lowers
    `anchors_witness_verified`, unless `strict_witness` turns it into a `witness` failure.

    Raises VerificationError at the first failed check.
    """
    if witnesses is None:
        witnesses = load_witnesses()
    if not records:
        raise VerificationError("empty", "run has no records")
    run_id = records[0]["run_id"]
    for edge in (records[0], records[-1]):
        if not isinstance(edge, dict):
            raise VerificationError("schema", "record is not a JSON object")
        errors = validate("record.json", edge, first_only=True)
        if errors:
            raise VerificationError(
                "schema", "; ".join(errors), edge.get("run_id"), edge.get("seq")
            )
    hash_alg = records[0]["hash_alg"]
    first_seq = records[0]["seq"]
    prev_hash = expected_prev_hash if expected_prev_hash is not None else zero_hash(hash_alg)
    if first_seq == 0 and prev_hash != zero_hash(hash_alg):
        raise VerificationError("chain", "run starts at seq 0 but prev hash is not zero", run_id, 0)

    delegation = _delegation_for_run(records[0], delegations, run_id)
    agent_keys = KeySet.from_json(delegation["agent_keys"])
    report = RunReport(run_id, len(records), first_seq, records[-1]["hash"], False)
    seen_ids: set[str] = set()
    ended = False

    for index, record in enumerate(records):
        seq = first_seq + index
        errors = validate("record.json", record, first_only=True)
        if errors:
            raise VerificationError("schema", "; ".join(errors), run_id, seq)
        ext_errors = validate_extensions(record.get("extensions", {}), first_only=True)
        if ext_errors:
            raise VerificationError("schema", "; ".join(ext_errors), run_id, seq)
        if record["run_id"] != run_id:
            raise VerificationError("run", "record belongs to another run", run_id, seq)
        if record["seq"] != seq:
            raise VerificationError("seq", f"expected seq {seq}, got {record['seq']}", run_id, seq)
        if record["record_id"] in seen_ids:
            raise VerificationError("record_id", "record_id repeats within the run", run_id, seq)
        seen_ids.add(record["record_id"])
        if record["hash_alg"] != hash_alg:
            raise VerificationError("hash_alg", "hash algorithm changed within run", run_id, seq)
        if len(record["hash"]) != digest_size(hash_alg) * 2:
            raise VerificationError("hash_alg", "hash length does not match algorithm", run_id, seq)
        if ended:
            raise VerificationError("run_end", "record after run_end", run_id, seq)
        if record["prev_hash"] != prev_hash:
            raise VerificationError(
                "chain", "prev_hash does not match previous record", run_id, seq
            )
        if not check_hash(record):
            raise VerificationError("hash", "record hash mismatch", run_id, seq)
        if record["agent_id"] != delegation["agent_id"]:
            raise VerificationError("delegation", "agent_id differs from delegation", run_id, seq)
        if record["principal_id"] != delegation["principal_id"]:
            raise VerificationError(
                "delegation", "principal_id differs from delegation", run_id, seq
            )
        if not covers(delegation, parse_timestamp(record["occurred_at"])):
            raise VerificationError("delegation", "record outside delegation validity", run_id, seq)
        if not check_signatures(record, DOMAIN_RECORD, agent_keys):
            raise VerificationError("signature", "agent signature invalid", run_id, seq)
        if payloads is not None:
            _check_payload(record, payloads, hash_alg, run_id, seq)
        if record["kind"] == "anchor":
            _check_anchor(record, records, first_seq, run_id, seq)
            report.anchors += 1
            if _witness_verified(record, witnesses):
                report.anchors_witness_verified += 1
            elif strict_witness:
                raise VerificationError("witness", "anchor receipt not verified", run_id, seq)
        if record["kind"] == "run_end":
            ended = True
        if record["target"].get("location") == "cloud" and record.get("outcome") != "blocked":
            for label in record["data_labels"]:
                report.labels_sent_to_cloud[label] = report.labels_sent_to_cloud.get(label, 0) + 1
        prev_hash = record["hash"]

    report.complete = ended
    return report


def _delegation_for_run(
    first: dict[str, Any], delegations: dict[str, dict[str, Any]], run_id: str
) -> dict[str, Any]:
    binding = first.get("extensions", {}).get("sealedrun.delegation")
    if first["seq"] == 0:
        if not binding:
            raise VerificationError("delegation", "run_start lacks sealedrun.delegation", run_id, 0)
        delegation = delegations.get(binding["delegation_id"])
        if delegation is None:
            raise VerificationError("delegation", "delegation not in bundle", run_id, 0)
        if delegation["hash"] != binding["hash"]:
            raise VerificationError("delegation", "delegation hash mismatch", run_id, 0)
    else:
        candidates = [d for d in delegations.values() if d["agent_id"] == first["agent_id"]]
        if not candidates:
            raise VerificationError("delegation", "no delegation for agent", run_id, first["seq"])
        delegation = candidates[0]
    problem = verify_delegation(delegation)
    if problem:
        raise VerificationError("delegation", problem, run_id, first["seq"])
    return delegation


def _check_payload(
    record: dict[str, Any], payloads: dict[str, bytes], hash_alg: str, run_id: str, seq: int
) -> None:
    ref = record.get("payload")
    if not ref or ref["storage"] not in ("bundle", "inline"):
        return
    for side in ("request", "response"):
        expected = ref.get(f"{side}_hash")
        if expected is None:
            continue
        body = payloads.get(expected)
        if body is None:
            raise VerificationError("payload", f"{side} body missing", run_id, seq)
        if payload_digest(hash_alg, body) != expected or len(body) != ref[f"{side}_size"]:
            raise VerificationError("payload", f"{side} body digest mismatch", run_id, seq)


def _check_anchor(
    record: dict[str, Any], records: list[dict[str, Any]], first_seq: int, run_id: str, seq: int
) -> None:
    """Check that an anchor points at an earlier record of this run and carries its hash.

    SPEC 8.1: the receipt digest is the digest the witness was given, so it must equal
    `anchored_hash`. Whether the receipt is genuine is settled by `_witness_verified`.
    """
    anchor = record["extensions"]["sealedrun.anchor"]
    index = anchor["anchored_seq"] - first_seq
    if index < 0 or index >= len(records) or anchor["anchored_seq"] >= seq:
        raise VerificationError("anchor", "anchored_seq not in run before anchor", run_id, seq)
    if records[index]["hash"] != anchor["anchored_hash"]:
        raise VerificationError("anchor", "anchored_hash does not match record", run_id, seq)
    if anchor["receipt"]["digest"] != anchor["anchored_hash"]:
        raise VerificationError(
            "anchor", "receipt digest does not match anchored_hash", run_id, seq
        )


def _witness_verified(record: dict[str, Any], witnesses: list[Witness]) -> bool:
    """Verify the anchor's receipt offline against the trust list (SPEC 8.4).

    `rfc3161` and `rekor` receipts are verified; other types count as bound, not verified.
    """
    anchor = record["extensions"]["sealedrun.anchor"]
    if anchor["type"] == "rfc3161":
        return rfc3161.verify(anchor["receipt"], anchor["witness"], witnesses)
    if anchor["type"] == "rekor":
        return rekor.verify(anchor["receipt"], anchor["witness"], witnesses)
    return False
