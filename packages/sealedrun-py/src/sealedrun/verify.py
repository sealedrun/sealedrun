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
from sealedrun.scope import Finding, Scope, scope_within
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
        findings: Records outside the delegation's scope (SPEC 6.5), in seq order. They do not
            break integrity; under `strict_scope` the first one fails the run instead.
        receipts_proxy: Receipts the recorder wrote from the reply it relayed (SPEC 10.9).
        receipts_self_reported: Receipts the caller supplied.
    """

    run_id: str
    record_count: int
    first_seq: int
    last_hash: str
    complete: bool
    anchors: int = 0
    anchors_witness_verified: int = 0
    labels_sent_to_cloud: dict[str, int] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    receipts_proxy: int = 0
    receipts_self_reported: int = 0


def verify_run(
    records: list[dict[str, Any]],
    delegations: dict[str, dict[str, Any]],
    *,
    payloads: dict[str, bytes] | None = None,
    expected_prev_hash: str | None = None,
    witnesses: list[Witness] | None = None,
    strict_witness: bool = False,
    strict_scope: bool = False,
) -> RunReport:
    """Verify schema, chain, hashes, delegation and signatures of one run, in record order.

    `delegations` maps `delegation_id` to the delegation object. When `payloads` (digest to body)
    is given, bodies stored in the bundle or inline are checked against their references. A run
    that starts above seq 0 chains from `expected_prev_hash` and takes the first delegation issued
    to its agent, since it has no `run_start` to name one. Anchor receipts are verified against
    `witnesses` (the shipped trust list by default); an anchor that does not verify only lowers
    `anchors_witness_verified`, unless `strict_witness` turns it into a `witness` failure. A
    record outside the delegation's structured scope (SPEC 6.5) is listed in `findings`, unless
    `strict_scope` turns the first one into a failure named after its check (`scope.target` and
    the like).

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
    try:
        scope = Scope.parse(delegation.get("scope"))
    except ValueError as error:
        raise VerificationError("schema", str(error), run_id, first_seq) from None
    agent_keys = KeySet.from_json(delegation["agent_keys"])
    report = RunReport(run_id, len(records), first_seq, records[-1]["hash"], False)
    seen_ids: set[str] = set()
    ended = False
    policy_set_hash: str | None = None

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
        policy_set_hash = _check_context(record, policy_set_hash, run_id, seq)
        observed_by = _check_receipt(record, run_id, seq)
        if observed_by == "proxy":
            report.receipts_proxy += 1
        elif observed_by == "self_reported":
            report.receipts_self_reported += 1
        for finding in scope.findings(record, index + 1):
            if strict_scope:
                raise VerificationError(finding.check, finding.reason, run_id, seq)
            report.findings.append(finding)
        if record["target"].get("location") == "cloud" and record.get("outcome") != "blocked":
            for label in record["data_labels"]:
                report.labels_sent_to_cloud[label] = report.labels_sent_to_cloud.get(label, 0) + 1
        prev_hash = record["hash"]

    report.complete = ended
    return report


def parent_of(records: list[dict[str, Any]]) -> dict[str, str] | None:
    """Return the parent link named in a run's `run_start` (SPEC 6.4), or None."""
    if not records or records[0].get("kind") != "run_start":
        return None
    binding = records[0].get("extensions", {}).get("sealedrun.delegation", {})
    run_id = binding.get("parent_run_id")
    if run_id is None:
        return None
    return {
        "run_id": run_id,
        "record_id": binding["parent_record_id"],
        "delegation_hash": binding["parent_delegation_hash"],
    }


def check_parent_links(
    runs: dict[str, list[dict[str, Any]]], delegations: dict[str, dict[str, Any]]
) -> list[str]:
    """Apply the `parent.*` checks of SPEC 6.4 to every run that names a parent among `runs`.

    Each run is expected to have passed `verify_run` already. Returns the ids of runs whose
    parent run is not among `runs` (the relying party asks for that bundle). Raises
    VerificationError with check `parent.record`, `parent.kind`, `parent.time`,
    `parent.delegation` or `parent.scope` on the child run.
    """
    unresolved: list[str] = []
    for run_id, records in runs.items():
        parent = parent_of(records)
        if parent is None:
            continue
        parent_records = runs.get(parent["run_id"])
        if parent_records is None:
            unresolved.append(run_id)
            continue
        asked = next((r for r in parent_records if r["record_id"] == parent["record_id"]), None)
        if asked is None:
            raise VerificationError("parent.record", "parent record not in parent run", run_id, 0)
        if asked["kind"] != "tool_call":
            raise VerificationError("parent.kind", "parent record is not a tool_call", run_id, 0)
        if parse_timestamp(records[0]["occurred_at"]) < parse_timestamp(
            parent_records[0]["occurred_at"]
        ):
            raise VerificationError(
                "parent.time", "run_start is before the parent run's run_start", run_id, 0
            )
        parent_binding = parent_records[0].get("extensions", {}).get("sealedrun.delegation", {})
        if parent_binding.get("hash") != parent["delegation_hash"]:
            raise VerificationError(
                "parent.delegation", "parent_delegation_hash differs from parent run", run_id, 0
            )
        child_scope = Scope.parse(_bound_delegation(records, delegations).get("scope"))
        parent_scope = Scope.parse(_bound_delegation(parent_records, delegations).get("scope"))
        problem = scope_within(child_scope, parent_scope)
        if problem is not None:
            raise VerificationError("parent.scope", problem, run_id, 0)
    return unresolved


def _bound_delegation(
    records: list[dict[str, Any]], delegations: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    binding = records[0].get("extensions", {}).get("sealedrun.delegation", {})
    return delegations.get(binding.get("delegation_id"), {})


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


def _check_context(
    record: dict[str, Any], policy_set_hash: str | None, run_id: str, seq: int
) -> str | None:
    """Apply SPEC 10.6 to one record and return the run's policy set digest, if any.

    `sealedrun.context` sits on `run_start` only, and every `policy` block that names a policy
    set names the run's.
    """
    context = record.get("extensions", {}).get("sealedrun.context")
    if context is not None:
        if record["kind"] != "run_start":
            raise VerificationError(
                "context", "sealedrun.context on a record other than run_start", run_id, seq
            )
        policy_set_hash = context.get("policy_set_hash")
    policy = record.get("policy")
    if policy is not None and policy_set_hash is not None:
        declared = policy.get("policy_set_hash")
        if declared is not None and declared != policy_set_hash:
            raise VerificationError(
                "context", "policy_set_hash differs from the run's context", run_id, seq
            )
    return policy_set_hash


def _check_receipt(record: dict[str, Any], run_id: str, seq: int) -> str | None:
    """Apply SPEC 10.9 to one record and return the receipt's `observed_by`, if any.

    A `proxy` receipt sits on a proxied record, is an `http_response` and carries the digest of
    the response body the record already names; a proxied record carries no other receipt.
    """
    extensions = record.get("extensions", {})
    receipt = extensions.get("sealedrun.receipt")
    proxied = "sealedrun.proxy" in extensions
    if receipt is None:
        return None
    observed_by = receipt["observed_by"]
    if observed_by == "proxy":
        if not proxied:
            raise VerificationError(
                "receipt", "proxy receipt on a record without sealedrun.proxy", run_id, seq
            )
        if receipt["kind"] != "http_response":
            raise VerificationError("receipt", "proxy receipt is not an http_response", run_id, seq)
        payload = record.get("payload") or {}
        if receipt.get("digest") is None or receipt["digest"] != payload.get("response_hash"):
            raise VerificationError(
                "receipt", "receipt digest differs from payload.response_hash", run_id, seq
            )
        if receipt.get("digest_alg", record["hash_alg"]) != record["hash_alg"]:
            raise VerificationError("receipt", "receipt digest_alg differs from run", run_id, seq)
    elif proxied:
        raise VerificationError("receipt", "self-reported receipt on a proxied record", run_id, seq)
    return str(observed_by)


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
