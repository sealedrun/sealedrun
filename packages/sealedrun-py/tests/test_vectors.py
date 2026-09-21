import json
from pathlib import Path

import pytest
from sealedrun import (
    KeySet,
    PrivateKeySet,
    VerificationError,
    canonicalize,
    read_bundle,
    verify_bundle,
    verify_delegation,
    verify_run,
)
from sealedrun.keys import verify_one
from sealedrun.schema import SCHEMA_DIR
from sealedrun.signing import check_hash

VECTORS = SCHEMA_DIR.parent / "vectors"


def load(path: Path) -> object:
    return json.loads(path.read_text())


def records_of(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


@pytest.mark.parametrize("case", sorted(p.stem for p in (VECTORS / "jcs").glob("*.json")))
def test_jcs_reference_vectors(case: str) -> None:
    source = load(VECTORS / "jcs" / f"{case}.json")
    assert canonicalize(source) == (VECTORS / "jcs" / f"{case}.expected").read_bytes()


def test_keys_derive_from_seeds() -> None:
    keys = load(VECTORS / "keys.json")
    assert isinstance(keys, dict)
    for name in ("principal", "agent", "attacker"):
        entry = keys[name]
        derived = PrivateKeySet.from_seeds({a: bytes.fromhex(s) for a, s in entry["seeds"].items()})
        assert derived.public.to_json() == entry["public"]
        assert derived.public.kid == entry["kid"]
        assert KeySet.from_json(entry["public"]).kid == entry["kid"]


def test_ed25519_edge_cases() -> None:
    cases = load(VECTORS / "signatures" / "ed25519.json")
    assert isinstance(cases, list) and len(cases) == 5
    for case in cases:
        accepted = verify_one(
            "ed25519",
            bytes.fromhex(case["public_key"]),
            bytes.fromhex(case["message"]),
            bytes.fromhex(case["signature"]),
        )
        assert accepted == case["ok"], case["name"]


@pytest.mark.parametrize(
    "name", sorted(p.name for p in (VECTORS / "delegations").glob("*.json") if p.stem != "expected")
)
def test_delegation_vectors(name: str) -> None:
    delegation = load(VECTORS / "delegations" / name)
    expected = load(VECTORS / "delegations" / "expected.json")
    assert isinstance(delegation, dict) and isinstance(expected, dict)
    if expected[name]["ok"]:
        assert verify_delegation(delegation) is None
    else:
        assert verify_delegation(delegation) == "principal signature invalid"
    assert delegation["hash"] == expected[name]["hash"]


def test_valid_run_hashes() -> None:
    records = records_of(VECTORS / "records" / "valid-run.jsonl")
    expected = load(VECTORS / "records" / "expected.json")
    assert isinstance(expected, dict)
    for record, exp in zip(records, expected["valid-run.jsonl"], strict=True):
        assert check_hash(record)
        assert record["hash"] == exp["hash"]
        assert record["prev_hash"] == exp["prev_hash"]
    delegation = load(VECTORS / "delegations" / "valid.json")
    assert isinstance(delegation, dict)
    report = verify_run(records, {delegation["delegation_id"]: delegation})
    assert report.complete
    assert report.anchors == 1


@pytest.mark.parametrize("name", sorted(p.name for p in (VECTORS / "chains").glob("*.jsonl")))
def test_negative_chains(name: str) -> None:
    expected = load(VECTORS / "chains" / "expected.json")
    assert isinstance(expected, dict)
    case = expected[name]
    delegation = (
        load(VECTORS / "chains" / case["delegation"])
        if "delegation" in case
        else load(VECTORS / "delegations" / "valid.json")
    )
    assert isinstance(delegation, dict)
    with pytest.raises(VerificationError) as info:
        verify_run(records_of(VECTORS / "chains" / name), {delegation["delegation_id"]: delegation})
    assert (info.value.check, info.value.seq) == (case["check"], case["seq"])


@pytest.mark.parametrize("name", sorted(p.name for p in (VECTORS / "bundle").glob("*.zip")))
def test_bundle_vectors(name: str) -> None:
    expected = load(VECTORS / "bundle" / "expected.json")
    assert isinstance(expected, dict)
    case = expected[name]
    data = (VECTORS / "bundle" / name).read_bytes()
    trusted = case.get("trusted_principals")
    if case["ok"]:
        report = verify_bundle(read_bundle(data), trusted)
        assert report.principal_trusted == (trusted is not None)
        assert len(report.runs) == case["runs"]
        assert report.runs[0].record_count == case["records"]
        assert report.runs[0].complete == case["complete"]
        return
    with pytest.raises(VerificationError) as info:
        verify_bundle(read_bundle(data), trusted)
    assert info.value.check == case["check"]
    if "seq" in case:
        assert info.value.seq == case["seq"]


def test_unknown_principal_without_trust_anchor_is_integrity_only() -> None:
    keys = load(VECTORS / "keys.json")
    assert isinstance(keys, dict)
    report = verify_bundle(read_bundle((VECTORS / "bundle" / "unknown-principal.zip").read_bytes()))
    assert report.principal_trusted is False
    assert report.principal_id == keys["attacker"]["kid"]
    assert report.exporter_agent_id != ""


def test_regeneration_is_hash_stable(tmp_path: Path) -> None:
    from sealedrun.vectors import generate

    generate(tmp_path)
    fresh = load(tmp_path / "vectors" / "records" / "expected.json")
    committed = load(VECTORS / "records" / "expected.json")
    assert fresh == committed
    assert load(tmp_path / "vectors" / "delegations" / "expected.json") == load(
        VECTORS / "delegations" / "expected.json"
    )
