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


def test_delegation_vector() -> None:
    delegation = load(VECTORS / "delegations" / "valid.json")
    expected = load(VECTORS / "delegations" / "expected.json")
    assert isinstance(delegation, dict) and isinstance(expected, dict)
    assert verify_delegation(delegation) is None
    assert delegation["hash"] == expected["valid.json"]["hash"]


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
    if case["ok"]:
        report = verify_bundle(read_bundle(data))
        assert len(report.runs) == case["runs"]
        assert report.runs[0].record_count == case["records"]
        assert report.runs[0].complete == case["complete"]
        return
    with pytest.raises(VerificationError) as info:
        verify_bundle(read_bundle(data))
    assert info.value.check == case["check"]
    if "seq" in case:
        assert info.value.seq == case["seq"]


def test_regeneration_is_hash_stable(tmp_path: Path) -> None:
    from sealedrun.vectors import generate

    generate(tmp_path)
    fresh = load(tmp_path / "vectors" / "records" / "expected.json")
    committed = load(VECTORS / "records" / "expected.json")
    assert fresh == committed
    assert load(tmp_path / "vectors" / "delegations" / "expected.json") == load(
        VECTORS / "delegations" / "expected.json"
    )
