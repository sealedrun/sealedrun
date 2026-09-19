import copy
from itertools import pairwise
from typing import Any

import pytest
from sealedrun import PrivateKeySet, RunWriter, VerificationError, verify_run
from sealedrun.schema import validate


def test_run_is_valid(run: RunWriter, delegation: dict[str, Any]) -> None:
    report = verify_run(run.records, {delegation["delegation_id"]: delegation})
    assert report.record_count == 5
    assert report.complete
    assert report.anchors == 1
    assert report.labels_sent_to_cloud == {"pii": 1}
    assert all(validate("record.json", r) == [] for r in run.records)


def test_chain_links(run: RunWriter) -> None:
    records = run.records
    assert records[0]["prev_hash"] == "0" * 64
    for prev, cur in pairwise(records):
        assert cur["prev_hash"] == prev["hash"]
        assert cur["seq"] == prev["seq"] + 1


def _expect(
    records: list[dict[str, Any]], delegation: dict[str, Any], check: str, seq: int
) -> None:
    with pytest.raises(VerificationError) as info:
        verify_run(records, {delegation["delegation_id"]: delegation})
    assert info.value.check == check
    assert info.value.seq == seq


def test_tampered_field(run: RunWriter, delegation: dict[str, Any]) -> None:
    records = copy.deepcopy(run.records)
    records[1]["data_labels"] = []
    _expect(records, delegation, "hash", 1)


def test_tampered_hash_and_resigned_by_other_key(
    run: RunWriter, delegation: dict[str, Any], keyfactory: Any
) -> None:
    from sealedrun.signing import DOMAIN_RECORD, seal

    records = copy.deepcopy(run.records)
    records[1]["data_labels"] = []
    records[1] = seal(records[1], DOMAIN_RECORD, keyfactory(b"attacker-"))
    _expect(records, delegation, "signature", 1)


def test_deleted_middle_record(run: RunWriter, delegation: dict[str, Any]) -> None:
    records = copy.deepcopy(run.records)
    del records[2]
    _expect(records, delegation, "seq", 2)


def test_reordered_records(run: RunWriter, delegation: dict[str, Any]) -> None:
    records = copy.deepcopy(run.records)
    records[1], records[2] = records[2], records[1]
    _expect(records, delegation, "seq", 1)


def test_truncated_run_is_incomplete(run: RunWriter, delegation: dict[str, Any]) -> None:
    report = verify_run(run.records[:-1], {delegation["delegation_id"]: delegation})
    assert not report.complete


def test_record_after_run_end(
    run: RunWriter, delegation: dict[str, Any], agent: PrivateKeySet
) -> None:
    writer = RunWriter(agent, delegation, run_id=run.run_id)
    writer.records = list(run.records)
    writer.closed = False
    writer.append("note", target={"type": "none", "name": "late"})
    _expect(writer.records, delegation, "run_end", 5)


def test_missing_delegation(run: RunWriter) -> None:
    with pytest.raises(VerificationError) as info:
        verify_run(run.records, {})
    assert info.value.check == "delegation"


def test_expired_delegation(run: RunWriter, delegation: dict[str, Any], keyfactory: Any) -> None:
    from sealedrun.signing import DOMAIN_DELEGATION, seal

    expired = seal(
        {**delegation, "not_after": "2026-09-16T12:00:02.000Z"},
        DOMAIN_DELEGATION,
        keyfactory(b"principal-"),
    )
    records = copy.deepcopy(run.records)
    records[0]["extensions"]["sealedrun.delegation"]["hash"] = expired["hash"]
    with pytest.raises(VerificationError) as info:
        verify_run(records, {expired["delegation_id"]: expired})
    assert info.value.check == "hash"
    assert info.value.seq == 0


def test_bad_anchor(run: RunWriter, delegation: dict[str, Any], agent: PrivateKeySet) -> None:
    writer = RunWriter(agent, delegation, run_id=run.run_id)
    writer.records = list(run.records[:3])
    writer.append(
        "anchor",
        target={"type": "witness", "name": "rekor"},
        extensions={
            "sealedrun.anchor": {
                "type": "rekor",
                "anchored_hash": "f" * 64,
                "anchored_seq": 2,
                "receipt": {},
                "witness": "x",
            }
        },
    )
    _expect(writer.records, delegation, "anchor", 3)


def test_writer_guards(agent: PrivateKeySet, delegation: dict[str, Any]) -> None:
    writer = RunWriter(agent, delegation)
    with pytest.raises(ValueError):
        writer.append("note", target={"type": "none", "name": "x"})
    writer.start()
    with pytest.raises(ValueError):
        writer.start()
    writer.end()
    with pytest.raises(ValueError):
        writer.append("note", target={"type": "none", "name": "x"})


def test_sha384_run(principal: PrivateKeySet, agent: PrivateKeySet) -> None:
    from sealedrun import create_delegation

    d = create_delegation(principal, agent.public, hash_alg="sha-384")
    writer = RunWriter(agent, d)
    writer.start()
    writer.end()
    assert len(writer.records[0]["hash"]) == 96
    assert verify_run(writer.records, {d["delegation_id"]: d}).complete
