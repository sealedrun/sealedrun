import base64
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from sealedrun.anchors import rekor
from sealedrun.anchors.rekor import RekorError
from sealedrun.trust import Witness, load_witnesses

sys.path.insert(0, str(Path(__file__).parent))
from rekor_fake import FakeRekor

DIGEST = "2e5ad85304c65f0accfac67e02c56eba796476d6e538eec989142845ab7a7651"
URL = "https://rekor.test"


@pytest.fixture
def log() -> FakeRekor:
    return FakeRekor()


def trust_for(log: FakeRekor, **overrides: Any) -> list[Witness]:
    entry: dict[str, Any] = {
        "type": "rekor",
        "uri": URL,
        "subject": "test log",
        "start": datetime(2025, 1, 1, tzinfo=UTC),
        "public_key": log.log_key_pem,
        "log_id": log.log_id,
    }
    entry.update(overrides)
    return [Witness(**entry)]


def submit(log: FakeRekor, digest: str = DIGEST, **add: Any) -> dict[str, Any]:
    key = rekor.generate_key()
    pem = rekor.public_pem(key)
    signature = rekor.sign_head(key, digest)
    answer = log.add(rekor.entry_for(digest, signature, pem), **add)
    return rekor.receipt_from(answer, URL + "/", digest, signature, pem)


def test_entry_shape_and_signature() -> None:
    key = rekor.generate_key()
    signature = rekor.sign_head(key, DIGEST)
    entry = rekor.entry_for(DIGEST, signature, rekor.public_pem(key))
    assert entry["kind"] == "hashedrekord" and entry["apiVersion"] == "0.0.1"
    assert entry["spec"]["data"]["hash"] == {"algorithm": "sha256", "value": DIGEST}
    assert base64.b64decode(entry["spec"]["signature"]["publicKey"]["content"]).startswith(
        b"-----BEGIN PUBLIC KEY-----"
    )
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import utils

    key.public_key().verify(
        signature, bytes.fromhex(DIGEST), ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )


def test_receipt_from_single_leaf_and_multi_leaf_trees(log: FakeRekor) -> None:
    receipt = submit(log)
    assert receipt["log_url"] == URL
    assert receipt["inclusion_proof"]["tree_size"] == 1
    assert receipt["inclusion_proof"]["hashes"] == []
    assert rekor.verify(receipt, URL, trust_for(log)) is True
    log.fill(5)
    later = submit(log, "ab" * 32)
    assert later["inclusion_proof"]["tree_size"] == 7
    assert len(later["inclusion_proof"]["hashes"]) == 2
    assert rekor.verify(later, URL, trust_for(log)) is True
    assert rekor.verify(receipt, URL, trust_for(log)) is True


def test_receipt_from_rejects_answers_that_do_not_fit(log: FakeRekor) -> None:
    key = rekor.generate_key()
    pem = rekor.public_pem(key)
    signature = rekor.sign_head(key, DIGEST)
    answer = log.add(rekor.entry_for(DIGEST, signature, pem))
    with pytest.raises(RekorError, match="submitted digest"):
        rekor.receipt_from(answer, URL, "f" * 64, signature, pem)
    with pytest.raises(RekorError, match="exactly one"):
        rekor.receipt_from({}, URL, DIGEST, signature, pem)
    broken = {u: {**e, "verification": {}} for u, e in answer.items()}
    with pytest.raises(RekorError, match="unreadable"):
        rekor.receipt_from(broken, URL, DIGEST, signature, pem)


def test_verify_matches_by_log_id_when_the_url_differs(log: FakeRekor) -> None:
    receipt = submit(log)
    assert rekor.verify(receipt, "https://mirror.test", trust_for(log, uri="https://x")) is True
    assert rekor.verify(receipt, URL, trust_for(log, uri="https://x", log_id=None)) is False
    assert rekor.verify(receipt, URL, []) is False


def test_verify_rejects_wrong_log_key(log: FakeRekor) -> None:
    receipt = submit(log)
    other = FakeRekor()
    assert rekor.verify(receipt, URL, trust_for(other, uri=URL)) is False
    assert rekor.verify(receipt, URL, trust_for(other, uri=URL, log_id=log.log_id)) is False


def test_verify_rejects_edits(log: FakeRekor) -> None:
    log.fill(3)
    receipt = submit(log)
    proof = receipt["inclusion_proof"]
    bad_hashes = ["0" * 64, *proof["hashes"][1:]]
    for change in (
        {"digest": "f" * 64},
        {"log_index": receipt["log_index"] + 1},
        {"integrated_time": receipt["integrated_time"] + 1},
        {"integrated_time": 1_500_000_000},
        {"signature": base64.b64encode(b"\x30\x00").decode()},
        {"inclusion_proof": {**proof, "hashes": bad_hashes}},
        {"inclusion_proof": {**proof, "root_hash": "0" * 64}},
        {"inclusion_proof": {**proof, "tree_size": proof["tree_size"] + 1}},
        {"inclusion_proof": {**proof, "log_index": 0}},
        {"inclusion_proof": {**proof, "checkpoint": "garbage"}},
        {"body": base64.b64encode(b"{}").decode()},
    ):
        assert rekor.verify({**receipt, **change}, URL, trust_for(log)) is False, change


def test_verify_checkpoint_signature_and_cosignatures(log: FakeRekor) -> None:
    receipt = submit(log)
    proof = receipt["inclusion_proof"]
    root = base64.b64decode(proof["checkpoint"].split("\n")[2])
    forged = log.checkpoint(proof["tree_size"], root, key=ec.generate_private_key(ec.SECP256R1()))
    assert (
        rekor.verify(
            {**receipt, "inclusion_proof": {**proof, "checkpoint": forged}}, URL, trust_for(log)
        )
        is False
    )
    log.cosign = True
    cosigned = log.checkpoint(proof["tree_size"], root)
    assert cosigned.count("—") == 2
    assert (
        rekor.verify(
            {**receipt, "inclusion_proof": {**proof, "checkpoint": cosigned}}, URL, trust_for(log)
        )
        is True
    )
    unsigned = proof["checkpoint"].split("\n\n")[0] + "\n\n"
    assert (
        rekor.verify(
            {**receipt, "inclusion_proof": {**proof, "checkpoint": unsigned}}, URL, trust_for(log)
        )
        is False
    )


def test_verify_without_time_needs_no_set(log: FakeRekor) -> None:
    receipt = submit(log)
    del receipt["integrated_time"]
    del receipt["signed_entry_timestamp"]
    assert rekor.verify(receipt, URL, trust_for(log)) is True
    receipt["integrated_time"] = 1_790_000_000
    assert rekor.verify(receipt, URL, trust_for(log)) is False


def test_captured_public_log_entry() -> None:
    doc = json.loads(
        (Path(__file__).parents[3] / "spec/vectors/anchors/rekor-sigstore.json").read_text()
    )
    receipt = doc["receipt"]
    assert receipt["digest"] == DIGEST
    assert receipt["log_url"] == "https://rekor.sigstore.dev"
    assert receipt["inclusion_proof"]["log_index"] != receipt["log_index"]
    assert rekor.verify(receipt, doc["witness"], load_witnesses()) is True
