import base64
import hashlib
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from asn1crypto import tsp
from cryptography import x509
from sealedrun import VerificationError, verify_run
from sealedrun.anchors import rekor, rfc3161
from sealedrun.anchors.rfc3161 import AnchorError
from sealedrun.schema import SCHEMA_DIR
from sealedrun.trust import Witness, load_witnesses, select

sys.path.insert(0, str(Path(__file__).parent))
from tsa import NOT_AFTER, NOT_BEFORE, TestAuthority, shift

VECTORS = SCHEMA_DIR.parent / "vectors"
DIGEST = "2e5ad85304c65f0accfac67e02c56eba796476d6e538eec989142845ab7a7651"
URL = "https://tsa.test/api/v1/timestamp"


@pytest.fixture(scope="module")
def tsa() -> TestAuthority:
    return TestAuthority()


def trust_for(tsa: TestAuthority, **overrides: Any) -> list[Witness]:
    entry: dict[str, Any] = {
        "type": "rfc3161",
        "uri": URL,
        "subject": "Test TSA Root",
        "start": NOT_BEFORE,
        "end": NOT_AFTER,
        "roots": (tsa.root_pem,),
    }
    entry.update(overrides)
    return [Witness(**entry)]


def good_receipt(tsa: TestAuthority, **respond: Any) -> dict[str, Any]:
    req = rfc3161.request(DIGEST)
    return rfc3161.receipt_from(req, tsa.respond(req.body, **respond), tsa.chain_pems)


def test_request_is_a_sha256_timestamp_query_with_nonce_and_cert_req() -> None:
    req = rfc3161.request(DIGEST)
    parsed = tsp.TimeStampReq.load(req.body, strict=True)
    assert parsed["message_imprint"]["hash_algorithm"]["algorithm"].native == "sha256"
    assert (
        parsed["message_imprint"]["hashed_message"].native
        == hashlib.sha256(bytes.fromhex(DIGEST)).digest()
    )
    assert parsed["nonce"].native == req.nonce > 0
    assert parsed["cert_req"].native is True
    assert req.digest == DIGEST


def test_receipt_from_carries_token_chain_nonce_time_and_policy(tsa: TestAuthority) -> None:
    req = rfc3161.request(DIGEST)
    receipt = rfc3161.receipt_from(req, tsa.respond(req.body), tsa.chain_pems)
    assert receipt["digest"] == DIGEST
    assert receipt["imprint_alg"] == "sha256"
    assert receipt["nonce"] == str(req.nonce)
    assert receipt["chain"] == tsa.chain_pems
    assert receipt["gen_time"] == "2026-09-16T12:00:07.000Z"
    assert receipt["policy"] == "1.3.6.1.4.1.99999.1"
    token = base64.b64decode(receipt["token"])
    assert tsp.TimeStampResp.load(tsa.respond(req.body))["status"]["status"].native == "granted"
    assert token[0] == 0x30


@pytest.mark.parametrize(
    ("respond", "message"),
    [
        ({"status": "rejection"}, "refused"),
        ({"nonce": 7}, "nonce"),
        ({"imprint": b"\0" * 32}, "imprint"),
    ],
)
def test_receipt_from_rejects_answers_that_do_not_fit(
    tsa: TestAuthority, respond: dict[str, Any], message: str
) -> None:
    req = rfc3161.request(DIGEST)
    with pytest.raises(AnchorError, match=message):
        rfc3161.receipt_from(req, tsa.respond(req.body, **respond))


def test_receipt_from_rejects_garbage() -> None:
    with pytest.raises(AnchorError, match="unreadable"):
        rfc3161.receipt_from(rfc3161.request(DIGEST), b"\x30\x03\x02\x01\x00")


def test_verify_leaf_only_token_with_chain_in_receipt(tsa: TestAuthority) -> None:
    assert rfc3161.verify(good_receipt(tsa), URL, trust_for(tsa)) is True


def test_verify_full_chain_token_without_receipt_chain(tsa: TestAuthority) -> None:
    req = rfc3161.request(DIGEST)
    receipt = rfc3161.receipt_from(req, tsa.respond(req.body, include="chain"), [])
    assert rfc3161.verify(receipt, URL, trust_for(tsa)) is True


def test_verify_needs_the_leaf_somewhere(tsa: TestAuthority) -> None:
    req = rfc3161.request(DIGEST)
    receipt = rfc3161.receipt_from(req, tsa.respond(req.body, include="none"), [])
    assert rfc3161.verify(receipt, URL, trust_for(tsa)) is False


def test_verify_unknown_witness_is_not_verified(tsa: TestAuthority) -> None:
    assert rfc3161.verify(good_receipt(tsa), "https://other.test/tsa", trust_for(tsa)) is False
    assert rfc3161.verify(good_receipt(tsa), URL, []) is False


def test_verify_root_from_receipt_is_never_trusted(tsa: TestAuthority) -> None:
    other = TestAuthority("Other")
    receipt = good_receipt(tsa)
    assert rfc3161.verify(receipt, URL, trust_for(other)) is False
    receipt["chain"] = [*receipt["chain"], other.root_pem]
    assert rfc3161.verify(receipt, URL, trust_for(other)) is False


def test_verify_receipt_chain_cannot_smuggle_a_root_under_another_spelling(
    tsa: TestAuthority,
) -> None:
    attacker = TestAuthority("Fake", root_issuer="fake Root")
    req = rfc3161.request(DIGEST)
    for include in ("leaf", "chain"):
        forged = attacker.respond(req.body, include=include)
        receipt = rfc3161.receipt_from(req, forged, attacker.chain_pems)
        assert rfc3161.verify(receipt, URL, trust_for(tsa)) is False
    receipt = rfc3161.receipt_from(req, attacker.respond(req.body), [attacker.root_pem])
    assert rfc3161.verify(receipt, URL, trust_for(tsa)) is False


def test_verify_receipt_chain_only_adds_certificates_a_root_signed(tsa: TestAuthority) -> None:
    other = TestAuthority("Other")
    receipt = good_receipt(tsa)
    receipt["chain"] = [*receipt["chain"], *other.chain_pems]
    assert rfc3161.verify(receipt, URL, trust_for(tsa)) is True
    trusted = x509.load_pem_x509_certificate(tsa.root_pem.encode())
    offered = [x509.load_pem_x509_certificate(pem.encode()) for pem in receipt["chain"]]
    added = rfc3161._issued_under([trusted], offered)
    assert [c.subject.rfc4514_string() for c in added] == ["CN=Test TSA CA"]


def test_verify_forged_leaf_in_front_of_the_bag_does_not_help(tsa: TestAuthority) -> None:
    attacker = TestAuthority("Attacker")
    req = rfc3161.request(DIGEST)
    honest = tsa.respond(req.body, prepend=[attacker.leaf, attacker.ca], include="chain")
    assert rfc3161.verify(rfc3161.receipt_from(req, honest, []), URL, trust_for(tsa)) is True
    forged = attacker.respond(req.body, prepend=[tsa.leaf, tsa.ca], include="chain")
    assert rfc3161.verify(rfc3161.receipt_from(req, forged, []), URL, trust_for(tsa)) is False
    forged = attacker.respond(req.body, prepend=[tsa.leaf, tsa.ca], include="chain")
    receipt = rfc3161.receipt_from(req, forged, tsa.chain_pems)
    assert rfc3161.verify(receipt, URL, trust_for(tsa)) is False


def test_verify_leaf_without_timestamping_eku(tsa: TestAuthority) -> None:
    plain = TestAuthority("Plain", leaf_eku=False)
    assert rfc3161.verify(good_receipt(plain), URL, trust_for(plain)) is False


@pytest.mark.parametrize(
    "change",
    [
        {"nonce": "1"},
        {"digest": "f" * 64},
        {"gen_time": "2026-01-01T00:00:00.000Z"},
        {"policy": "1.2.3"},
        {"imprint_alg": "sha256", "token": base64.b64encode(b"\x30\x00").decode()},
    ],
)
def test_verify_rejects_edited_receipt(tsa: TestAuthority, change: dict[str, Any]) -> None:
    receipt = {**good_receipt(tsa), **change}
    assert rfc3161.verify(receipt, URL, trust_for(tsa)) is False


def test_verify_rejects_flipped_token_byte(tsa: TestAuthority) -> None:
    receipt = good_receipt(tsa)
    token = bytearray(base64.b64decode(receipt["token"]))
    token[-1] ^= 1
    receipt["token"] = base64.b64encode(bytes(token)).decode()
    assert rfc3161.verify(receipt, URL, trust_for(tsa)) is False


def test_verify_gen_time_must_lie_within_valid_for(tsa: TestAuthority) -> None:
    early = good_receipt(tsa, gen_time=shift(NOT_BEFORE, days=-1))
    assert rfc3161.verify(early, URL, trust_for(tsa)) is False
    inside = good_receipt(tsa, gen_time=datetime(2030, 1, 1, tzinfo=UTC))
    assert rfc3161.verify(inside, URL, trust_for(tsa)) is True
    assert (
        rfc3161.verify(inside, URL, trust_for(tsa, end=datetime(2029, 1, 1, tzinfo=UTC))) is False
    )
    assert rfc3161.verify(inside, URL, trust_for(tsa, end=None)) is True


def test_verify_expired_certificate_at_gen_time(tsa: TestAuthority) -> None:
    late = good_receipt(tsa, gen_time=shift(NOT_AFTER, days=1))
    assert rfc3161.verify(late, URL, trust_for(tsa, end=None)) is False


def test_shipped_trust_list() -> None:
    witnesses = load_witnesses()
    assert [(w.type, w.uri) for w in witnesses] == [
        ("rfc3161", "https://timestamp.sigstore.dev/api/v1/timestamp"),
        ("rfc3161", "http://timestamp.digicert.com"),
        ("rekor", "https://rekor.sigstore.dev"),
    ]
    for witness in witnesses[:2]:
        assert witness.roots and witness.roots[0].startswith("-----BEGIN CERTIFICATE-----")
    rekor = witnesses[2]
    assert rekor.log_id == "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
    assert select(witnesses, "rekor", "x", log_id=rekor.log_id) == [rekor]
    assert select(witnesses, "rfc3161", "http://timestamp.digicert.com") == [witnesses[1]]
    assert (
        load_witnesses(Path(__file__).parents[1] / "src/sealedrun/trust/witnesses.json")
        == witnesses
    )


def load_cases() -> list[dict[str, Any]]:
    return json.loads((VECTORS / "anchors" / "cases.json").read_text())


@pytest.mark.parametrize("case", load_cases(), ids=lambda c: c["name"])
def test_captured_receipt_vectors(case: dict[str, Any]) -> None:
    module = {"rfc3161": rfc3161, "rekor": rekor}[case["type"]]
    receipt = {k: v for k, v in case["receipt"].items() if v is not None}
    assert module.verify(receipt, case["witness"], load_witnesses()) is case["verified"]


def load_hostile() -> tuple[list[Witness], list[dict[str, Any]]]:
    document = json.loads((VECTORS / "anchors" / "hostile.json").read_text())
    return [Witness.from_json(e) for e in document["trust"]], document["cases"]


@pytest.mark.parametrize("case", load_hostile()[1], ids=lambda c: c["name"])
def test_hostile_receipt_vectors(case: dict[str, Any]) -> None:
    trust, _ = load_hostile()
    assert rfc3161.verify(case["receipt"], case["witness"], trust) is case["verified"]


def test_reference_run_anchor_is_witness_verified() -> None:
    records = [
        json.loads(line)
        for line in (VECTORS / "records" / "valid-run.jsonl").read_text().splitlines()
        if line
    ]
    delegation = json.loads((VECTORS / "delegations" / "valid.json").read_text())
    delegations = {delegation["delegation_id"]: delegation}
    report = verify_run(records, delegations)
    assert (report.anchors, report.anchors_witness_verified) == (1, 1)
    report = verify_run(records, delegations, witnesses=[])
    assert (report.anchors, report.anchors_witness_verified) == (1, 0)
    with pytest.raises(VerificationError) as failure:
        verify_run(records, delegations, witnesses=[], strict_witness=True)
    assert failure.value.check == "witness"
