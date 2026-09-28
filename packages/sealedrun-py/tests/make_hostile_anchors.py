"""Write `spec/vectors/anchors/hostile.json`: forged RFC 3161 receipts every verifier must refuse.

Run from `packages/sealedrun-py`: `uv run python tests/make_hostile_anchors.py`. The file carries
its own throw-away trust list, so the cases are self-contained; the keys are fresh on every run,
which is fine because only the committed output is used.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any

from asn1crypto import cms
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sealedrun.anchors import rfc3161
from sealedrun.schema import SCHEMA_DIR
from sealedrun.timeutil import format_timestamp

sys.path.insert(0, str(Path(__file__).parent))
from tsa import NOT_AFTER, NOT_BEFORE, TestAuthority, certificate

OUT = SCHEMA_DIR.parent / "vectors" / "anchors" / "hostile.json"
URL = "https://hostile.test/tsa"
DIGEST = "2e5ad85304c65f0accfac67e02c56eba796476d6e538eec989142845ab7a7651"


def _pem(cert: Any) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _case(name: str, receipt: dict[str, Any], verified: bool, note: str) -> dict[str, Any]:
    return {"name": name, "witness": URL, "receipt": receipt, "verified": verified, "note": note}


def _non_minimal_serial(cert: Any) -> bytes:
    """Return `cert` as DER with a leading zero byte added to its serial number.

    The signature no longer matches, which does not matter for a decoy that is never meant
    to verify.
    """
    der = cert.public_bytes(serialization.Encoding.DER)
    tbs_at = _header_length(der, 0)
    version_at = tbs_at + _header_length(der, tbs_at)
    assert der[version_at : version_at + 5] == b"\xa0\x03\x02\x01\x02"
    serial_at = version_at + 5
    assert der[serial_at] == 0x02 and der[serial_at + 1] < 0x80
    serial_end = serial_at + 2 + der[serial_at + 1]
    serial = b"\x02" + bytes([der[serial_at + 1] + 1, 0]) + der[serial_at + 2 : serial_end]
    tbs_end = tbs_at + _header_length(der, tbs_at) + _content_length(der, tbs_at)
    tbs = _tlv(0x30, der[version_at:serial_at] + serial + der[serial_end:tbs_end])
    return _tlv(0x30, tbs + der[tbs_end:])


def _header_length(der: bytes, at: int) -> int:
    return 2 if der[at + 1] < 0x80 else 2 + (der[at + 1] & 0x7F)


def _content_length(der: bytes, at: int) -> int:
    if der[at + 1] < 0x80:
        return der[at + 1]
    count = der[at + 1] & 0x7F
    return int.from_bytes(der[at + 2 : at + 2 + count], "big")


def _tlv(tag: int, content: bytes) -> bytes:
    length = len(content)
    if length < 0x80:
        return bytes([tag, length]) + content
    size = (length.bit_length() + 7) // 8
    return bytes([tag, 0x80 | size]) + length.to_bytes(size, "big") + content


def _with_certificates_first(token: bytes, first: list[bytes]) -> bytes:
    """Re-encode `token` with the raw `first` certificates ahead of the existing bag.

    Written byte by byte so the SET keeps this order instead of DER's sorted one, which is what
    an attacker who writes the token by hand can do.
    """
    info = cms.ContentInfo.load(token)
    signed = info["content"]
    existing = [choice.dump() for choice in signed["certificates"]]
    signed["certificates"] = cms.CertificateSet(contents=b"".join([*first, *existing]))
    return info.dump()


def main() -> None:
    tsa = TestAuthority("Hostile")
    cases: list[dict[str, Any]] = []

    req = rfc3161.request(DIGEST)
    receipt = rfc3161.receipt_from(req, tsa.respond(req.body), tsa.chain_pems)
    cases.append(_case("good", receipt, True, "honest leaf-only token, chain in the receipt"))

    # F1: a self-issued authority whose issuer is spelt differently from its subject.
    fake = TestAuthority("Fake", root_issuer="fake Root")
    req = rfc3161.request(DIGEST)
    receipt = rfc3161.receipt_from(req, fake.respond(req.body), fake.chain_pems)
    cases.append(
        _case(
            "root-respelled-in-chain",
            receipt,
            False,
            "receipt chain carries a self-issued CA (subject 'Fake Root', issuer 'fake Root')",
        )
    )

    # F4/F5: the signer is a genuine non-time-stamping leaf under the trusted root; a decoy with
    # the same issuer, the same serial value in a non-minimal encoding and the time-stamping EKU
    # sits in front of it in the bag.
    weak_key = ec.generate_private_key(ec.SECP256R1())
    weak = certificate("Weak Signer", weak_key, tsa.ca, tsa.ca_key, ca=False, eku=False)
    decoy_key = ec.generate_private_key(ec.SECP256R1())
    decoy = certificate(
        "Decoy Signer", decoy_key, tsa.ca, tsa.ca_key, ca=False, eku=True, serial=weak.serial_number
    )
    signer = TestAuthority("Hostile")
    signer.root, signer.root_key = tsa.root, tsa.root_key
    signer.ca, signer.ca_key = tsa.ca, tsa.ca_key
    signer.leaf, signer.leaf_key = weak, weak_key
    req = rfc3161.request(DIGEST)
    token = signer.respond(req.body, include="chain")
    receipt = rfc3161.receipt_from(req, token, [])
    receipt["token"] = base64.b64encode(
        _with_certificates_first(base64.b64decode(receipt["token"]), [_non_minimal_serial(decoy)])
    ).decode()
    cases.append(
        _case(
            "decoy-serial-eku",
            receipt,
            False,
            "token signed by a non-TSA leaf; a decoy with serial 00||S and the TSA EKU precedes it",
        )
    )

    # F13: two authorities that issued each other, with the signer under one of them.
    key_a = ec.generate_private_key(ec.SECP256R1())
    key_b = ec.generate_private_key(ec.SECP256R1())
    cycle_a = certificate("Cycle A", key_a, None, key_b, ca=True, issuer_name="Cycle B")
    cycle_b = certificate("Cycle B", key_b, None, key_a, ca=True, issuer_name="Cycle A")
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = certificate("Cycle Signer", leaf_key, cycle_a, key_a, ca=False, eku=True)
    cyclic = TestAuthority("Hostile")
    cyclic.leaf, cyclic.leaf_key = leaf, leaf_key
    req = rfc3161.request(DIGEST)
    token = cyclic.respond(req.body, include="leaf", prepend=[cycle_a, cycle_b])
    receipt = rfc3161.receipt_from(req, token, [_pem(cycle_a), _pem(cycle_b)])
    cases.append(
        _case(
            "issuer-cycle",
            receipt,
            False,
            "the offered CAs issued each other; chain building must stop, not loop",
        )
    )

    document = {
        "trust": [
            {
                "type": "rfc3161",
                "uri": URL,
                "subject": "Hostile Root",
                "valid_for": {
                    "start": format_timestamp(NOT_BEFORE),
                    "end": format_timestamp(NOT_AFTER),
                },
                "roots": [tsa.root_pem],
            }
        ],
        "cases": cases,
    }
    OUT.write_text(json.dumps(document, indent=2) + "\n")
    print(f"wrote {OUT} ({len(cases)} cases)")


if __name__ == "__main__":
    main()
