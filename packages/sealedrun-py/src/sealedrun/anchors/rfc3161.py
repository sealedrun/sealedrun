"""RFC 3161 time-stamp receipts (SPEC 8.1.1) and their offline verification (SPEC 8.4).

No networking here: `request` builds the bytes to POST to a TSA, `receipt_from` turns the
answer into the receipt object and `verify` checks a receipt against the trust list. Parsing and
chain building come from `rfc3161-client`; the token is re-encoded as strict DER first because
some authorities (DigiCert) return BER-ordered certificate sets that a DER parser refuses. The
signature covers the signed attributes only, so the re-encoding never changes what was signed.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import UTC
from typing import Any

from asn1crypto import cms, core, tsp
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from rfc3161_client import (
    HashAlgorithm,
    PKIStatus,
    TimestampRequestBuilder,
    VerifierBuilder,
    decode_timestamp_response,
)
from rfc3161_client import VerificationError as TsaVerificationError

from sealedrun.errors import SealedRunError
from sealedrun.timeutil import format_timestamp
from sealedrun.trust import Witness, parse_instant, select

MEDIA_TYPE = "application/timestamp-query"


class AnchorError(SealedRunError):
    """A witness answer that cannot become a receipt."""


@dataclass(frozen=True)
class TsaRequest:
    """A built TimeStampReq: the bytes to POST and the nonce to expect back."""

    body: bytes
    nonce: int
    digest: str


def imprint(digest: str) -> bytes:
    """Return the message imprint: SHA-256 over the raw bytes of the hex `digest`."""
    return hashlib.sha256(bytes.fromhex(digest)).digest()


def request(digest: str) -> TsaRequest:
    """Build a TimeStampReq for the chain head `digest` (hex), with a fresh nonce and certReq."""
    built = (
        TimestampRequestBuilder()
        .data(bytes.fromhex(digest))
        .hash_algorithm(HashAlgorithm.SHA256)
        .nonce(nonce=True)
        .cert_request(cert_request=True)
        .build()
    )
    if built.nonce is None:
        raise AnchorError("time-stamp request has no nonce")
    return TsaRequest(built.as_bytes(), built.nonce, digest)


def receipt_from(
    req: TsaRequest, response: bytes, chain: list[str] | None = None
) -> dict[str, Any]:
    """Turn a TSA answer into the `rfc3161` receipt for `req`.

    Checks the status, the nonce and the imprint against the request; `chain` is the PEM
    certificate chain published by the authority, kept as an untrusted snapshot.
    Raises AnchorError when the answer does not fit the request.
    """
    try:
        status_info = tsp.PKIStatusInfo.load(core.Sequence.load(response)[0].dump())
        status = status_info["status"].native
        if status not in ("granted", "granted_with_mods"):
            texts = status_info["status_string"].native or []
            raise AnchorError(f"time-stamp refused: {status} {' '.join(texts)}".rstrip())
        parsed = tsp.TimeStampResp.load(response, strict=True)
        token = parsed["time_stamp_token"]
        token_der = token.dump(force=True)
        info = _tst_info(token)
    except (ValueError, KeyError, TypeError) as exc:
        raise AnchorError(f"time-stamp response unreadable: {exc}") from exc
    if info["nonce"].native != req.nonce:
        raise AnchorError("time-stamp nonce does not match the request")
    if info["message_imprint"]["hash_algorithm"]["algorithm"].native != "sha256":
        raise AnchorError("time-stamp imprint algorithm is not sha256")
    if info["message_imprint"]["hashed_message"].native != imprint(req.digest):
        raise AnchorError("time-stamp imprint does not match the request")
    receipt: dict[str, Any] = {
        "digest": req.digest,
        "imprint_alg": "sha256",
        "token": base64.b64encode(token_der).decode(),
        "chain": list(chain or []),
        "nonce": str(req.nonce),
        "gen_time": format_timestamp(info["gen_time"].native.astimezone(UTC)),
        "policy": info["policy"].native,
    }
    return receipt


def verify(receipt: dict[str, Any], witness: str, trust: list[Witness]) -> bool:
    """Verify an `rfc3161` receipt obtained from `witness` against `trust` (SPEC 8.4).

    Returns False when no trust entry matches the witness, when the token fails any check, or
    when its time lies outside the entry's validity. Never raises on bad input.
    """
    entries = select(trust, "rfc3161", witness)
    if not entries:
        return False
    try:
        return any(_verify_with(receipt, entry) for entry in entries)
    except (TsaVerificationError, ValueError, KeyError, TypeError, OverflowError):
        return False


def _verify_with(receipt: dict[str, Any], entry: Witness) -> bool:
    token = cms.ContentInfo.load(base64.b64decode(receipt["token"]), strict=True)
    info = _tst_info(token)
    gen_time = info["gen_time"].native.astimezone(UTC)
    if not entry.covers(gen_time):
        return False
    if "gen_time" in receipt and parse_instant(receipt["gen_time"]) != gen_time:
        return False
    if "policy" in receipt and info["policy"].native != receipt["policy"]:
        return False
    if info["message_imprint"]["hash_algorithm"]["algorithm"].native != "sha256":
        return False
    response = tsp.TimeStampResp({"status": {"status": "granted"}, "time_stamp_token": token}).dump(
        force=True
    )
    decoded = decode_timestamp_response(response)
    if PKIStatus(decoded.status) != PKIStatus.GRANTED:
        return False
    builder = VerifierBuilder().nonce(int(receipt["nonce"]))
    roots = [x509.load_pem_x509_certificate(pem.encode()) for pem in entry.roots]
    for root in roots:
        builder = builder.add_root_certificate(root)
    root_der = {root.public_bytes(Encoding.DER) for root in roots}
    for pem in receipt.get("chain", []):
        certificate = x509.load_pem_x509_certificate(pem.encode())
        if certificate.public_bytes(Encoding.DER) in root_der:
            continue
        if _self_signed(certificate):
            continue
        builder = builder.add_intermediate_certificate(certificate)
    return bool(builder.build().verify(decoded, imprint(receipt["digest"])))


def _self_signed(certificate: x509.Certificate) -> bool:
    """Tell whether a certificate is self-signed; such a one from a receipt would act as a root."""
    return certificate.issuer == certificate.subject


def _tst_info(token: cms.ContentInfo) -> tsp.TSTInfo:
    if token["content_type"].native != "signed_data":
        raise ValueError("token is not CMS SignedData")
    content = token["content"]["encap_content_info"]
    if content["content_type"].native != "tst_info":
        raise ValueError("token does not carry TSTInfo")
    info = content["content"].parsed
    if not isinstance(info, tsp.TSTInfo):
        raise ValueError("token content is not TSTInfo")
    return info
