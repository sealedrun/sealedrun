"""Sigstore Rekor v1 `hashedrekord` receipts (SPEC 8.1.2) and their offline verification (8.4).

No networking here: `entry_for` builds the entry to POST to `/api/v1/log/entries`,
`receipt_from` turns the log's answer into the receipt and `verify` checks a receipt against
the trust list. The anchoring key signs the chain head as a prehashed message, which is what the
log verifies: the entry then attests the record whose hash the head is.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey

from sealedrun.errors import SealedRunError
from sealedrun.trust import Witness, select

ENTRIES_PATH = "/api/v1/log/entries"
RETRIEVE_PATH = "/api/v1/index/retrieve"


class RekorError(SealedRunError):
    """A log answer that cannot become a receipt."""


MAX_INTEGRATED_TIME = 4_102_444_800  # 2100-01-01T00:00:00Z


def generate_key() -> ec.EllipticCurvePrivateKey:
    """Return a fresh P-256 anchoring key."""
    return ec.generate_private_key(ec.SECP256R1())


def public_pem(key: ec.EllipticCurvePrivateKey | EllipticCurvePublicKey) -> str:
    """PEM SubjectPublicKeyInfo of a key."""
    public = key.public_key() if isinstance(key, ec.EllipticCurvePrivateKey) else key
    return public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def sign_head(key: ec.EllipticCurvePrivateKey, digest: str) -> bytes:
    """ECDSA-P256 signature with `digest` (hex SHA-256) as the prehashed message, DER."""
    return key.sign(bytes.fromhex(digest), ec.ECDSA(utils.Prehashed(hashes.SHA256())))


def entry_for(digest: str, signature: bytes, public_key: str) -> dict[str, Any]:
    """Return the `hashedrekord` v0.0.1 entry document for the log."""
    return {
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": digest}},
            "signature": {
                "content": base64.b64encode(signature).decode(),
                "publicKey": {"content": base64.b64encode(public_key.encode()).decode()},
            },
        },
    }


def receipt_from(
    answer: dict[str, Any], log_url: str, digest: str, signature: bytes, public_key: str
) -> dict[str, Any]:
    """Turn the log's answer (`{uuid: entry}`) into the `rekor` receipt.

    Requires the entry to carry an inclusion proof and to decode to `digest` and `public_key`.
    Raises RekorError otherwise.
    """
    if len(answer) != 1:
        raise RekorError("log answer does not hold exactly one entry")
    uuid, entry = next(iter(answer.items()))
    try:
        proof = entry["verification"]["inclusionProof"]
        receipt: dict[str, Any] = {
            "digest": digest,
            "log_url": log_url.rstrip("/"),
            "uuid": uuid,
            "log_index": int(entry["logIndex"]),
            "log_id": entry["logID"],
            "body": entry["body"],
            "inclusion_proof": {
                "log_index": int(proof["logIndex"]),
                "root_hash": proof["rootHash"],
                "tree_size": int(proof["treeSize"]),
                "hashes": list(proof["hashes"]),
                "checkpoint": proof["checkpoint"],
            },
            "public_key": public_key,
            "signature": base64.b64encode(signature).decode(),
        }
        if entry.get("integratedTime") is not None:
            receipt["integrated_time"] = int(entry["integratedTime"])
        set_ = entry["verification"].get("signedEntryTimestamp")
        if set_ is not None:
            receipt["signed_entry_timestamp"] = set_
    except (KeyError, TypeError, ValueError) as exc:
        raise RekorError(f"log answer unreadable: {exc}") from exc
    if _body_fields(receipt["body"]) != (digest, public_key):
        raise RekorError("log entry body does not carry the submitted digest and key")
    return receipt


def verify(receipt: dict[str, Any], witness: str, trust: list[Witness]) -> bool:
    """Verify a `rekor` receipt obtained from `witness` against `trust` (SPEC 8.4).

    Returns False when no trust entry matches the log (by URL or `log_id`), or any check
    fails; never raises on bad input.
    """
    entries = select(trust, "rekor", witness, receipt.get("log_id"))
    if not entries:
        return False
    try:
        return any(_verify_with(receipt, entry) for entry in entries)
    except (KeyError, TypeError, ValueError, InvalidSignature, OverflowError, OSError):
        return False


def _verify_with(receipt: dict[str, Any], entry: Witness) -> bool:
    if entry.public_key is None:
        return False
    log_key = serialization.load_pem_public_key(entry.public_key.encode())
    if not isinstance(log_key, EllipticCurvePublicKey):
        return False
    log_id = hashlib.sha256(
        log_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    ).hexdigest()
    if receipt["log_id"] != log_id or (entry.log_id is not None and entry.log_id != log_id):
        return False
    body = base64.b64decode(receipt["body"], validate=True)
    if _body_fields(receipt["body"]) != (receipt["digest"], receipt["public_key"]):
        return False
    anchoring_key = serialization.load_pem_public_key(receipt["public_key"].encode())
    if not isinstance(anchoring_key, EllipticCurvePublicKey):
        return False
    anchoring_key.verify(
        base64.b64decode(receipt["signature"], validate=True),
        bytes.fromhex(receipt["digest"]),
        ec.ECDSA(utils.Prehashed(hashes.SHA256())),
    )
    integrated = receipt.get("integrated_time")
    set_ = receipt.get("signed_entry_timestamp")
    # Without the log's time the receipt cannot be placed inside the witness validity window,
    # so it does not count; a time outside the plausible range is refused before conversion.
    if not isinstance(integrated, int) or isinstance(integrated, bool):
        return False
    if not 0 < integrated < MAX_INTEGRATED_TIME:
        return False
    if integrated is not None:
        from datetime import UTC, datetime

        if not entry.covers(datetime.fromtimestamp(integrated, UTC)):
            return False
        if set_ is None:
            return False
        signed = json.dumps(
            {
                "body": receipt["body"],
                "integratedTime": integrated,
                "logID": receipt["log_id"],
                "logIndex": receipt["log_index"],
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        log_key.verify(base64.b64decode(set_, validate=True), signed, ec.ECDSA(hashes.SHA256()))
    proof = receipt["inclusion_proof"]
    leaf = hashlib.sha256(b"\x00" + body).digest()
    root = _root_from_path(leaf, proof["log_index"], proof["tree_size"], proof["hashes"])
    if root != bytes.fromhex(proof["root_hash"]):
        return False
    origin, size, checkpoint_root = _verify_checkpoint(proof["checkpoint"], log_key, log_id)
    if not origin or size != proof["tree_size"] or checkpoint_root != root:
        return False
    return True


def _body_fields(body_b64: str) -> tuple[str, str] | None:
    try:
        body = json.loads(base64.b64decode(body_b64, validate=True))
        if body["kind"] != "hashedrekord" or body["spec"]["data"]["hash"]["algorithm"] != "sha256":
            return None
        digest = body["spec"]["data"]["hash"]["value"]
        key = base64.b64decode(body["spec"]["signature"]["publicKey"]["content"]).decode()
        return digest, key
    except (KeyError, TypeError, ValueError):
        return None


def _root_from_path(leaf: bytes, index: int, size: int, hashes_hex: list[str]) -> bytes:
    """RFC 6962 inclusion proof: fold the sibling hashes from the leaf up to the root."""
    if index < 0 or index >= size:
        raise ValueError("leaf index outside the tree")
    node = leaf
    path = [bytes.fromhex(h) for h in hashes_hex]
    inner = (index ^ (size - 1)).bit_length()
    border = bin(index >> inner).count("1")
    if len(path) != inner + border:
        raise ValueError("proof length does not fit the tree")
    for i, sibling in enumerate(path[:inner]):
        if (index >> i) & 1:
            node = _node(sibling, node)
        else:
            node = _node(node, sibling)
    for sibling in path[inner:]:
        node = _node(sibling, node)
    return node


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


_SIGNATURE_LINE = re.compile(r"^— (\S+) (\S+)$")


def _verify_checkpoint(
    text: str, log_key: EllipticCurvePublicKey, log_id: str
) -> tuple[str, int, bytes]:
    """Parse a C2SP signed note and verify the log's signature line.

    The note body is everything up to and including the blank line; each signature line is
    `— <name> <base64(4-byte key hint || signature)>`. The log's hint is the first four bytes of
    its `log_id`; lines with other hints (witness cosignatures) are ignored. Returns origin,
    tree size and root hash.
    """
    body, _, signatures = text.partition("\n\n")
    if not signatures:
        raise ValueError("checkpoint has no signature lines")
    lines = body.split("\n")
    if len(lines) < 3:
        raise ValueError("checkpoint body too short")
    origin, size, root_b64 = lines[0], int(lines[1]), lines[2]
    root = base64.b64decode(root_b64, validate=True)
    hint = bytes.fromhex(log_id)[:4]
    message = (body + "\n").encode()
    for line in signatures.rstrip("\n").split("\n"):
        match = _SIGNATURE_LINE.match(line)
        if not match:
            raise ValueError("malformed signature line")
        blob = base64.b64decode(match.group(2), validate=True)
        if blob[:4] != hint:
            continue
        log_key.verify(blob[4:], message, ec.ECDSA(hashes.SHA256()))
        return origin, size, root
    raise ValueError("no signature by the log on the checkpoint")
