"""Offline Rekor v1 for tests: a log key, a growing Merkle tree and real signed answers.

`FakeRekor.add` takes a `hashedrekord` entry document and answers like `POST /api/v1/log/entries`
(one `{uuid: entry}` object with inclusion proof, checkpoint and signed entry timestamp), so
receipts built from it verify against a trust entry holding `log_key_pem`. Knobs exist for the
tampering tests: a wrong log key for the SET or the checkpoint, a bad proof, a cosignature line.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

ORIGIN = "rekor.test - 1234567890"


class FakeRekor:
    """A single-shard log whose leaves are the entries added so far."""

    def __init__(self, *, log_index_base: int = 1_000) -> None:
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.leaves: list[bytes] = []
        self.bodies: list[str] = []
        self.base = log_index_base
        self.cosign = False
        self.answers = 0

    @property
    def log_key_pem(self) -> str:
        return (
            self.key.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )

    @property
    def log_id(self) -> str:
        der = self.key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return hashlib.sha256(der).hexdigest()

    def fill(self, count: int) -> None:
        """Add `count` unrelated leaves so proofs have sibling hashes."""
        for _ in range(count):
            self.bodies.append(base64.b64encode(os.urandom(24)).decode())
            self.leaves.append(_leaf(base64.b64decode(self.bodies[-1])))

    def add(self, entry: dict[str, Any], *, integrated_time: int = 1_790_000_000) -> dict[str, Any]:
        """Append `entry` and return the log's answer for it."""
        self.answers += 1
        body = base64.b64encode(
            json.dumps(entry, separators=(",", ":"), sort_keys=True).encode()
        ).decode()
        self.bodies.append(body)
        self.leaves.append(_leaf(base64.b64decode(body)))
        index = len(self.leaves) - 1
        return self.answer(index, integrated_time)

    def answer(self, index: int, integrated_time: int = 1_790_000_000) -> dict[str, Any]:
        """The `{uuid: entry}` answer for leaf `index` at the current tree size."""
        size = len(self.leaves)
        root = _root(self.leaves)
        body = self.bodies[index]
        log_index = self.base + index
        signed = json.dumps(
            {
                "body": body,
                "integratedTime": integrated_time,
                "logID": self.log_id,
                "logIndex": log_index,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        set_ = self.key.sign(signed, ec.ECDSA(hashes.SHA256()))
        uuid = "0" * 16 + self.leaves[index].hex()
        return {
            uuid: {
                "body": body,
                "integratedTime": integrated_time,
                "logID": self.log_id,
                "logIndex": log_index,
                "verification": {
                    "inclusionProof": {
                        "checkpoint": self.checkpoint(size, root),
                        "hashes": [h.hex() for h in _path(self.leaves, index)],
                        "logIndex": index,
                        "rootHash": root.hex(),
                        "treeSize": size,
                    },
                    "signedEntryTimestamp": base64.b64encode(set_).decode(),
                },
            }
        }

    def checkpoint(
        self, size: int, root: bytes, key: ec.EllipticCurvePrivateKey | None = None
    ) -> str:
        """A C2SP signed note over `size` and `root`, signed by `key` (the log key by default)."""
        body = f"{ORIGIN}\n{size}\n{base64.b64encode(root).decode()}\n"
        signer = key or self.key
        signature = signer.sign(body.encode(), ec.ECDSA(hashes.SHA256()))
        hint = bytes.fromhex(self.log_id)[:4]
        lines = [body, "\n"]
        if self.cosign:
            cosig = base64.b64encode(b"\xde\xad\xbe\xef" + os.urandom(70)).decode()
            lines.append(f"— witness.test {cosig}\n")
        lines.append(f"— rekor.test {base64.b64encode(hint + signature).decode()}\n")
        return "".join(lines)


def _leaf(body: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + body).digest()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _root(leaves: list[bytes]) -> bytes:
    """RFC 6962 root of `leaves`."""
    if len(leaves) == 1:
        return leaves[0]
    split = 1 << (len(leaves) - 1).bit_length() - 1
    return _node(_root(leaves[:split]), _root(leaves[split:]))


def _path(leaves: list[bytes], index: int) -> list[bytes]:
    """RFC 6962 inclusion path for `index`, leaf to root."""
    if len(leaves) == 1:
        return []
    split = 1 << (len(leaves) - 1).bit_length() - 1
    if index < split:
        return [*_path(leaves[:split], index), _root(leaves[split:])]
    return [*_path(leaves[split:], index - split), _root(leaves[:split])]
