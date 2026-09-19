from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, mldsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from sealedrun.canonical import canonicalize
from sealedrun.hashing import b64url_decode, b64url_encode, digest

SigAlg = Literal["ed25519", "ml-dsa-65", "es256", "ml-dsa-87"]
Profile = Literal["sealedrun-hybrid-1", "aat-compat-1", "sealedrun-hybrid-2"]

PROFILES: dict[str, tuple[SigAlg, SigAlg]] = {
    "sealedrun-hybrid-1": ("ed25519", "ml-dsa-65"),
    "aat-compat-1": ("es256", "ml-dsa-65"),
    "sealedrun-hybrid-2": ("ed25519", "ml-dsa-87"),
}
DEFAULT_PROFILE: Profile = "sealedrun-hybrid-1"
SIG_ALGS: frozenset[str] = frozenset({"ed25519", "ml-dsa-65", "es256", "ml-dsa-87"})
SEED_SIZE = 32


class Signer(Protocol):
    alg: SigAlg

    def sign(self, message: bytes) -> bytes: ...

    def public_bytes(self) -> bytes: ...

    def seed(self) -> bytes: ...


class Ed25519Signer:
    alg: SigAlg = "ed25519"

    def __init__(self, key: ed25519.Ed25519PrivateKey):
        self._key = key

    @classmethod
    def generate(cls) -> Ed25519Signer:
        return cls(ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> Ed25519Signer:
        return cls(ed25519.Ed25519PrivateKey.from_private_bytes(seed))

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)

    def public_bytes(self) -> bytes:
        return self._key.public_key().public_bytes_raw()

    def seed(self) -> bytes:
        return self._key.private_bytes_raw()


class Es256Signer:
    alg: SigAlg = "es256"

    def __init__(self, key: ec.EllipticCurvePrivateKey):
        self._key = key

    @classmethod
    def generate(cls) -> Es256Signer:
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_seed(cls, seed: bytes) -> Es256Signer:
        scalar = int.from_bytes(digest("sha-256", b"sealedrun/es256/seed" + seed), "big")
        order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
        return cls(ec.derive_private_key(scalar % (order - 1) + 1, ec.SECP256R1()))

    def sign(self, message: bytes) -> bytes:
        r, s = decode_dss_signature(self._key.sign(message, ec.ECDSA(hashes.SHA256())))
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def public_bytes(self) -> bytes:
        numbers = self._key.public_key().public_numbers()
        return b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")

    def seed(self) -> bytes:
        return self._key.private_numbers().private_value.to_bytes(32, "big")


class MlDsaSigner:
    def __init__(self, alg: SigAlg, key: mldsa.MLDSA65PrivateKey | mldsa.MLDSA87PrivateKey):
        self.alg = alg
        self._key = key

    @classmethod
    def generate(cls, alg: SigAlg) -> MlDsaSigner:
        return cls(alg, _mldsa_private_class(alg).generate())

    @classmethod
    def from_seed(cls, alg: SigAlg, seed: bytes) -> MlDsaSigner:
        return cls(alg, _mldsa_private_class(alg).from_seed_bytes(seed))

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)

    def public_bytes(self) -> bytes:
        return self._key.public_key().public_bytes_raw()

    def seed(self) -> bytes:
        return self._key.private_bytes_raw()


def _mldsa_private_class(alg: str) -> type[mldsa.MLDSA65PrivateKey] | type[mldsa.MLDSA87PrivateKey]:
    if alg == "ml-dsa-65":
        return mldsa.MLDSA65PrivateKey
    if alg == "ml-dsa-87":
        return mldsa.MLDSA87PrivateKey
    raise ValueError(f"unsupported ML-DSA algorithm {alg}")


def generate_signer(alg: SigAlg) -> Signer:
    if alg == "ed25519":
        return Ed25519Signer.generate()
    if alg == "es256":
        return Es256Signer.generate()
    return MlDsaSigner.generate(alg)


def signer_from_seed(alg: str, seed: bytes) -> Signer:
    if len(seed) != SEED_SIZE:
        raise ValueError("seed must be 32 bytes")
    if alg == "ed25519":
        return Ed25519Signer.from_seed(seed)
    if alg == "es256":
        return Es256Signer.from_seed(seed)
    return MlDsaSigner.from_seed(alg, seed)  # type: ignore[arg-type]


def verify_one(alg: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        if alg == "ed25519":
            ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        elif alg == "es256":
            if len(signature) != 64:
                return False
            der = encode_dss_signature(
                int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
            )
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), public_key).verify(
                der, message, ec.ECDSA(hashes.SHA256())
            )
        elif alg == "ml-dsa-65":
            mldsa.MLDSA65PublicKey.from_public_bytes(public_key).verify(signature, message)
        elif alg == "ml-dsa-87":
            mldsa.MLDSA87PublicKey.from_public_bytes(public_key).verify(signature, message)
        else:
            return False
    except (InvalidSignature, ValueError):
        return False
    return True


@dataclass(frozen=True)
class KeySet:
    keys: dict[str, str]

    @property
    def kid(self) -> str:
        return b64url_encode(digest("sha-256", canonicalize(self.keys)))

    @property
    def profile(self) -> str:
        algs = tuple(sorted(self.keys))
        for name, pair in PROFILES.items():
            if tuple(sorted(pair)) == algs:
                return name
        raise ValueError(f"key set does not match a registered profile: {algs}")

    def to_json(self) -> dict[str, str]:
        return dict(self.keys)

    @classmethod
    def from_json(cls, value: dict[str, str]) -> KeySet:
        keyset = cls(dict(value))
        _ = keyset.profile
        return keyset

    def verify(self, message: bytes, signatures: dict[str, str]) -> bool:
        if set(signatures) != set(self.keys):
            return False
        return all(
            verify_one(alg, b64url_decode(self.keys[alg]), message, b64url_decode(signatures[alg]))
            for alg in self.keys
        )


@dataclass(frozen=True)
class PrivateKeySet:
    signers: dict[str, Signer]

    @classmethod
    def generate(cls, profile: str = DEFAULT_PROFILE) -> PrivateKeySet:
        return cls({alg: generate_signer(alg) for alg in PROFILES[profile]})

    @classmethod
    def from_seeds(cls, seeds: dict[str, bytes]) -> PrivateKeySet:
        signers: dict[str, Signer] = {}
        for alg, seed in seeds.items():
            if alg not in SIG_ALGS:
                raise ValueError(f"unsupported signature algorithm {alg}")
            signers[alg] = signer_from_seed(alg, seed)
        keyset = cls(signers)
        _ = keyset.public.profile
        return keyset

    @property
    def public(self) -> KeySet:
        return KeySet({alg: b64url_encode(s.public_bytes()) for alg, s in self.signers.items()})

    def seeds(self) -> dict[str, bytes]:
        return {alg: s.seed() for alg, s in self.signers.items()}

    def sign(self, message: bytes) -> dict[str, str]:
        return {alg: b64url_encode(s.sign(message)) for alg, s in self.signers.items()}
