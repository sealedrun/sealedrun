"""Signature algorithms, hybrid profiles and key sets (SPEC 4.2, 4.3).

A key set holds one classical and one post-quantum key. Signing produces one signature per
algorithm, and verification requires all of them to pass.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import cache
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
    """A private key of one signature algorithm."""

    alg: SigAlg

    def sign(self, message: bytes) -> bytes:
        """Sign `message` and return the raw signature in the SPEC 4.2 encoding."""
        ...

    def public_bytes(self) -> bytes:
        """Return the raw public key in the SPEC 4.2 encoding."""
        ...

    def seed(self) -> bytes:
        """Return the 32 secret bytes that `signer_from_seed` turns back into this key."""
        ...


class Ed25519Signer:
    """Pure Ed25519 (RFC 8032)."""

    alg: SigAlg = "ed25519"

    def __init__(self, key: ed25519.Ed25519PrivateKey):
        self._key = key

    @classmethod
    def generate(cls) -> Ed25519Signer:
        """Create a signer with a fresh random key."""
        return cls(ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> Ed25519Signer:
        """Load the key whose RFC 8032 private key is `seed`."""
        return cls(ed25519.Ed25519PrivateKey.from_private_bytes(seed))

    def sign(self, message: bytes) -> bytes:
        """Return the 64-byte signature `R || S`."""
        return self._key.sign(message)

    def public_bytes(self) -> bytes:
        """Return the 32-byte encoded public point."""
        return self._key.public_key().public_bytes_raw()

    def seed(self) -> bytes:
        """Return the 32-byte RFC 8032 private key."""
        return self._key.private_bytes_raw()


P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


class Es256Signer:
    """ECDSA over P-256 with SHA-256, for the `aat-compat-1` profile."""

    alg: SigAlg = "es256"

    def __init__(self, key: ec.EllipticCurvePrivateKey):
        self._key = key

    @classmethod
    def generate(cls) -> Es256Signer:
        """Create a signer with a fresh random key."""
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @classmethod
    def from_seed(cls, seed: bytes) -> Es256Signer:
        """Derive the private scalar from `seed` with a domain-separated SHA-256.

        The digest is reduced into `[1, n - 1]`. The derivation is specific to this package.
        `seed()` returns the scalar itself, which is not the value passed here.
        """
        scalar = int.from_bytes(digest("sha-256", b"sealedrun/es256/seed" + seed), "big")
        return cls(ec.derive_private_key(scalar % (P256_ORDER - 1) + 1, ec.SECP256R1()))

    def sign(self, message: bytes) -> bytes:
        """Return the 64-byte signature `r || s` with low-S.

        SPEC 4.2 requires low-S so that a signature has exactly one valid encoding.
        """
        r, s = decode_dss_signature(self._key.sign(message, ec.ECDSA(hashes.SHA256())))
        s = min(s, P256_ORDER - s)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def public_bytes(self) -> bytes:
        """Return the 65-byte uncompressed SEC1 public point."""
        numbers = self._key.public_key().public_numbers()
        return b"\x04" + numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")

    def seed(self) -> bytes:
        """Return the private scalar as 32 big-endian bytes."""
        return self._key.private_numbers().private_value.to_bytes(32, "big")


class MlDsaSigner:
    """ML-DSA-65 or ML-DSA-87 (FIPS 204), pure variant with an empty context string."""

    def __init__(self, alg: SigAlg, key: mldsa.MLDSA65PrivateKey | mldsa.MLDSA87PrivateKey):
        self.alg = alg
        self._key = key

    @classmethod
    def generate(cls, alg: SigAlg) -> MlDsaSigner:
        """Create a signer with a fresh random key for `alg`."""
        return cls(alg, _mldsa_private_class(alg).generate())

    @classmethod
    def from_seed(cls, alg: SigAlg, seed: bytes) -> MlDsaSigner:
        """Expand the 32-byte FIPS 204 seed into the key pair for `alg`."""
        return cls(alg, _mldsa_private_class(alg).from_seed_bytes(seed))

    def sign(self, message: bytes) -> bytes:
        """Return the raw FIPS 204 signature."""
        return self._key.sign(message)

    def public_bytes(self) -> bytes:
        """Return the raw FIPS 204 public key."""
        return self._key.public_key().public_bytes_raw()

    def seed(self) -> bytes:
        """Return the 32-byte FIPS 204 seed."""
        return self._key.private_bytes_raw()


def _mldsa_private_class(alg: str) -> type[mldsa.MLDSA65PrivateKey] | type[mldsa.MLDSA87PrivateKey]:
    if alg == "ml-dsa-65":
        return mldsa.MLDSA65PrivateKey
    if alg == "ml-dsa-87":
        return mldsa.MLDSA87PrivateKey
    raise ValueError(f"unsupported ML-DSA algorithm {alg}")


def generate_signer(alg: SigAlg) -> Signer:
    """Create a signer with a fresh random key for `alg`."""
    if alg == "ed25519":
        return Ed25519Signer.generate()
    if alg == "es256":
        return Es256Signer.generate()
    return MlDsaSigner.generate(alg)


def signer_from_seed(alg: str, seed: bytes) -> Signer:
    """Rebuild a signer from a 32-byte seed; any other length raises ValueError."""
    if len(seed) != SEED_SIZE:
        raise ValueError("seed must be 32 bytes")
    if alg == "ed25519":
        return Ed25519Signer.from_seed(seed)
    if alg == "es256":
        return Es256Signer.from_seed(seed)
    return MlDsaSigner.from_seed(alg, seed)  # type: ignore[arg-type]


_ED_P = 2**255 - 19
_ED_L = 2**252 + 27742317777372353535851937790883648493
_ED_D = -121665 * pow(121666, -1, _ED_P) % _ED_P


def _ed_add(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int]:
    (x1, y1), (x2, y2) = a, b
    k = _ED_D * x1 * x2 * y1 * y2 % _ED_P
    x = (x1 * y2 + x2 * y1) * pow(1 + k, -1, _ED_P) % _ED_P
    y = (y1 * y2 + x1 * x2) * pow(1 - k, -1, _ED_P) % _ED_P
    return x, y


def _ed_mul(scalar: int, point: tuple[int, int]) -> tuple[int, int]:
    result = (0, 1)
    while scalar:
        if scalar & 1:
            result = _ed_add(result, point)
        point = _ed_add(point, point)
        scalar >>= 1
    return result


def _ed_decode(encoded: bytes) -> tuple[int, int] | None:
    if len(encoded) != 32:
        return None
    sign = encoded[31] >> 7
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    if y >= _ED_P:
        return None
    x2 = (y * y - 1) * pow(_ED_D * y * y + 1, -1, _ED_P) % _ED_P
    x = pow(x2, (_ED_P + 3) // 8, _ED_P)
    if (x * x - x2) % _ED_P:
        x = x * pow(2, (_ED_P - 1) // 4, _ED_P) % _ED_P
    if (x * x - x2) % _ED_P or (x == 0 and sign):
        return None
    return (_ED_P - x if x & 1 != sign else x), y


def _ed_encode(point: tuple[int, int]) -> bytes:
    return (point[1] | ((point[0] & 1) << 255)).to_bytes(32, "little")


@cache
def ed25519_key_is_valid(public_key: bytes) -> bool:
    """Check the SPEC 4.2 key rule: canonical encoding of a point of prime order.

    The identity and points with a torsion part are rejected.

    Cofactored and cofactorless Ed25519 verifiers disagree exactly on keys outside this set.
    """
    point = _ed_decode(public_key)
    return point is not None and point != (0, 1) and _ed_mul(_ED_L, point) == (0, 1)


def _ed25519_r_is_acceptable(signature: bytes) -> bool:
    """Check the SPEC 4.2 rule for `R`: canonically encoded and not the identity.

    A cofactorless check already rejects every other R that is not of prime order, because
    [s]B and [h]A are.
    """
    if len(signature) != 64:
        return False
    y = int.from_bytes(signature[:32], "little") & ((1 << 255) - 1)
    return y < _ED_P and y != 1


def verify_one(alg: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify one raw signature; malformed input and unknown algorithms return False.

    Enforces the SPEC 4.2 strictness rules before the library check: Ed25519 key and `R`
    validity, and low-S for es256.
    """
    try:
        if alg == "ed25519":
            if not ed25519_key_is_valid(public_key) or not _ed25519_r_is_acceptable(signature):
                return False
            ed25519.Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        elif alg == "es256":
            if len(signature) != 64:
                return False
            r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
            if s > P256_ORDER // 2:
                return False
            der = encode_dss_signature(r, s)
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
    """Public keys of one party: a map from `sig_alg` to a base64url public key (SPEC 4.3)."""

    keys: dict[str, str]

    @property
    def kid(self) -> str:
        """Key identifier: `base64url(SHA-256(JCS(keyset)))`."""
        return b64url_encode(digest("sha-256", canonicalize(self.keys)))

    @property
    def profile(self) -> str:
        """Name of the registered profile with exactly these algorithms; ValueError if none."""
        algs = tuple(sorted(self.keys))
        for name, pair in PROFILES.items():
            if tuple(sorted(pair)) == algs:
                return name
        raise ValueError(f"key set does not match a registered profile: {algs}")

    def to_json(self) -> dict[str, str]:
        """Return a copy of the key map in its SPEC 4.3 JSON form."""
        return dict(self.keys)

    @classmethod
    def from_json(cls, value: dict[str, str]) -> KeySet:
        """Build a key set from its JSON form; ValueError unless it matches a registered profile."""
        keyset = cls(dict(value))
        _ = keyset.profile
        return keyset

    def verify(self, message: bytes, signatures: dict[str, str]) -> bool:
        """Require a valid signature for every key and no signatures for other algorithms.

        SPEC 4.2: an object is rejected unless both signatures of the hybrid verify.
        """
        if set(signatures) != set(self.keys):
            return False
        return all(
            verify_one(alg, b64url_decode(self.keys[alg]), message, b64url_decode(signatures[alg]))
            for alg in self.keys
        )


@dataclass(frozen=True)
class PrivateKeySet:
    """Private keys of one party: one signer per algorithm of a profile."""

    signers: dict[str, Signer]

    @classmethod
    def generate(cls, profile: str = DEFAULT_PROFILE) -> PrivateKeySet:
        """Create fresh random keys for every algorithm of `profile`."""
        return cls({alg: generate_signer(alg) for alg in PROFILES[profile]})

    @classmethod
    def from_seeds(cls, seeds: dict[str, bytes]) -> PrivateKeySet:
        """Rebuild keys from a map of `sig_alg` to 32-byte seed.

        Raises ValueError for an unknown algorithm, a wrong seed length, or a combination that is
        not a registered profile.
        """
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
        """The matching public key set."""
        return KeySet({alg: b64url_encode(s.public_bytes()) for alg, s in self.signers.items()})

    def seeds(self) -> dict[str, bytes]:
        """Export the secret seed of every signer, in the form `from_seeds` accepts."""
        return {alg: s.seed() for alg, s in self.signers.items()}

    def sign(self, message: bytes) -> dict[str, str]:
        """Sign `message` with every key and return the SPEC 4.4 `signatures` object."""
        return {alg: b64url_encode(s.sign(message)) for alg, s in self.signers.items()}
