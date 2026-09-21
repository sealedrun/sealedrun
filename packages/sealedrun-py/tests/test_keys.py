from typing import Any

import pytest
from sealedrun import PROFILES, KeySet, PrivateKeySet
from sealedrun.keys import P256_ORDER, Es256Signer, verify_one
from sealedrun.signing import signing_input


@pytest.mark.parametrize("profile", list(PROFILES))
def test_generate_sign_verify(profile: str) -> None:
    keys = PrivateKeySet.generate(profile)
    message = signing_input(b"sealedrun/record/v1", "ab" * 32)
    sigs = keys.sign(message)
    assert keys.public.profile == profile
    assert keys.public.verify(message, sigs)
    assert not keys.public.verify(message + b"x", sigs)


def test_seed_determinism(keyfactory: Any) -> None:
    a, b = keyfactory(b"k"), keyfactory(b"k")
    assert a.public == b.public
    assert a.public.kid == b.public.kid
    assert keyfactory(b"other").public.kid != a.public.kid


def test_seed_roundtrip() -> None:
    keys = PrivateKeySet.generate()
    again = PrivateKeySet.from_seeds(keys.seeds())
    assert again.public == keys.public


def test_hybrid_requires_both_signatures() -> None:
    keys = PrivateKeySet.generate()
    message = b"m"
    sigs = keys.sign(message)
    assert not keys.public.verify(message, {"ed25519": sigs["ed25519"]})
    other = PrivateKeySet.generate().sign(message)
    assert not keys.public.verify(message, {**sigs, "ml-dsa-65": other["ml-dsa-65"]})
    assert not keys.public.verify(message, {**sigs, "ed25519": other["ed25519"]})


def test_keyset_rejects_unknown_profile() -> None:
    with pytest.raises(ValueError):
        KeySet.from_json({"ed25519": "AA", "es256": "AA"})


def test_verify_one_rejects_garbage() -> None:
    assert not verify_one("ed25519", b"\0" * 32, b"m", b"\0" * 64)
    assert not verify_one("ml-dsa-65", b"\0" * 10, b"m", b"\0" * 10)
    assert not verify_one("nope", b"", b"", b"")


def test_es256_is_low_s_only() -> None:
    signer = Es256Signer.generate()
    for i in range(40):
        message = f"message {i}".encode()
        signature = signer.sign(message)
        s = int.from_bytes(signature[32:], "big")
        assert s <= P256_ORDER // 2
        assert verify_one("es256", signer.public_bytes(), message, signature)
        flipped = signature[:32] + (P256_ORDER - s).to_bytes(32, "big")
        assert not verify_one("es256", signer.public_bytes(), message, flipped)
