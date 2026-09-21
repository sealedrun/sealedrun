"""JSON canonicalization used for every hash and signature (SPEC 3)."""

from __future__ import annotations

from typing import Any

import rfc8785


def canonicalize(value: Any) -> bytes:
    """Serialize a JSON value to its RFC 8785 (JCS) byte form."""
    return rfc8785.dumps(value)
