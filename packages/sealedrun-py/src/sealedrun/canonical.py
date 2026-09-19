from __future__ import annotations

from typing import Any

import rfc8785


def canonicalize(value: Any) -> bytes:
    return rfc8785.dumps(value)
