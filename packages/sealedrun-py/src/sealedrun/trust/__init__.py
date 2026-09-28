"""Witness trust list (SPEC 8.4).

The package ships `witnesses.json`, built from the Sigstore trust root and DigiCert's published
roots. A verifier may pass its own list or extend the shipped one; certificates carried in a
receipt are never trusted on their own.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import cache
from pathlib import Path
from typing import Any

_SHIPPED = Path(__file__).resolve().parent / "witnesses.json"


def parse_instant(text: str) -> datetime:
    """Parse an RFC 3339 instant (any fraction, `Z` or offset) into an aware UTC datetime."""
    return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(UTC)


@dataclass(frozen=True)
class Witness:
    """One trust entry: a witness endpoint and what its receipts are checked against.

    Attributes:
        type: `rfc3161` or `rekor`.
        uri: Endpoint URL as written in the anchor record's `witness`.
        subject: Human-readable name of the trust root.
        start: Receipts timed before this instant are not accepted.
        end: Receipts timed after this instant are not accepted; None for no end.
        roots: PEM root certificates (`rfc3161`).
        public_key: PEM public key of the log (`rekor`).
        log_id: Hex SHA-256 of the log's DER public key (`rekor`).
    """

    type: str
    uri: str
    subject: str
    start: datetime
    end: datetime | None = None
    roots: tuple[str, ...] = field(default_factory=tuple)
    public_key: str | None = None
    log_id: str | None = None

    def covers(self, moment: datetime) -> bool:
        """Return True when `moment` lies within `valid_for`."""
        return self.start <= moment and (self.end is None or moment <= self.end)

    @classmethod
    def from_json(cls, entry: dict[str, Any]) -> Witness:
        """Build an entry from its `witnesses.json` form."""
        valid_for = entry["valid_for"]
        end = valid_for.get("end")
        return cls(
            type=entry["type"],
            uri=entry["uri"],
            subject=entry["subject"],
            start=parse_instant(valid_for["start"]),
            end=parse_instant(end) if end else None,
            roots=tuple(entry.get("roots", ())),
            public_key=entry.get("public_key"),
            log_id=entry.get("log_id"),
        )


def load_witnesses(path: Path | None = None) -> list[Witness]:
    """Load a trust list from `path`, or the shipped one."""
    if path is None:
        return list(_shipped())
    return _parse(json.loads(path.read_text()))


def select(
    witnesses: list[Witness], type_: str, uri: str, log_id: str | None = None
) -> list[Witness]:
    """Return the entries matching an anchor's `type` and `witness` (or `log_id` for `rekor`)."""
    return [
        w
        for w in witnesses
        if w.type == type_ and (w.uri == uri or (log_id is not None and w.log_id == log_id))
    ]


@cache
def _shipped() -> tuple[Witness, ...]:
    return tuple(_parse(json.loads(_SHIPPED.read_text())))


def _parse(document: dict[str, Any]) -> list[Witness]:
    return [Witness.from_json(entry) for entry in document["witnesses"]]
