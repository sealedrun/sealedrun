"""Timestamps in the SPEC 3 form: RFC 3339, UTC, millisecond precision, `Z` suffix."""

from __future__ import annotations

from datetime import UTC, datetime


def format_timestamp(value: datetime) -> str:
    """Format an aware datetime in the SPEC 3 form, truncating to milliseconds."""
    utc = value.astimezone(UTC)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def parse_timestamp(text: str) -> datetime:
    """Parse a SPEC 3 timestamp into an aware UTC datetime; other forms raise ValueError."""
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=UTC)


def now() -> datetime:
    """Return the current time as an aware UTC datetime."""
    return datetime.now(UTC)
