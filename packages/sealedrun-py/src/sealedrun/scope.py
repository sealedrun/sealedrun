"""Delegation scope: the structured limits a verifier checks records against (SPEC 6.5)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

STRUCTURAL_KINDS = frozenset({"run_start", "run_end", "anchor", "tombstone"})
TARGET_FIELDS = ("type", "name", "provider", "location")
DATA_TARGET_TYPES = frozenset({"model", "tool", "memory"})


@dataclass(frozen=True)
class Finding:
    """One record that a verified run reports as outside its delegation's scope.

    A finding does not break integrity: the record is genuine and signed. It says the agent
    acted where the Principal did not allow it to.

    Attributes:
        check: `scope.target`, `scope.location`, `scope.label` or `scope.max_records`.
        seq: Sequence number of the record.
        record_id: Its `record_id`.
        reason: Human-readable detail.
    """

    check: str
    seq: int
    record_id: str
    reason: str


@dataclass(frozen=True)
class Scope:
    """Parsed structured part of `Delegation.scope`; other keys are ignored."""

    allowed_targets: tuple[dict[str, str], ...] | None
    allowed_locations: frozenset[str] | None
    denied_labels: frozenset[str]
    max_records: int | None

    @staticmethod
    def parse(scope: dict[str, Any] | None) -> Scope:
        """Read the structured keys of a scope object.

        Raises ValueError when a structured key has the wrong shape.
        """
        if scope is None:
            return Scope(None, None, frozenset(), None)
        targets = scope.get("allowed_targets")
        if targets is not None:
            if not isinstance(targets, list):
                raise ValueError("scope.allowed_targets is not an array")
            for item in targets:
                if not isinstance(item, dict) or not item:
                    raise ValueError("scope.allowed_targets item is not a non-empty object")
                for key, value in item.items():
                    if key not in TARGET_FIELDS or not isinstance(value, str):
                        raise ValueError(f"scope.allowed_targets item has bad field {key}")
        locations = _string_list(scope, "allowed_locations")
        labels = _string_list(scope, "denied_labels")
        max_records = scope.get("max_records")
        if max_records is not None and (
            isinstance(max_records, bool) or not isinstance(max_records, int) or max_records < 1
        ):
            raise ValueError("scope.max_records is not a positive integer")
        return Scope(
            None if targets is None else tuple(targets),
            None if locations is None else frozenset(locations),
            frozenset(labels or ()),
            max_records,
        )

    def findings(self, record: dict[str, Any], record_count: int) -> list[Finding]:
        """Return the scope findings of one record, given how many records the run has so far."""
        out: list[Finding] = []
        seq, record_id = record["seq"], record["record_id"]
        if self.max_records is not None and record_count == self.max_records + 1:
            out.append(
                Finding(
                    "scope.max_records", seq, record_id, f"run exceeds {self.max_records} records"
                )
            )
        if record["kind"] in STRUCTURAL_KINDS:
            return out
        target = record["target"]
        if self.allowed_targets is not None and not any(
            _target_matches(pattern, target) for pattern in self.allowed_targets
        ):
            out.append(
                Finding(
                    "scope.target",
                    seq,
                    record_id,
                    f"target {target['name']} is not in allowed_targets",
                )
            )
        location = target.get("location", "unknown")
        if (
            self.allowed_locations is not None
            and target["type"] in DATA_TARGET_TYPES
            and location not in self.allowed_locations
        ):
            out.append(
                Finding(
                    "scope.location",
                    seq,
                    record_id,
                    f"location {location} is not in allowed_locations",
                )
            )
        denied = sorted(self.denied_labels.intersection(record.get("data_labels", [])))
        if denied:
            out.append(
                Finding("scope.label", seq, record_id, f"labels {', '.join(denied)} are denied")
            )
        return out


def scope_within(child: Scope, parent: Scope) -> str | None:
    """Return why `child` is not within `parent` (SPEC 6.4), or None when it is."""
    if parent.allowed_targets is not None:
        if child.allowed_targets is None:
            return "child scope lacks allowed_targets"
        for pattern in child.allowed_targets:
            if not any(_covers(wide, pattern) for wide in parent.allowed_targets):
                return f"child allows target {pattern} outside the parent's"
    if parent.allowed_locations is not None:
        if child.allowed_locations is None:
            return "child scope lacks allowed_locations"
        extra = sorted(child.allowed_locations - parent.allowed_locations)
        if extra:
            return f"child allows locations {', '.join(extra)} outside the parent's"
    missing = sorted(parent.denied_labels - child.denied_labels)
    if missing:
        return f"child does not deny labels {', '.join(missing)}"
    if parent.max_records is not None and (
        child.max_records is None or child.max_records > parent.max_records
    ):
        return "child max_records exceeds the parent's"
    return None


def _covers(wide: dict[str, str], narrow: dict[str, str]) -> bool:
    for field, expected in wide.items():
        actual = narrow.get(field)
        if actual is None:
            return False
        if field == "name":
            if actual != expected and not glob_match(expected, actual):
                return False
        elif actual != expected:
            return False
    return True


def _string_list(scope: dict[str, Any], key: str) -> list[str] | None:
    value = scope.get(key)
    if value is None:
        return None
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"scope.{key} is not an array of strings")
    return value


def glob_match(pattern: str, value: str) -> bool:
    """Match `value` against `pattern`, where `*` stands for any run of characters.

    The only wildcard is `*`; every other character matches itself, so the rule is the same in
    every implementation.
    """
    regex = ".*".join(re.escape(part) for part in pattern.split("*"))
    return re.fullmatch(regex, value) is not None


def _target_matches(pattern: dict[str, str], target: dict[str, Any]) -> bool:
    for field, expected in pattern.items():
        actual = target.get(field)
        if not isinstance(actual, str):
            return False
        if field == "name":
            if not glob_match(expected, actual):
                return False
        elif actual != expected:
            return False
    return True
