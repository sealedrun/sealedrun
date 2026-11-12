"""Write the `window-*.zip` bundles of `spec/vectors/bundle`: exports by time window.

Run from `packages/sealedrun-py`: `uv run python tests/make_window_bundles.py`. Each bundle
carries a manifest `query` block (SPEC 13.1) and its entry in `expected.json` says what every
verifier must report: the query, the records of each run outside the window, or the failing
check. Signatures are fresh on every run, which is fine because only the committed output is
used; the other bundles and their entries are left as they are.
"""

from __future__ import annotations

import io
import json
import sys
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

from sealedrun import RunWriter, create_delegation, write_bundle
from sealedrun.schema import SCHEMA_DIR

sys.path.insert(0, str(Path(__file__).parent))
from conftest import START, Clock, seeded

OUT = SCHEMA_DIR.parent / "vectors" / "bundle"
PREFIX = "0192b3c4-5d6e-7f80-9a1b-"
LABEL = "billing-agent"
TOOL = {"target": {"type": "tool", "name": "add"}}
EARLY = PREFIX + "0000000000e1"
LATE = PREFIX + "0000000000e2"
UNLABELLED = PREFIX + "0000000000e3"


def _ids(start: int) -> Callable[[], str]:
    """Return a factory of record ids counting up from `start`, so runs do not share ids."""
    counter = iter(range(start + 1, start + 0x100))
    return lambda: f"{PREFIX}{next(counter):012x}"


def _run(
    delegation: dict[str, Any],
    run_id: str,
    ids: int,
    minutes: int,
    *,
    label: str | None,
    end: bool,
) -> list[dict[str, Any]]:
    """Write a run of three records, one second apart, starting `minutes` after START."""
    writer = RunWriter(
        seeded(b"agent-"),
        delegation,
        run_id=run_id,
        clock=Clock(START + timedelta(minutes=minutes)),
        id_factory=_ids(ids),
    )
    writer.start(extensions={"sealedrun.proxy": {"run_label": label}} if label else {})
    writer.append("tool_call", **TOOL)
    if end:
        writer.end()
    else:
        writer.append("tool_call", **TOOL)
    return writer.records


def _bundle(
    delegation: dict[str, Any], runs: list[list[dict[str, Any]]], query: dict[str, str]
) -> bytes:
    out = io.BytesIO()
    write_bundle(
        out,
        exporter=seeded(b"agent-"),
        software="sealedrun-vectors/0.1.0",
        delegations=[delegation],
        runs=runs,
        principal=seeded(b"principal-"),
        bundle_id=PREFIX + "0000000000b1",
        created_at="2026-09-16T13:00:00.000Z",
        query=query,
    )
    return out.getvalue()


def main() -> None:
    delegation = create_delegation(
        seeded(b"principal-"),
        seeded(b"agent-").public,
        not_before=START - timedelta(days=1),
        not_after=START + timedelta(days=3650),
        agent_name="window-agent",
        delegation_id=PREFIX + "0000000000c1",
    )
    early = _run(delegation, EARLY, 0x300, 0, label=LABEL, end=True)
    late = _run(delegation, LATE, 0x310, 10, label=LABEL, end=False)
    unlabelled = _run(delegation, UNLABELLED, 0x320, 10, label=None, end=True)
    window = {"since": "2026-09-16T12:00:03.000Z", "until": "2026-09-16T12:10:02.000Z"}
    labelled = {**window, "label": LABEL, "note": "incident 2026-09-16, exported by on-call"}
    ok = {"ok": True, "records": 3, "complete": True}
    cases: dict[str, tuple[bytes, dict[str, Any]]] = {
        "window.zip": (
            _bundle(delegation, [early, late, unlabelled], window),
            {
                **ok,
                "runs": 3,
                "query": window,
                "outside_window": {EARLY: 2, LATE: 2, UNLABELLED: 2},
            },
        ),
        "window-label.zip": (
            _bundle(delegation, [early, late], labelled),
            {**ok, "runs": 2, "query": labelled, "outside_window": {EARLY: 2, LATE: 2}},
        ),
        "window-wrong-label.zip": (
            _bundle(delegation, [early, unlabelled], labelled),
            {"ok": False, "check": "query"},
        ),
        "window-run-outside.zip": (
            _bundle(
                delegation,
                [early, late],
                {"since": "2026-09-16T12:05:00.000Z", "until": "2026-09-16T12:20:00.000Z"},
            ),
            {"ok": False, "check": "query"},
        ),
        "window-inverted.zip": (
            _bundle(
                delegation,
                [early],
                {"since": "2026-09-16T12:10:00.000Z", "until": "2026-09-16T12:00:00.000Z"},
            ),
            {"ok": False, "check": "query"},
        ),
    }
    path = OUT / "expected.json"
    expected = json.loads(path.read_text())
    for name, (data, case) in cases.items():
        (OUT / name).write_bytes(data)
        expected[name] = case
    path.write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n")
    print(f"wrote {len(cases)} bundles to {OUT}")


if __name__ == "__main__":
    main()
