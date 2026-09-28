"""Command line: `python -m sealedrun <bundle.zip> [principal_id ...]` verifies a bundle.

Prints one line per run with the counts a relying party asks about, including how many anchors
verified against a witness in the shipped trust list, and exits 1 on a failed check.
"""

from __future__ import annotations

import re
import sys

from sealedrun.bundle import read_bundle, verify_bundle
from sealedrun.errors import VerificationError


CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def plain(text: str) -> str:
    """Replace control characters with `?`.

    An error message may quote an archive path or a field from the bundle under test, and a
    terminal would obey an escape sequence hidden there, so nothing that steers a terminal is
    printed.
    """
    return CONTROL.sub("?", text)


def main(argv: list[str] | None = None) -> int:
    """Verify the bundle named first; further arguments are trusted principal ids."""
    args = sys.argv[1:] if argv is None else argv
    if not args:
        print("usage: python -m sealedrun <bundle.zip> [trusted_principal_id ...]", file=sys.stderr)
        return 2
    path, principals = args[0], args[1:]
    try:
        with open(path, "rb") as handle:
            bundle = read_bundle(handle)
        report = verify_bundle(bundle, principals or None)
    except VerificationError as error:
        print(f"FAIL {plain(str(error))}")
        return 1
    except (OSError, ValueError) as error:
        print(f"FAIL malformed: {plain(str(error))}")
        return 1
    trust = "principal trusted" if report.principal_trusted else "principal not confirmed"
    print(f"OK bundle {report.bundle_id}: {len(report.runs)} run(s), {trust}")
    for run in report.runs:
        state = "complete" if run.complete else "open"
        print(
            f"  run {run.run_id}: {run.record_count} records, {state}, "
            f"anchors {run.anchors}, witness verified {run.anchors_witness_verified}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
