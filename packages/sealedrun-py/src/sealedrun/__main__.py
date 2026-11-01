"""Command line: `python -m sealedrun [--strict-scope] [--strict-approval] <bundle.zip> [id ...]`.

Prints one line per run with the counts a relying party asks about, including how many anchors
verified against a witness in the shipped trust list, then one line per record outside the
delegation's scope (SPEC 6.5). Exits 1 on a failed check, and with `--strict-scope` on the first
scope finding as well; `--strict-approval` does the same for a step that ran without the human
approval its policy required (SPEC 6.6).
"""

from __future__ import annotations

import argparse
import re
import sys

from sealedrun.bundle import MAX_TOTAL_BYTES, read_bundle, verify_bundle
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
    parser = argparse.ArgumentParser(prog="python -m sealedrun", add_help=True)
    parser.add_argument("bundle", nargs="?", help="bundle archive to verify")
    parser.add_argument("principals", nargs="*", help="trusted principal ids")
    parser.add_argument(
        "--max-total-bytes",
        type=int,
        default=MAX_TOTAL_BYTES,
        help=f"most the archive may hold once inflated (default {MAX_TOTAL_BYTES})",
    )
    parser.add_argument(
        "--strict-scope",
        action="store_true",
        help="fail on the first record outside the delegation's scope instead of listing it",
    )
    parser.add_argument(
        "--strict-approval",
        action="store_true",
        help="fail on the first step that ran without the human approval its policy required",
    )
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as error:
        return 2 if error.code else 0
    if args.bundle is None or args.max_total_bytes < 1:
        parser.print_usage(sys.stderr)
        return 2
    path, principals = args.bundle, args.principals
    try:
        with open(path, "rb") as handle:
            bundle = read_bundle(handle, max_total_bytes=args.max_total_bytes)
        report = verify_bundle(
            bundle,
            principals or None,
            strict_scope=args.strict_scope,
            strict_approval=args.strict_approval,
        )
    except VerificationError as error:
        print(f"FAIL {plain(str(error))}")
        return 1
    except (OSError, ValueError) as error:
        print(f"FAIL malformed: {plain(str(error))}")
        return 1
    trust = "principal trusted" if report.principal_trusted else "principal not confirmed"
    print(f"OK bundle {report.bundle_id}: {len(report.runs)} run(s), {trust}")
    if report.payloads_omitted:
        print("  payloads omitted by exporter (bodies not checked)")
    for run in report.runs:
        state = "complete" if run.complete else "open"
        print(
            f"  run {run.run_id}: {run.record_count} records, {state}, "
            f"anchors {run.anchors}, witness verified {run.anchors_witness_verified}, "
            f"findings {len(run.findings)}, receipts {run.receipts_proxy} proxy / "
            f"{run.receipts_self_reported} self-reported"
        )
        for finding in run.findings:
            print(f"    seq {finding.seq} {finding.check}: {plain(finding.reason)}")
        for seq in run.system_prompt_changes:
            print(f"    seq {seq} system prompt changed")
        if run.run_id in report.parents_unresolved:
            print("    parent run not in this bundle; verify both bundles together")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
