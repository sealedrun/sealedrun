"""Command line: `python -m sealedrun [--report [--json]] [--strict-scope] <bundle.zip> [id ...]`.

Prints the time window of a bundle exported by one (SPEC 13.1), then one line per run with the
counts a relying party asks about, including how many anchors
verified against a witness in the shipped trust list, then one line per record outside the
delegation's scope (SPEC 6.5). Exits 1 on a failed check, and with `--strict-scope` on the first
scope finding as well; `--strict-approval` does the same for a step that ran without the human
approval its policy required (SPEC 6.6).

With `--report` the output is the one-page evidence report of `sealedrun.report` instead, as
text or with `--json` as JSON; the exit code is the same.
"""

from __future__ import annotations

import argparse
import json
import re
import sys

from sealedrun.bundle import MAX_TOTAL_BYTES, read_bundle, verify_bundle
from sealedrun.errors import VerificationError
from sealedrun.report import evidence_report, failure_report, file_sha256, render_report

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
    parser.add_argument(
        "--max-approval-lag",
        type=float,
        metavar="SECONDS",
        help="list every human approval that no verified anchor covers within this time",
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="print the one-page evidence report instead of the per-run lines",
    )
    parser.add_argument("--json", action="store_true", help="with --report: print it as JSON")
    try:
        args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as error:
        return 2 if error.code else 0
    if args.bundle is None or args.max_total_bytes < 1 or (args.json and not args.report):
        parser.print_usage(sys.stderr)
        return 2
    path, principals = args.bundle, args.principals
    sha256 = ""
    try:
        with open(path, "rb") as handle:
            if args.report:
                sha256 = file_sha256(handle)
            bundle = read_bundle(handle, max_total_bytes=args.max_total_bytes)
        report = verify_bundle(
            bundle,
            principals or None,
            strict_scope=args.strict_scope,
            strict_approval=args.strict_approval,
            max_approval_anchor_lag=args.max_approval_lag,
        )
    except VerificationError as error:
        if args.report:
            _print_report(failure_report(error, sha256), as_json=args.json)
        else:
            print(f"FAIL {plain(str(error))}")
        return 1
    except (OSError, ValueError) as error:
        print(f"FAIL malformed: {plain(str(error))}")
        return 1
    if args.report:
        _print_report(evidence_report(bundle, report, sha256), as_json=args.json)
        return 0
    trust = "principal trusted" if report.principal_trusted else "principal not confirmed"
    print(f"OK bundle {report.bundle_id}: {len(report.runs)} run(s), {trust}")
    if report.payloads_omitted:
        print("  payloads omitted by exporter (bodies not checked)")
    if report.query is not None:
        label = f", run label {plain(report.query['label'])}" if "label" in report.query else ""
        print(f"  exported window: {report.query['since']} to {report.query['until']}{label}")
        if "note" in report.query:
            print(f"  exporter's note: {plain(report.query['note'])}")
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
        print(f"    records after the last verified anchor: {run.unanchored_records}")
        for approval in run.approval_anchors:
            if approval.lag_ms is None:
                print(f"    seq {approval.seq} approval: no verified anchor covers it")
            else:
                print(f"    seq {approval.seq} approval: anchor lag {approval.lag_ms / 1000:.3f} s")
        if report.query is not None:
            print(f"    records outside the exported window: {report.outside_window[run.run_id]}")
        if run.run_id in report.parents_unresolved:
            print("    parent run not in this bundle; verify both bundles together")
    return 0


def _print_report(report: dict[str, object], *, as_json: bool) -> None:
    """Print the evidence report as text, or as JSON with sorted keys."""
    if as_json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(render_report(report), end="")


if __name__ == "__main__":
    raise SystemExit(main())
