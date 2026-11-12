import { sha256 } from "@noble/hashes/sha2.js";

import type { Bundle, BundleReport } from "./bundle.js";
import type { Json } from "./canonical.js";
import type { VerificationError } from "./errors.js";
import type { ManifestQuery } from "./types.js";

/** Version of the report layout; raised when a field changes meaning. */
export const REPORT_VERSION = 1;

const TRUST_URL = "https://github.com/sealedrun/sealedrun/blob/main/TRUST.md";
const LIMITS =
  "This report restates what the verifier checked in the bundle. It does not show that the " +
  "recorder saw every action of the agent, that no run was left out of the export, or that " +
  "a recorded step was right to take. A principal that is not confirmed means the bundle " +
  `is consistent, not that it comes from the party you expect. See ${TRUST_URL}`;

/** An anchor record as the report names it: when it was recorded, its kind and its witness. */
export interface ReportAnchor {
  at: string;
  type: Json;
  witness: Json;
}

/** One run of the bundle in the report. */
export interface ReportRun {
  run_id: string;
  /** Run label of a run that starts in the bundle; null otherwise. */
  label: Json;
  records: number;
  first_record_at: string;
  last_record_at: string;
  complete: boolean;
  parent_unresolved: boolean;
  /** Records outside the query window; null without a query. */
  outside_window: number | null;
  anchors: number;
  witness_verified: number;
  unanchored_records: number;
}

/**
 * The one-page report of a bundle that passed verification, with the same keys in every
 * implementation (spec/vectors/report).
 */
export interface EvidenceReport {
  report_version: number;
  result: "passed";
  /** SHA-256 of the archive file, hex. */
  file_sha256: string;
  bundle: {
    bundle_id: string;
    created_at: string;
    software: string;
    exporter_agent_id: string;
    principal_id: string;
    principal_trusted: boolean;
    principal_countersigned: boolean;
    payloads: "included" | "omitted";
  };
  query: ManifestQuery | null;
  coverage: {
    runs: number;
    runs_complete: number;
    records: number;
    first_record_at: string | null;
    last_record_at: string | null;
    records_outside_window: number | null;
  };
  anchors: {
    count: number;
    witness_verified: number;
    first: ReportAnchor | null;
    last: ReportAnchor | null;
    unanchored_records: number;
  };
  approvals: {
    run_id: string;
    seq: number;
    at: string;
    actor: string;
    decision: Json;
    anchor_lag_ms: number | null;
  }[];
  findings: { run_id: string; seq: number; check: string; reason: string }[];
  runs: ReportRun[];
  limits: string;
}

/** The report of a bundle that failed verification: the failing check and nothing else. */
export interface FailureReport {
  report_version: number;
  result: "failed";
  file_sha256: string;
  check: string;
  run_id: string | null;
  seq: number | null;
  message: string;
  limits: string;
}

/** Returns the SHA-256 of the archive bytes in hex, the digest to note outside the agent's host. */
export function fileSha256(data: Uint8Array): string {
  return [...sha256(data)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Builds the report of a bundle that passed verification.
 *
 * @remarks
 * Pass the result of `verifyBundleAsync` so that the witness figures are filled; after the
 * synchronous `verifyBundle` no anchor counts as verified. Times are the recorder's
 * `occurred_at`; an anchor's time is that of its anchor record.
 *
 * @param sha256Hex - Digest of the archive file as received, from {@link fileSha256}.
 */
export function evidenceReport(
  bundle: Bundle,
  verified: BundleReport,
  sha256Hex: string,
): EvidenceReport {
  const { manifest } = bundle;
  const runs: ReportRun[] = [];
  const approvals: EvidenceReport["approvals"] = [];
  const findings: EvidenceReport["findings"] = [];
  const anchors: ReportAnchor[] = [];
  for (const run of verified.runs) {
    const records = bundle.runs.get(run.runId) ?? [];
    const times = records.map((r) => r.occurred_at).sort();
    const first = records[0];
    const label = first?.seq === 0 ? first.extensions?.["sealedrun.proxy"]?.run_label : undefined;
    runs.push({
      run_id: run.runId,
      label: label ?? null,
      records: run.recordCount,
      first_record_at: times[0] ?? "",
      last_record_at: times[times.length - 1] ?? "",
      complete: run.complete,
      parent_unresolved: verified.parentsUnresolved.includes(run.runId),
      outside_window: verified.outsideWindow[run.runId] ?? null,
      anchors: run.anchors,
      witness_verified: run.anchorsWitnessVerified,
      unanchored_records: run.unanchoredRecords,
    });
    const lags = new Map(run.approvalAnchors.map((a) => [a.seq, a.lagMs]));
    for (const record of records) {
      if (record.kind === "human_approval") {
        approvals.push({
          run_id: run.runId,
          seq: record.seq,
          at: record.occurred_at,
          actor: record.actor.id,
          decision: record.extensions?.["sealedrun.approval"]?.decision ?? null,
          anchor_lag_ms: lags.get(record.seq) ?? null,
        });
      } else if (record.kind === "anchor") {
        const anchor = record.extensions?.["sealedrun.anchor"];
        anchors.push({
          at: record.occurred_at,
          type: anchor?.type ?? null,
          witness: anchor?.witness ?? null,
        });
      }
    }
    for (const f of run.findings) {
      findings.push({ run_id: run.runId, seq: f.seq, check: f.check, reason: f.reason });
    }
  }
  anchors.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0));
  const sum = (pick: (run: ReportRun) => number) => runs.reduce((n, run) => n + pick(run), 0);
  const firsts = runs.map((r) => r.first_record_at).sort();
  const lasts = runs.map((r) => r.last_record_at).sort();
  return {
    report_version: REPORT_VERSION,
    result: "passed",
    file_sha256: sha256Hex,
    bundle: {
      bundle_id: manifest.bundle_id,
      created_at: manifest.created_at,
      software: manifest.exporter.software,
      exporter_agent_id: verified.exporterAgentId,
      principal_id: verified.principalId,
      principal_trusted: verified.principalTrusted,
      principal_countersigned: manifest.principal_signatures !== undefined,
      payloads: verified.payloadsOmitted ? "omitted" : "included",
    },
    query: verified.query ?? null,
    coverage: {
      runs: runs.length,
      runs_complete: runs.filter((r) => r.complete).length,
      records: sum((r) => r.records),
      first_record_at: firsts[0] ?? null,
      last_record_at: lasts[lasts.length - 1] ?? null,
      records_outside_window: verified.query ? sum((r) => r.outside_window ?? 0) : null,
    },
    anchors: {
      count: sum((r) => r.anchors),
      witness_verified: sum((r) => r.witness_verified),
      first: anchors[0] ?? null,
      last: anchors[anchors.length - 1] ?? null,
      unanchored_records: sum((r) => r.unanchored_records),
    },
    approvals,
    findings,
    runs,
    limits: LIMITS,
  };
}

/**
 * Builds the report of a bundle that failed verification. Nothing inside such a bundle is
 * repeated, because none of it can be relied on.
 */
export function failureReport(error: VerificationError, sha256Hex: string): FailureReport {
  return {
    report_version: REPORT_VERSION,
    result: "failed",
    file_sha256: sha256Hex,
    check: error.check,
    run_id: error.runId ?? null,
    seq: error.seq ?? null,
    message: error.reason,
    limits: LIMITS,
  };
}

// eslint-disable-next-line no-control-regex
const CONTROL = /[\x00-\x1f\x7f-\x9f]/g;

/** Renders a value from the bundle without characters that steer a terminal. */
const plain = (value: unknown): string =>
  (typeof value === "string" ? value : JSON.stringify(value)).replace(CONTROL, "?");

const row = (label: string, value: unknown): string => `  ${`${label}:`.padEnd(22)}${plain(value)}`;

const anchorLine = (anchor: ReportAnchor | null): string =>
  anchor === null
    ? "none"
    : `${anchor.at} (${plain(anchor.type)}, ${anchor.witness ? plain(anchor.witness) : "witness not named"})`;

/** Breaks text at spaces into indented lines of at most `width` characters where it can. */
function wrap(text: string, width = 76): string[] {
  const lines: string[] = [];
  let line = "";
  for (const word of text.split(" ")) {
    if (line && line.length + 1 + word.length > width) {
      lines.push(`  ${line}`);
      line = word;
    } else {
      line = line ? `${line} ${word}` : word;
    }
  }
  return [...lines, `  ${line}`];
}

/**
 * Renders a report as plain text ending in a newline, the same text in every implementation.
 */
export function renderReport(report: EvidenceReport | FailureReport): string {
  const lines = ["SealedRun evidence report", "=========================", ""];
  if (report.result === "failed") {
    const where =
      (report.run_id !== null ? `, run ${report.run_id}` : "") +
      (report.seq !== null ? `, seq ${report.seq}` : "");
    lines.push(
      "Verification",
      row("Result", `FAILED at check ${report.check}${where}`),
      row("Reason", report.message),
      row("File SHA-256", report.file_sha256),
      "",
      "Nothing in a bundle that fails verification can be relied on, so nothing else",
      "from it is repeated here.",
      "",
    );
    return lines.join("\n");
  }
  const { bundle, coverage, anchors, query } = report;
  lines.push(
    "Verification",
    row("Result", "PASSED: every hash, signature and chain link in the bundle was checked"),
    row("Principal", bundle.principal_id),
    row(
      "Principal identity",
      bundle.principal_trusted
        ? "confirmed: it is one of the principals the verifier was given"
        : "NOT CONFIRMED: the verifier was given no trusted principal to compare with",
    ),
    row(
      "Manifest signed by",
      bundle.principal_countersigned ? "exporter key and principal key" : "exporter key only",
    ),
    row(
      "Payload bodies",
      bundle.payloads === "included"
        ? "included and checked against the records"
        : "left out by the exporter; the records keep their digests, the bodies were not checked",
    ),
    "",
    "Bundle",
    row("File SHA-256", report.file_sha256),
    row("Bundle id", bundle.bundle_id),
    row("Created", bundle.created_at),
    row("Exported by", `${bundle.software}, agent ${bundle.exporter_agent_id}`),
    "",
    "What the exporter was asked for",
  );
  if (query === null) {
    lines.push("  No query: the bundle was not exported by a time window.");
  } else {
    lines.push(
      row("Window", `${query.since} to ${query.until} (end not included)`),
      row("Run label", query.label ?? "any"),
      row("Exporter's note", query.note ?? "none"),
    );
  }
  const open = coverage.runs - coverage.runs_complete;
  lines.push(
    "",
    "What the bundle covers",
    row("Runs", `${coverage.runs} (${coverage.runs_complete} ended, ${open} open)`),
    row("Records", String(coverage.records)),
    row("First record", coverage.first_record_at ?? "none"),
    row("Last record", coverage.last_record_at ?? "none"),
  );
  if (coverage.records_outside_window !== null) {
    lines.push(row("Outside the window", `${coverage.records_outside_window} records`));
  }
  lines.push(
    "",
    "Anchors (what an outside witness saw)",
    row("Anchor records", String(anchors.count)),
    row("Witness verified", `${anchors.witness_verified} of ${anchors.count}`),
    row("First anchor", anchorLine(anchors.first)),
    row("Last anchor", anchorLine(anchors.last)),
    row("Not anchored", `${anchors.unanchored_records} records after the last verified anchor`),
    "",
    `Human approvals: ${report.approvals.length}`,
  );
  for (const approval of report.approvals) {
    const seen =
      approval.anchor_lag_ms === null
        ? "no verified anchor covers it"
        : `a witness saw it ${(approval.anchor_lag_ms / 1000).toFixed(3)} s later`;
    const decision = approval.decision ? plain(approval.decision) : "decision not stated";
    lines.push(
      plain(
        `  run ${approval.run_id} seq ${approval.seq} at ${approval.at}: ` +
          `${decision} by ${approval.actor}; ${seen}`,
      ),
    );
  }
  lines.push("", `Findings: ${report.findings.length}`);
  for (const f of report.findings) {
    lines.push(plain(`  run ${f.run_id} seq ${f.seq} ${f.check}: ${f.reason}`));
  }
  lines.push("", "Runs");
  for (const run of report.runs) {
    const state = run.complete ? "ended" : "open";
    const parent = run.parent_unresolved ? ", parent run not in this bundle" : "";
    lines.push(
      plain(
        `  ${run.run_id} label ${run.label ? plain(run.label) : "none"}: ${run.records} records, ` +
          `${run.first_record_at} to ${run.last_record_at}, ${state}${parent}`,
      ),
    );
  }
  lines.push("", "Limits", ...wrap(report.limits), "");
  return lines.join("\n");
}
