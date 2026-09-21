import {
  type SealedRunRecord,
  type Bundle,
  type BundleReport,
  readBundle,
  VerificationError,
  verifyBundle,
} from "@sealedrun/core";

/**
 * Result of checking a bundle file in the browser. Exactly one of `report` and `failure` is set;
 * `bundle` is also kept on failure when the archive itself could be read.
 */
export interface LocalVerification {
  fileName: string;
  sizeBytes: number;
  bundle: Bundle | null;
  report: BundleReport | null;
  failure: { check: string; runId?: string; seq?: number; message: string } | null;
}

/** Splits the trusted-principals text field into ids. Whitespace and commas both separate. */
export function parsePrincipals(text: string): string[] {
  return text.split(/[\s,]+/).filter(Boolean);
}

/**
 * Reads and verifies a bundle without throwing: a failed check or a malformed archive is returned
 * as `failure`.
 *
 * @param trustedPrincipals - Principal ids the user trusts. An empty list means "no trust anchor
 * given", not "trust nobody" (SPEC 13.2 step 2).
 */
export function verifyLocally(
  fileName: string,
  data: Uint8Array,
  trustedPrincipals: string[] = [],
): LocalVerification {
  let bundle: Bundle | null = null;
  try {
    bundle = readBundle(data);
    const report = verifyBundle(bundle, trustedPrincipals.length > 0 ? { trustedPrincipals } : {});
    return { fileName, sizeBytes: data.length, bundle, report, failure: null };
  } catch (error) {
    const failure =
      error instanceof VerificationError
        ? { check: error.check, message: error.message, runId: error.runId, seq: error.seq }
        : { check: "malformed", message: error instanceof Error ? error.message : String(error) };
    return { fileName, sizeBytes: data.length, bundle, report: null, failure };
  }
}

/**
 * Payload bytes as display text: pretty-printed when they parse as JSON, otherwise decoded as
 * lenient UTF-8.
 */
export function decodePayload(bytes: Uint8Array | undefined): string {
  if (!bytes) return "";
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}

/** The target's name, followed by its endpoint when the record has one. */
export function describeTarget(record: SealedRunRecord): string {
  const { target } = record;
  return target.endpoint ? `${target.name} @ ${target.endpoint}` : target.name;
}

/**
 * Headline counts for a run. A blocked call to a cloud target is not counted as a cloud call,
 * because nothing left the host.
 */
export function summarize(records: SealedRunRecord[]) {
  const cloud = records.filter((r) => r.target.location === "cloud" && r.outcome !== "blocked");
  const blocked = records.filter((r) => r.outcome === "blocked");
  const labels = new Set(records.flatMap((r) => r.data_labels));
  return {
    steps: records.length,
    cloudCalls: cloud.length,
    blocked: blocked.length,
    labels: [...labels].sort(),
    anchors: records.filter((r) => r.kind === "anchor").length,
  };
}
