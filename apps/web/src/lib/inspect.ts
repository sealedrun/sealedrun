import {
  type SealedRunRecord,
  type Bundle,
  type BundleReport,
  readBundle,
  shippedWitnesses,
  VerificationError,
  verifyBundleAsync,
  verifyReceipt,
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
 * as `failure`. Anchor receipts are checked offline against the trust list shipped with
 * `@sealedrun/core` (SPEC 8.4).
 *
 * @param trustedPrincipals - Principal ids the user trusts. An empty list means "no trust anchor
 * given", not "trust nobody" (SPEC 13.2 step 2).
 */
export async function verifyLocally(
  fileName: string,
  data: Uint8Array,
  trustedPrincipals: string[] = [],
): Promise<LocalVerification> {
  let bundle: Bundle | null = null;
  try {
    bundle = readBundle(data);
    const report = await verifyBundleAsync(
      bundle,
      trustedPrincipals.length > 0 ? { trustedPrincipals } : {},
    );
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

/**
 * Anchor record metadata for display: the witness, the receipt time, the anchor type and, for a
 * transparency log entry, its index and a link to the public entry.
 */
export function anchorInfo(record: SealedRunRecord) {
  const anchor = record.extensions?.["sealedrun.anchor"] as
    | {
        type?: string;
        witness?: string;
        receipt?: {
          gen_time?: string;
          integrated_time?: number;
          log_index?: number;
          log_url?: string;
        };
      }
    | undefined;
  if (record.kind !== "anchor" || !anchor) return null;
  const receipt = anchor.receipt ?? {};
  const time =
    receipt.gen_time ??
    (receipt.integrated_time !== undefined
      ? new Date(receipt.integrated_time * 1000).toISOString()
      : undefined);
  const logIndex = receipt.log_index;
  let entryUrl: string | undefined;
  if (logIndex !== undefined && receipt.log_url) {
    entryUrl =
      receipt.log_url === "https://rekor.sigstore.dev"
        ? `https://search.sigstore.dev/?logIndex=${logIndex}`
        : `${receipt.log_url}/api/v1/log/entries?logIndex=${logIndex}`;
  }
  return { type: anchor.type, witness: anchor.witness, time, logIndex, entryUrl };
}

/**
 * Per anchor record, whether its receipt verifies offline against the shipped witness trust
 * list (SPEC 8.4). Unknown witnesses and receipt types the verifier does not know give false.
 */
export async function witnessResults(records: SealedRunRecord[]): Promise<Map<string, boolean>> {
  const trust = shippedWitnesses();
  const results = new Map<string, boolean>();
  for (const record of records) {
    if (record.kind !== "anchor") continue;
    const anchor = record.extensions?.["sealedrun.anchor"] as Record<string, unknown> | undefined;
    results.set(record.record_id, anchor ? await verifyReceipt(anchor, trust) : false);
  }
  return results;
}
