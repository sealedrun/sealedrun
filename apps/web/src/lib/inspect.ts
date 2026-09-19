import {
  type SealedRunRecord,
  type Bundle,
  type BundleReport,
  readBundle,
  VerificationError,
  verifyBundle,
} from "@sealedrun/core";

export interface LocalVerification {
  fileName: string;
  sizeBytes: number;
  bundle: Bundle | null;
  report: BundleReport | null;
  failure: { check: string; runId?: string; seq?: number; message: string } | null;
}

export function verifyLocally(fileName: string, data: Uint8Array): LocalVerification {
  let bundle: Bundle | null = null;
  try {
    bundle = readBundle(data);
    const report = verifyBundle(bundle);
    return { fileName, sizeBytes: data.length, bundle, report, failure: null };
  } catch (error) {
    const failure =
      error instanceof VerificationError
        ? { check: error.check, message: error.message, runId: error.runId, seq: error.seq }
        : { check: "malformed", message: error instanceof Error ? error.message : String(error) };
    return { fileName, sizeBytes: data.length, bundle, report: null, failure };
  }
}

export function decodePayload(bytes: Uint8Array | undefined): string {
  if (!bytes) return "";
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return text;
  }
}

export function describeTarget(record: SealedRunRecord): string {
  const { target } = record;
  return target.endpoint ? `${target.name} @ ${target.endpoint}` : target.name;
}

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
