import {
  type SealedRunRecord,
  type Bundle,
  type BundleReport,
  readBundle,
  selectWitnesses,
  shippedWitnesses,
  VerificationError,
  verifyBundleAsync,
  verifyReceipt,
  type Witness,
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

/** Most characters of one body or extension block the page renders; the rest is downloadable. */
export const DISPLAY_CAP = 256 * 1024;

/** Cuts `text` at `cap` characters with a note on what was left out. */
export function capText(text: string, cap = DISPLAY_CAP): string {
  if (text.length <= cap) return text;
  return `${text.slice(0, cap)}\n… ${text.length - cap} more characters not shown; download the body for all of it`;
}

/**
 * Payload bytes as display text: pretty-printed when they parse as JSON, otherwise decoded as
 * lenient UTF-8. Bodies past {@link DISPLAY_CAP} are cut rather than pretty-printed, so one
 * huge body cannot freeze the tab.
 */
export function decodePayload(bytes: Uint8Array | undefined, cap = DISPLAY_CAP): string {
  if (!bytes) return "";
  const decoder = new TextDecoder("utf-8", { fatal: false });
  if (bytes.length > cap) {
    const head = decoder.decode(bytes.subarray(0, cap));
    return `${head}\n… ${bytes.length - cap} more bytes not shown; download the body for all of it`;
  }
  const text = decoder.decode(bytes);
  try {
    return capText(JSON.stringify(JSON.parse(text), null, 2), cap);
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
 * Whether the record is the caller's own account of a step (`sealedrun.step`), as opposed to
 * something the recorder saw itself through a proxy or a trace receiver.
 */
export function isSelfReported(record: SealedRunRecord): boolean {
  return record.extensions?.["sealedrun.step"] !== undefined;
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

/** Most bytes a bundle file may have to be verified in the browser; the CLI has no such cap. */
export const MAX_BROWSER_BUNDLE_BYTES = 1024 * 1024 * 1024;
/** Above this, the Inspector points at the export without payloads before a full one. */
export const LARGE_EXPORT_BYTES = 256 * 1024 * 1024;

/** Bytes the distinct payload bodies of these records would add to a full export. */
export function payloadBytes(records: SealedRunRecord[]): number {
  const sizes = new Map<string, number>();
  for (const record of records) {
    const ref = record.payload;
    if (!ref || ref.storage !== "bundle") continue;
    for (const side of ["request", "response"] as const) {
      const hash = ref[`${side}_hash`];
      if (typeof hash === "string") sizes.set(hash, Number(ref[`${side}_size`] ?? 0));
    }
  }
  let total = 0;
  for (const size of sizes.values()) total += size;
  return total;
}

/** A byte count in decimal units with at most one decimal, for example `1.2 GB`. */
export function formatBytes(size: number): string {
  let value = size;
  for (const unit of ["B", "kB", "MB", "GB"]) {
    if (value < 1000 || unit === "GB") {
      return unit === "B" ? `${value} B` : `${value.toFixed(1).replace(/\.0$/, "")} ${unit}`;
    }
    value /= 1000;
  }
  return `${value.toFixed(1)} GB`;
}

/** The `sealedrun.context` of a run's `run_start` (SPEC 10.6), as far as the record carries it. */
export interface RunContext {
  recorder: string;
  agent?: string;
  agentSource?: string;
  policySetHash?: string;
  toolInventoryHash?: string;
  toolInventoryServer?: string;
}

/** Reads the run context from the `run_start` record; null when the run carries none. */
export function runContext(records: SealedRunRecord[]): RunContext | null {
  const start = records.find((r) => r.kind === "run_start");
  const raw = start?.extensions?.["sealedrun.context"];
  if (!raw || typeof raw.recorder_software !== "string") return null;
  const text = (key: string) => (typeof raw[key] === "string" ? (raw[key] as string) : undefined);
  const name = text("agent_software");
  const version = text("agent_version");
  const context: RunContext = { recorder: raw.recorder_software };
  if (name) context.agent = version ? `${name} ${version}` : name;
  const source = text("agent_source");
  if (source) context.agentSource = source;
  const policy = text("policy_set_hash");
  if (policy) context.policySetHash = policy;
  const tools = text("tool_inventory_hash");
  if (tools) context.toolInventoryHash = tools;
  const server = text("tool_inventory_server");
  if (server) context.toolInventoryServer = server;
  return context;
}

/**
 * Names what makes two runs not comparable: the agent, the policy set or the tool inventory
 * differs. Empty when they match on everything both runs state.
 */
export function contextDifferences(a: RunContext, b: RunContext): string[] {
  const differences: string[] = [];
  if (a.agent !== b.agent) differences.push("agent");
  if (a.policySetHash !== b.policySetHash) differences.push("policy set");
  if (a.toolInventoryHash !== b.toolInventoryHash) differences.push("tool inventory");
  return differences;
}

/** What the offline witness check found for one anchor record. */
export interface WitnessVerdict {
  verified: boolean;
  /** The trust entry that verified the receipt: its endpoint and the root's subject. */
  witness?: string;
  subject?: string;
}

/** The key of a record in a bundle-wide map; record ids are unique per run only. */
export function recordKey(record: Pick<SealedRunRecord, "run_id" | "record_id">): string {
  return `${record.run_id}/${record.record_id}`;
}

/**
 * Anchor record metadata for display: the witness, the receipt time, the anchor type and, for a
 * transparency log entry, its index and a link to the public entry.
 *
 * Only what the offline check authenticated is shown as the witness's word: for a verified
 * receipt the witness name and the link come from the trust entry that verified it, never from
 * the record. A `rekor` time is the log's `integrated_time`; `gen_time` is trusted only for an
 * `rfc3161` receipt, where the verifier checks it against the signed token.
 */
export function anchorInfo(record: SealedRunRecord, verdict?: WitnessVerdict) {
  const anchor = record.extensions?.["sealedrun.anchor"] as
    | {
        type?: string;
        witness?: string;
        receipt?: {
          gen_time?: string;
          integrated_time?: number;
          log_index?: number;
        };
      }
    | undefined;
  if (record.kind !== "anchor" || !anchor) return null;
  const receipt = anchor.receipt ?? {};
  const time =
    anchor.type === "rekor"
      ? receipt.integrated_time !== undefined
        ? new Date(receipt.integrated_time * 1000).toISOString()
        : undefined
      : receipt.gen_time;
  const logIndex = receipt.log_index;
  const verified = verdict?.verified === true && verdict.witness !== undefined;
  let entryUrl: string | undefined;
  if (verified && anchor.type === "rekor" && Number.isInteger(logIndex)) {
    const logUrl = trimSlashes(verdict.witness ?? "");
    entryUrl =
      logUrl === "https://rekor.sigstore.dev"
        ? `https://search.sigstore.dev/?logIndex=${logIndex}`
        : `${logUrl}/api/v1/log/entries?logIndex=${logIndex}`;
  }
  const witness = verified ? verdict.witness : anchor.witness;
  return {
    type: anchor.type,
    witness,
    subject: verified ? verdict.subject : undefined,
    time,
    logIndex,
    entryUrl,
  };
}

function trimSlashes(text: string): string {
  let end = text.length;
  while (end > 0 && text[end - 1] === "/") end -= 1;
  return text.slice(0, end);
}

/**
 * Per anchor record (keyed by {@link recordKey}), whether its receipt verifies offline against
 * the shipped witness trust list (SPEC 8.4) and which entry verified it. Unknown witnesses and
 * receipt types the verifier does not know give an unverified verdict.
 */
export async function witnessResults(
  records: SealedRunRecord[],
): Promise<Map<string, WitnessVerdict>> {
  const trust = shippedWitnesses();
  const results = new Map<string, WitnessVerdict>();
  for (const record of records) {
    if (record.kind !== "anchor") continue;
    const anchor = record.extensions?.["sealedrun.anchor"] as Record<string, unknown> | undefined;
    results.set(recordKey(record), anchor ? await verdictFor(anchor, trust) : { verified: false });
  }
  return results;
}

async function verdictFor(
  anchor: Record<string, unknown>,
  trust: Witness[],
): Promise<WitnessVerdict> {
  const receipt = anchor["receipt"] as { log_id?: unknown } | undefined;
  const logId = typeof receipt?.log_id === "string" ? receipt.log_id : undefined;
  const entries = selectWitnesses(trust, String(anchor["type"]), String(anchor["witness"]), logId);
  for (const entry of entries) {
    if (await verifyReceipt(anchor, [entry])) {
      return { verified: true, witness: entry.uri, subject: entry.subject };
    }
  }
  return { verified: false };
}
