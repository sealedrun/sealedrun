import { covers, verifyDelegation } from "./delegation.js";
import { VerificationError } from "./errors.js";
import { digestSize, type HashAlg, isHashAlg, payloadDigest, zeroHash } from "./hashing.js";
import { assertRecord } from "./structure.js";
import { checkHash, checkSignatures, DOMAIN_RECORD } from "./signing.js";
import { parseTimestamp } from "./time.js";
import { type RekorReceipt, verifyRekor } from "./anchors/rekor.js";
import { verifyRfc3161, type Rfc3161Receipt } from "./anchors/rfc3161.js";
import { shippedWitnesses, type Witness } from "./trust.js";
import type { SealedRunRecord, Delegation } from "./types.js";

/** Result of a successful {@link verifyRun}. */
export interface RunReport {
  runId: string;
  /** Records in the verified slice, which may be less than the whole run. */
  recordCount: number;
  firstSeq: number;
  lastHash: string;
  /** True when the slice contains a `run_end` record. */
  complete: boolean;
  /** Anchor records whose `anchored_hash` and receipt digest matched the run. */
  anchors: number;
  /**
   * Anchors whose receipt was verified offline against a witness in the trust list (SPEC 8.4).
   * Filled by {@link verifyRunAsync}; the synchronous {@link verifyRun} leaves it at 0 because
   * WebCrypto is asynchronous.
   */
  anchorsWitnessVerified: number;
  /** Per data label, the number of non-blocked records whose target location is `cloud`. */
  labelsSentToCloud: Record<string, number>;
}

/** Optional inputs of {@link verifyRun}. */
export interface VerifyRunOptions {
  /**
   * Bodies by base64url digest. When given, the bodies of `bundle` and `inline` payloads must be
   * present and match their digest and size.
   */
  payloads?: Map<string, Uint8Array>;
  /** `prev_hash` the first record must carry when the slice does not start at seq 0. */
  expectedPrevHash?: string;
}

/** Optional inputs of {@link verifyRunAsync}, on top of {@link VerifyRunOptions}. */
export interface WitnessOptions {
  /** Witness trust list; the shipped one when omitted, an empty list trusts no witness. */
  witnesses?: Witness[];
  /** Fail with check `witness` on an anchor that does not verify instead of not counting it. */
  strictWitness?: boolean;
}

/**
 * Verifies one run or a contiguous slice of it: structure, seq contiguity, hash chain, record
 * hashes, delegation binding and validity, agent signatures, anchors, and nothing after `run_end`
 * (SPEC 13.2 steps 3 to 5).
 *
 * @remarks
 * All records are checked against a single Delegation. For a run that starts at seq 0 it is the
 * one bound by `sealedrun.delegation` in `run_start` (SPEC 6.4). For a slice it is the first
 * Delegation in the map issued to the agent.
 *
 * @param records - Records in ascending seq order.
 * @param delegations - Delegations by `delegation_id`.
 * @throws VerificationError naming the first failed check, with run id and seq.
 * @throws TypeError if a timestamp is not in the SPEC 3 form.
 */
export function verifyRun(
  records: SealedRunRecord[],
  delegations: Map<string, Delegation>,
  options: VerifyRunOptions = {},
): RunReport {
  const first = records[0];
  if (!first) throw new VerificationError("empty", "run has no records");
  const runId = first.run_id;
  if (!isHashAlg(first.hash_alg)) {
    throw new VerificationError("hash_alg", "unsupported hash algorithm", runId, first.seq);
  }
  const hashAlg: HashAlg = first.hash_alg;
  const firstSeq = first.seq;
  let prevHash = options.expectedPrevHash ?? zeroHash(hashAlg);
  if (firstSeq === 0 && prevHash !== zeroHash(hashAlg)) {
    throw new VerificationError("chain", "run starts at seq 0 but prev hash is not zero", runId, 0);
  }
  const delegation = delegationForRun(first, delegations, runId);
  const last = records[records.length - 1] ?? first;
  const report: RunReport = {
    runId,
    recordCount: records.length,
    firstSeq,
    lastHash: last.hash,
    complete: false,
    anchors: 0,
    anchorsWitnessVerified: 0,
    labelsSentToCloud: {},
  };
  let ended = false;

  records.forEach((record, index) => {
    const seq = firstSeq + index;
    try {
      assertRecord(record);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new VerificationError("schema", message, runId, seq);
    }
    if (record.run_id !== runId) {
      throw new VerificationError("run", "record belongs to another run", runId, seq);
    }
    if (record.seq !== seq) {
      throw new VerificationError("seq", `expected seq ${seq}, got ${record.seq}`, runId, seq);
    }
    if (record.hash_alg !== hashAlg) {
      throw new VerificationError("hash_alg", "hash algorithm changed within run", runId, seq);
    }
    if (record.hash.length !== digestSize(hashAlg) * 2) {
      throw new VerificationError("hash_alg", "hash length does not match algorithm", runId, seq);
    }
    if (ended) throw new VerificationError("run_end", "record after run_end", runId, seq);
    if (record.prev_hash !== prevHash) {
      throw new VerificationError("chain", "prev_hash does not match previous record", runId, seq);
    }
    if (!checkHash(record)) throw new VerificationError("hash", "record hash mismatch", runId, seq);
    if (record.agent_id !== delegation.agent_id) {
      throw new VerificationError("delegation", "agent_id differs from delegation", runId, seq);
    }
    if (record.principal_id !== delegation.principal_id) {
      throw new VerificationError("delegation", "principal_id differs from delegation", runId, seq);
    }
    if (!covers(delegation, parseTimestamp(record.occurred_at))) {
      throw new VerificationError("delegation", "record outside delegation validity", runId, seq);
    }
    if (!checkSignatures(record, DOMAIN_RECORD, delegation.agent_keys)) {
      throw new VerificationError("signature", "agent signature invalid", runId, seq);
    }
    if (options.payloads) checkPayload(record, options.payloads, hashAlg, runId, seq);
    if (record.kind === "anchor") {
      checkAnchor(record, records, firstSeq, runId, seq);
      report.anchors += 1;
    }
    if (record.kind === "run_end") ended = true;
    if (record.target.location === "cloud" && record.outcome !== "blocked") {
      for (const label of record.data_labels) {
        report.labelsSentToCloud[label] = (report.labelsSentToCloud[label] ?? 0) + 1;
      }
    }
    prevHash = record.hash;
  });

  report.complete = ended;
  return report;
}

function delegationForRun(
  first: SealedRunRecord,
  delegations: Map<string, Delegation>,
  runId: string,
): Delegation {
  let delegation: Delegation | undefined;
  if (first.seq === 0) {
    const binding = first.extensions?.["sealedrun.delegation"];
    if (!binding)
      throw new VerificationError("delegation", "run_start lacks sealedrun.delegation", runId, 0);
    delegation = delegations.get(String(binding["delegation_id"]));
    if (!delegation)
      throw new VerificationError("delegation", "delegation not in bundle", runId, 0);
    if (delegation.hash !== binding["hash"]) {
      throw new VerificationError("delegation", "delegation hash mismatch", runId, 0);
    }
  } else {
    delegation = [...delegations.values()].find((d) => d.agent_id === first.agent_id);
    if (!delegation) {
      throw new VerificationError("delegation", "no delegation for agent", runId, first.seq);
    }
  }
  const problem = verifyDelegation(delegation);
  if (problem) throw new VerificationError("delegation", problem, runId, first.seq);
  return delegation;
}

function checkPayload(
  record: SealedRunRecord,
  payloads: Map<string, Uint8Array>,
  hashAlg: HashAlg,
  runId: string,
  seq: number,
): void {
  const ref = record.payload;
  if (!ref || (ref.storage !== "bundle" && ref.storage !== "inline")) return;
  for (const side of ["request", "response"] as const) {
    const expected = ref[`${side}_hash`];
    if (expected === undefined) continue;
    const body = payloads.get(expected);
    if (!body) throw new VerificationError("payload", `${side} body missing`, runId, seq);
    if (payloadDigest(hashAlg, body) !== expected || body.length !== ref[`${side}_size`]) {
      throw new VerificationError("payload", `${side} body digest mismatch`, runId, seq);
    }
  }
}

/**
 * {@link verifyRun}, then the anchor receipts against the witness trust list (SPEC 8.4), filling
 * `anchorsWitnessVerified`. `rfc3161` and `rekor` receipts are verified; other types count as
 * bound, not verified.
 *
 * @throws VerificationError as {@link verifyRun}, plus check `witness` under `strictWitness`.
 */
export async function verifyRunAsync(
  records: SealedRunRecord[],
  delegations: Map<string, Delegation>,
  options: VerifyRunOptions & WitnessOptions = {},
): Promise<RunReport> {
  const report = verifyRun(records, delegations, options);
  report.anchorsWitnessVerified = await verifyWitnesses(records, options);
  return report;
}

/**
 * Counts the anchors of an already verified run whose receipt verifies against the trust list.
 *
 * @throws VerificationError with check `witness` under `strictWitness`.
 */
export async function verifyWitnesses(
  records: SealedRunRecord[],
  options: WitnessOptions = {},
): Promise<number> {
  const witnesses = options.witnesses ?? shippedWitnesses();
  let verified = 0;
  for (const record of records) {
    if (record.kind !== "anchor") continue;
    const anchor = record.extensions?.["sealedrun.anchor"] as Record<string, unknown>;
    const ok = await verifyReceipt(anchor, witnesses);
    if (ok) verified += 1;
    else if (options.strictWitness) {
      throw new VerificationError(
        "witness",
        "anchor receipt not verified",
        record.run_id,
        record.seq,
      );
    }
  }
  return verified;
}

/** Verifies one anchor's receipt by its type against the trust list (SPEC 8.4). */
export async function verifyReceipt(
  anchor: Record<string, unknown>,
  witnesses: Witness[],
): Promise<boolean> {
  const witness = anchor["witness"] as string;
  if (anchor["type"] === "rfc3161") {
    return verifyRfc3161(anchor["receipt"] as Rfc3161Receipt, witness, witnesses);
  }
  if (anchor["type"] === "rekor") {
    return verifyRekor(anchor["receipt"] as RekorReceipt, witness, witnesses);
  }
  return false;
}

/**
 * Checks that an anchor record points at an earlier record of the same run and that its receipt
 * carries the digest the witness was given (SPEC 8.1).
 *
 * @remarks
 * Whether the receipt is genuine is settled by {@link verifyWitnesses}.
 */
function checkAnchor(
  record: SealedRunRecord,
  records: SealedRunRecord[],
  firstSeq: number,
  runId: string,
  seq: number,
): void {
  const anchor = record.extensions?.["sealedrun.anchor"];
  if (!anchor)
    throw new VerificationError("anchor", "anchor record lacks sealedrun.anchor", runId, seq);
  const anchoredSeq = anchor["anchored_seq"];
  const anchoredHash = anchor["anchored_hash"];
  if (!Number.isSafeInteger(anchoredSeq) || (anchoredSeq as number) < 0) {
    throw new VerificationError("anchor", "anchored_seq is not a non-negative integer", runId, seq);
  }
  if (typeof anchoredHash !== "string") {
    throw new VerificationError("anchor", "anchored_hash is missing", runId, seq);
  }
  const index = (anchoredSeq as number) - firstSeq;
  if (index < 0 || index >= records.length || (anchoredSeq as number) >= seq) {
    throw new VerificationError("anchor", "anchored_seq not in run before anchor", runId, seq);
  }
  if (records[index]?.hash !== anchoredHash) {
    throw new VerificationError("anchor", "anchored_hash does not match record", runId, seq);
  }
  const receipt = anchor["receipt"] as Record<string, unknown>;
  if (receipt["digest"] !== anchoredHash) {
    throw new VerificationError(
      "anchor",
      "receipt digest does not match anchored_hash",
      runId,
      seq,
    );
  }
}
