import { covers, verifyDelegation } from "./delegation.js";
import { VerificationError } from "./errors.js";
import { digestSize, type HashAlg, isHashAlg, payloadDigest, zeroHash } from "./hashing.js";
import { Approvals } from "./approval.js";
import { assertRecord } from "./structure.js";
import { type Finding, parseScope, scopeFindings, scopeWithin } from "./scope.js";
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
  /**
   * Records outside the delegation's scope (SPEC 6.5) and steps that ran without the human
   * approval their policy required (SPEC 6.6), in seq order. They do not break integrity; under
   * `strictScope` / `strictApproval` the first one fails the run instead.
   */
  findings: Finding[];
  /** Receipts the recorder wrote from the reply it relayed (SPEC 10.9). */
  receiptsProxy: number;
  /** Receipts the caller supplied. */
  receiptsSelfReported: number;
  /**
   * Seq of every `llm_call` whose `system_prompt_hash` differs from the previous `llm_call`'s
   * (SPEC 10.1), including a hash appearing or disappearing.
   */
  systemPromptChanges: number[];
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
  /** Fail with the finding's check (`scope.target` and the like) on the first scope finding. */
  strictScope?: boolean;
  /** Fail with the finding's check (`approval.missing` and the like) on the first approval finding. */
  strictApproval?: boolean;
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
 * (SPEC 13.2 steps 3 to 5). Records outside the delegation's scope are listed as findings
 * (SPEC 6.5).
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
  let scope;
  try {
    scope = parseScope(delegation.scope);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new VerificationError("schema", message, runId, firstSeq);
  }
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
    findings: [],
    receiptsProxy: 0,
    receiptsSelfReported: 0,
    systemPromptChanges: [],
  };
  let ended = false;
  let policySetHash: string | undefined;
  const seenIds = new Set<string>();
  const approvals = new Approvals();
  let promptSeen = false;
  let promptHash: string | undefined;

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
    if (seenIds.has(record.record_id)) {
      throw new VerificationError("record_id", "record_id repeats within the run", runId, seq);
    }
    seenIds.add(record.record_id);
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
    policySetHash = checkContext(record, policySetHash, runId, seq);
    const observedBy = checkReceipt(record, runId, seq);
    if (observedBy === "proxy") report.receiptsProxy += 1;
    else if (observedBy === "self_reported") report.receiptsSelfReported += 1;
    for (const finding of scopeFindings(scope, record, index + 1)) {
      if (options.strictScope)
        throw new VerificationError(finding.check, finding.reason, runId, seq);
      report.findings.push(finding);
    }
    if (record.kind === "llm_call") {
      const llm = record.extensions?.["sealedrun.llm"] as
        { system_prompt_hash?: string } | undefined;
      const current = llm?.system_prompt_hash;
      if (promptSeen && current !== promptHash) report.systemPromptChanges.push(seq);
      promptSeen = true;
      promptHash = current;
    }
    for (const finding of approvals.findings(record)) {
      if (options.strictApproval)
        throw new VerificationError(finding.check, finding.reason, runId, seq);
      report.findings.push(finding);
    }
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

/**
 * Applies SPEC 10.6: `sealedrun.context` sits on `run_start` only, and every `policy` block that
 * names a policy set names the run's. Returns the run's policy set digest, if any.
 */
function checkContext(
  record: SealedRunRecord,
  policySetHash: string | undefined,
  runId: string,
  seq: number,
): string | undefined {
  const context = record.extensions?.["sealedrun.context"];
  if (context !== undefined) {
    if (record.kind !== "run_start") {
      throw new VerificationError(
        "context",
        "sealedrun.context on a record other than run_start",
        runId,
        seq,
      );
    }
    const digest = context.policy_set_hash;
    policySetHash = typeof digest === "string" ? digest : undefined;
  }
  const declared = record.policy?.policy_set_hash;
  if (declared !== undefined && policySetHash !== undefined && declared !== policySetHash) {
    throw new VerificationError(
      "context",
      "policy_set_hash differs from the run's context",
      runId,
      seq,
    );
  }
  return policySetHash;
}

/**
 * Applies SPEC 10.9 to one record and returns the receipt's `observed_by`, if any: a `proxy`
 * receipt sits on a proxied record, is an `http_response` and carries the digest of the response
 * body the record already names; a proxied record carries no other receipt.
 */
function checkReceipt(record: SealedRunRecord, runId: string, seq: number): string | undefined {
  const extensions = record.extensions ?? {};
  const receipt = extensions["sealedrun.receipt"];
  const proxied = extensions["sealedrun.proxy"] !== undefined;
  if (receipt === undefined) return undefined;
  const observedBy = String(receipt["observed_by"]);
  if (observedBy === "proxy") {
    if (!proxied) {
      throw new VerificationError(
        "receipt",
        "proxy receipt on a record without sealedrun.proxy",
        runId,
        seq,
      );
    }
    if (receipt["kind"] !== "http_response") {
      throw new VerificationError("receipt", "proxy receipt is not an http_response", runId, seq);
    }
    const digest = receipt["digest"];
    if (digest === undefined || digest !== record.payload?.response_hash) {
      throw new VerificationError(
        "receipt",
        "receipt digest differs from payload.response_hash",
        runId,
        seq,
      );
    }
    if ((receipt["digest_alg"] ?? record.hash_alg) !== record.hash_alg) {
      throw new VerificationError("receipt", "receipt digest_alg differs from run", runId, seq);
    }
  } else if (proxied) {
    throw new VerificationError("receipt", "self-reported receipt on a proxied record", runId, seq);
  }
  return observedBy;
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

/** The parent link a run's `run_start` names (SPEC 6.4). */
export interface ParentLink {
  runId: string;
  recordId: string;
  delegationHash: string;
}

/** Returns the parent link named in a run's `run_start`, if any. */
export function parentOf(records: SealedRunRecord[]): ParentLink | undefined {
  const first = records[0];
  if (!first || first.kind !== "run_start") return undefined;
  const binding = first.extensions?.["sealedrun.delegation"];
  const runId = binding?.["parent_run_id"];
  if (binding === undefined || runId === undefined) return undefined;
  return {
    runId: String(runId),
    recordId: String(binding["parent_record_id"]),
    delegationHash: String(binding["parent_delegation_hash"]),
  };
}

/**
 * Applies the `parent.*` checks of SPEC 6.4 to every run that names a parent among `runs`, each
 * of which has passed {@link verifyRun}. Returns the ids of runs whose parent run is not among
 * `runs`.
 *
 * @throws VerificationError with check `parent.record`, `parent.kind`, `parent.time`,
 * `parent.delegation` or `parent.scope` on the child run.
 */
export function checkParentLinks(
  runs: Map<string, SealedRunRecord[]>,
  delegations: Map<string, Delegation>,
): string[] {
  const unresolved: string[] = [];
  for (const [runId, records] of runs) {
    const parent = parentOf(records);
    if (!parent) continue;
    const parentRecords = runs.get(parent.runId);
    if (!parentRecords) {
      unresolved.push(runId);
      continue;
    }
    const start = records[0];
    const asked = parentRecords.find((r) => r.record_id === parent.recordId);
    if (!asked)
      throw new VerificationError("parent.record", "parent record not in parent run", runId, 0);
    if (asked.kind !== "tool_call") {
      throw new VerificationError("parent.kind", "parent record is not a tool_call", runId, 0);
    }
    const parentStart = parentRecords[0];
    if (
      start &&
      parentStart &&
      parseTimestamp(start.occurred_at) < parseTimestamp(parentStart.occurred_at)
    ) {
      throw new VerificationError(
        "parent.time",
        "run_start is before the parent run's run_start",
        runId,
        0,
      );
    }
    const parentBinding = parentRecords[0]?.extensions?.["sealedrun.delegation"];
    if (parentBinding?.["hash"] !== parent.delegationHash) {
      throw new VerificationError(
        "parent.delegation",
        "parent_delegation_hash differs from parent run",
        runId,
        0,
      );
    }
    const problem = scopeWithin(
      parseScope(boundDelegation(records, delegations)?.scope),
      parseScope(boundDelegation(parentRecords, delegations)?.scope),
    );
    if (problem !== undefined) throw new VerificationError("parent.scope", problem, runId, 0);
  }
  return unresolved;
}

function boundDelegation(
  records: SealedRunRecord[],
  delegations: Map<string, Delegation>,
): Delegation | undefined {
  const binding = records[0]?.extensions?.["sealedrun.delegation"];
  return binding ? delegations.get(String(binding["delegation_id"])) : undefined;
}
