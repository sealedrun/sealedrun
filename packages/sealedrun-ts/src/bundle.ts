import { unzipSync } from "fflate";

import { canonicalize, type Json } from "./canonical.js";
import { verifyDelegation } from "./delegation.js";
import { VerificationError } from "./errors.js";
import { type HashAlg, isHashAlg, payloadDigest } from "./hashing.js";
import { assertDelegation, assertManifest, assertRecord } from "./structure.js";
import { checkHash, checkSignatures, DOMAIN_MANIFEST } from "./signing.js";
import type { SealedRunRecord, Delegation, Manifest } from "./types.js";
import { type RunReport, verifyRun } from "./verify.js";

/**
 * Parsed content of a bundle archive (SPEC 13). Parsing proves digests and structure, not signatures.
 */
export interface Bundle {
  manifest: Manifest;
  /** By `delegation_id`. */
  delegations: Map<string, Delegation>;
  /** By `run_id`, records in file order. */
  runs: Map<string, SealedRunRecord[]>;
  /** Bodies by base64url digest, which is also the file name. */
  payloads: Map<string, Uint8Array>;
  /** Raw witness receipts by the `record_id` of their anchor record. */
  anchors: Map<string, unknown>;
}

/** Result of a successful {@link verifyBundle}. */
export interface BundleReport {
  bundleId: string;
  runs: RunReport[];
  principalId: string;
  exporterAgentId: string;
  /** False means integrity only: the Principal was not compared with a trust anchor (SPEC 13.2). */
  principalTrusted: boolean;
}

/** Optional inputs of {@link verifyBundle}. */
export interface VerifyBundleOptions {
  /** Principal ids obtained out of band. The keys inside a bundle are not a root of trust. */
  trustedPrincipals?: Iterable<string>;
}

const MANIFEST = "manifest.json";
const decoder = new TextDecoder("utf-8", { fatal: true });

/** Most ZIP entries a bundle may have. */
export const MAX_ENTRIES = 10_000;
/** Default limit on the uncompressed size of one entry. */
export const MAX_ENTRY_BYTES = 64 * 1024 * 1024;
/** Limit on `manifest.json` (SPEC 13.1). {@link BundleLimits} cannot raise it. */
export const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
/** Default limit on the uncompressed size of all entries together. */
export const MAX_TOTAL_BYTES = 512 * 1024 * 1024;

/** Overrides of the archive size limits applied by {@link readBundle}. */
export interface BundleLimits {
  /** Defaults to {@link MAX_ENTRY_BYTES}. */
  maxEntryBytes?: number;
  /** Defaults to {@link MAX_TOTAL_BYTES}. */
  maxTotalBytes?: number;
}

/**
 * Unpacks a bundle ZIP and parses its files.
 *
 * @remarks
 * Size limits are enforced from the ZIP directory before anything is inflated. The file list must
 * equal `manifest.files` exactly, every file must match its digest, and every document must pass
 * its structural check. No signature is verified here. That is the job of {@link verifyBundle}.
 *
 * @throws VerificationError with check `bundle` or `schema`. Any other failure, such as invalid
 * ZIP, UTF-8 or JSON, is reported as `bundle: malformed archive`.
 */
export function readBundle(data: Uint8Array, limits: BundleLimits = {}): Bundle {
  try {
    return readArchive(unzipLimited(data, limits));
  } catch (error) {
    if (error instanceof VerificationError) throw error;
    throw new VerificationError("bundle", "malformed archive");
  }
}

/**
 * Inflates the archive, applying the limits to the central directory sizes before an entry is read.
 *
 * @remarks
 * Both sizes come from the central directory, so neither can be trusted on its own: a stored
 * entry is copied at its compressed size whatever `originalSize` claims, and entries may all
 * point at the same local data. Each entry is therefore counted at the larger of the two, and
 * the compressed sizes together may not exceed the archive.
 */
function unzipLimited(data: Uint8Array, limits: BundleLimits): Record<string, Uint8Array> {
  const maxEntry = limits.maxEntryBytes ?? MAX_ENTRY_BYTES;
  const maxTotal = limits.maxTotalBytes ?? MAX_TOTAL_BYTES;
  let entries = 0;
  let total = 0;
  let compressed = 0;
  return unzipSync(data, {
    filter: (file) => {
      entries += 1;
      const claimed = Math.max(file.originalSize, file.size);
      total += claimed;
      compressed += file.size;
      if (entries > MAX_ENTRIES) throw new VerificationError("bundle", "too many entries");
      if (claimed > (file.name === MANIFEST ? Math.min(maxEntry, MAX_MANIFEST_BYTES) : maxEntry)) {
        throw new VerificationError("bundle", "entry exceeds size limit");
      }
      if (total > maxTotal) {
        throw new VerificationError("bundle", "archive exceeds uncompressed size limit");
      }
      if (compressed > data.length) {
        throw new VerificationError("bundle", "entries overlap or exceed the archive");
      }
      return true;
    },
  });
}

function payloadKey(path: string, content: Uint8Array, hashAlg: HashAlg): string {
  const parts = path.split("/");
  if (parts.length !== 3 || parts[1] !== hashAlg) {
    throw new VerificationError("bundle", `malformed payload path ${path}`);
  }
  if (parts[2] !== payloadDigest(hashAlg, content)) {
    throw new VerificationError("bundle", `payload name is not the digest of its content: ${path}`);
  }
  return parts[2];
}

function readArchive(files: Record<string, Uint8Array>): Bundle {
  const manifestBytes = files[MANIFEST];
  if (!manifestBytes) throw new VerificationError("bundle", "manifest.json missing");
  const manifest: unknown = JSON.parse(decoder.decode(manifestBytes));
  assertManifest(manifest);
  if (!isHashAlg(manifest.hash_alg)) {
    throw new VerificationError("schema", "unsupported manifest hash_alg");
  }
  const hashAlg: HashAlg = manifest.hash_alg;
  const names = new Set(Object.keys(files).filter((n) => !n.endsWith("/")));
  const listed = new Set(Object.keys(manifest.files));
  const extra = [...names].filter((n) => n !== MANIFEST && !listed.has(n));
  if (extra.length) {
    throw new VerificationError("bundle", `files not in manifest: ${extra.sort().join(", ")}`);
  }
  const missing = [...listed].filter((n) => !names.has(n));
  if (missing.length) {
    throw new VerificationError("bundle", `files missing: ${missing.sort().join(", ")}`);
  }
  const bundle: Bundle = {
    manifest,
    delegations: new Map(),
    runs: new Map(),
    payloads: new Map(),
    anchors: new Map(),
  };
  for (const [path, expected] of Object.entries(manifest.files)) {
    const content = files[path];
    if (content === undefined) throw new VerificationError("bundle", `files missing: ${path}`);
    if (payloadDigest(hashAlg, content) !== expected) {
      throw new VerificationError("bundle", `digest mismatch for ${path}`);
    }
    if (path.startsWith("delegations/")) {
      const doc: unknown = JSON.parse(decoder.decode(content));
      assertDelegation(doc);
      bundle.delegations.set(doc.delegation_id, doc);
    } else if (path.startsWith("runs/")) {
      const records = decoder
        .decode(content)
        .split("\n")
        .filter((line) => line.length > 0)
        .map((line) => {
          const record: unknown = JSON.parse(line);
          assertRecord(record);
          return record;
        });
      bundle.runs.set(path.slice("runs/".length, -".jsonl".length), records);
    } else if (path.startsWith("payloads/")) {
      bundle.payloads.set(payloadKey(path, content, hashAlg), content);
    } else if (path.startsWith("anchors/")) {
      bundle.anchors.set(
        path.slice("anchors/".length, -".json".length),
        JSON.parse(decoder.decode(content)),
      );
    }
  }
  return bundle;
}

/**
 * Runs the verification procedure of SPEC 13.2 on a parsed bundle.
 *
 * @remarks
 * A bundle carries its own public keys, so without `trustedPrincipals` a pass proves internal
 * consistency only and the report has `principalTrusted: false`.
 *
 * @throws VerificationError naming the first failed check.
 * @throws TypeError if a timestamp is not in the SPEC 3 form.
 */
export function verifyBundle(bundle: Bundle, options: VerifyBundleOptions = {}): BundleReport {
  const { manifest } = bundle;
  const trusted = options.trustedPrincipals ? new Set(options.trustedPrincipals) : undefined;
  if (!checkHash(manifest)) throw new VerificationError("manifest", "manifest hash mismatch");
  for (const delegation of bundle.delegations.values()) {
    const problem = verifyDelegation(delegation);
    if (problem !== null) throw new VerificationError("delegation", problem);
    if (delegation.principal_id !== manifest.principal_id) {
      throw new VerificationError("manifest", "delegation principal differs from manifest");
    }
  }
  if (trusted && !trusted.has(manifest.principal_id)) {
    throw new VerificationError("trust", "principal is not in the trusted set");
  }
  const exporter = [...bundle.delegations.values()].find(
    (d) => d.agent_id === manifest.exporter.agent_id,
  );
  if (!exporter) throw new VerificationError("manifest", "exporter has no delegation in bundle");
  if (!checkSignatures(manifest, DOMAIN_MANIFEST, exporter.agent_keys)) {
    throw new VerificationError("manifest", "exporter signature invalid");
  }
  if (manifest.principal_signatures) {
    const principalKeys = exporter.principal_keys;
    if (!checkSignatures(manifest, DOMAIN_MANIFEST, principalKeys, "principal_signatures")) {
      throw new VerificationError("manifest", "principal signature invalid");
    }
  }
  if (!sameSet(manifest.delegations, [...bundle.delegations.keys()])) {
    throw new VerificationError("manifest", "delegation list does not match files");
  }
  if (
    !sameSet(
      manifest.runs.map((r) => r.run_id),
      [...bundle.runs.keys()],
    )
  ) {
    throw new VerificationError("manifest", "run list does not match files");
  }
  const runs = manifest.runs.map((entry) => {
    const records = bundle.runs.get(entry.run_id) ?? [];
    const report = verifyRun(records, bundle.delegations, {
      payloads: bundle.payloads,
      ...(entry.first_seq > 0 ? { expectedPrevHash: entry.first_hash } : {}),
    });
    if (report.recordCount !== entry.record_count || report.lastHash !== entry.last_hash) {
      throw new VerificationError("manifest", "run entry does not match records", entry.run_id);
    }
    if (report.complete !== entry.complete || report.firstSeq !== entry.first_seq) {
      throw new VerificationError("manifest", "run entry flags do not match records", entry.run_id);
    }
    return report;
  });
  checkAnchorFiles(bundle);
  return {
    bundleId: manifest.bundle_id,
    runs,
    principalId: manifest.principal_id,
    exporterAgentId: manifest.exporter.agent_id,
    principalTrusted: trusted !== undefined,
  };
}

/** Requires every `anchors/<record_id>.json` to be the receipt of that anchor record (SPEC 13). */
function checkAnchorFiles(bundle: Bundle): void {
  const receipts = new Map<string, unknown>();
  for (const records of bundle.runs.values()) {
    for (const r of records) {
      if (r.kind === "anchor")
        receipts.set(r.record_id, r.extensions?.["sealedrun.anchor"]?.["receipt"]);
    }
  }
  for (const [recordId, receipt] of bundle.anchors) {
    if (!receipts.has(recordId)) {
      throw new VerificationError("anchor", `receipt file for unknown anchor record ${recordId}`);
    }
    const expected = receipts.get(recordId);
    if (
      expected === undefined ||
      canonicalize(receipt as Json) !== canonicalize(expected as Json)
    ) {
      throw new VerificationError("anchor", `receipt file differs from anchor record ${recordId}`);
    }
  }
}

function sameSet(a: string[], b: string[]): boolean {
  return a.length === b.length && new Set(a).size === a.length && a.every((x) => b.includes(x));
}
