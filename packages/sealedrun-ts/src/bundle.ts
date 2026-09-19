import { unzipSync } from "fflate";

import { VerificationError } from "./errors.js";
import { type HashAlg, isHashAlg, payloadDigest } from "./hashing.js";
import { checkHash, checkSignatures, DOMAIN_MANIFEST } from "./signing.js";
import type { SealedRunRecord, Delegation, Manifest } from "./types.js";
import { type RunReport, verifyRun } from "./verify.js";

export interface Bundle {
  manifest: Manifest;
  delegations: Map<string, Delegation>;
  runs: Map<string, SealedRunRecord[]>;
  payloads: Map<string, Uint8Array>;
  anchors: Map<string, unknown>;
}

export interface BundleReport {
  bundleId: string;
  runs: RunReport[];
}

const MANIFEST = "manifest.json";
const decoder = new TextDecoder();

export function readBundle(data: Uint8Array): Bundle {
  const files = unzipSync(data);
  const manifestBytes = files[MANIFEST];
  if (!manifestBytes) throw new VerificationError("bundle", "manifest.json missing");
  const manifest = JSON.parse(decoder.decode(manifestBytes)) as Manifest;
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
      const doc = JSON.parse(decoder.decode(content)) as Delegation;
      bundle.delegations.set(doc.delegation_id, doc);
    } else if (path.startsWith("runs/")) {
      const records = decoder
        .decode(content)
        .split("\n")
        .filter((line) => line.length > 0)
        .map((line) => JSON.parse(line) as SealedRunRecord);
      bundle.runs.set(path.slice("runs/".length, -".jsonl".length), records);
    } else if (path.startsWith("payloads/")) {
      bundle.payloads.set(path.slice(path.lastIndexOf("/") + 1), content);
    } else if (path.startsWith("anchors/")) {
      bundle.anchors.set(
        path.slice("anchors/".length, -".json".length),
        JSON.parse(decoder.decode(content)),
      );
    }
  }
  return bundle;
}

export function verifyBundle(bundle: Bundle): BundleReport {
  const { manifest } = bundle;
  if (!checkHash(manifest)) throw new VerificationError("manifest", "manifest hash mismatch");
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
  return { bundleId: manifest.bundle_id, runs };
}

function sameSet(a: string[], b: string[]): boolean {
  return a.length === b.length && new Set(a).size === a.length && a.every((x) => b.includes(x));
}
