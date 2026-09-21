import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, test } from "vitest";

import {
  type SealedRunRecord,
  canonicalize,
  checkHash,
  type Delegation,
  hexDecode,
  hexEncode,
  type Json,
  kidOf,
  publicKeyFromSeed,
  readBundle,
  type SigAlg,
  VerificationError,
  verifyBundle,
  verifyDelegation,
  verifyOne,
  verifyRun,
  b64urlEncode,
} from "../src/index.js";

const VECTORS = join(import.meta.dirname, "..", "..", "..", "spec", "vectors");

const readJson = <T>(...parts: string[]): T =>
  JSON.parse(readFileSync(join(VECTORS, ...parts), "utf8")) as T;
const readRecords = (...parts: string[]): SealedRunRecord[] =>
  readFileSync(join(VECTORS, ...parts), "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as SealedRunRecord);
const validDelegation = () => readJson<Delegation>("delegations", "valid.json");
const delegationMap = (d: Delegation) => new Map([[d.delegation_id, d]]);

function expectFailure(fn: () => unknown, check: string, seq?: number) {
  let error: unknown;
  try {
    fn();
  } catch (e) {
    error = e;
  }
  expect(error).toBeInstanceOf(VerificationError);
  const failure = error as VerificationError;
  expect(failure.check).toBe(check);
  if (seq !== undefined) expect(failure.seq).toBe(seq);
}

describe("RFC 8785 canonicalization", () => {
  const cases = readdirSync(join(VECTORS, "jcs")).filter((f) => f.endsWith(".json"));
  test.each(cases)("%s", (file) => {
    const input = readJson<Json>("jcs", file);
    const expected = readFileSync(join(VECTORS, "jcs", file.replace(".json", ".expected")), "utf8");
    expect(canonicalize(input)).toBe(expected);
  });
});

describe("keys", () => {
  type Entry = { seeds: Record<string, string>; public: Record<string, string>; kid: string };
  const keys = readJson<Record<string, Entry>>("keys.json");
  test.each(["principal", "agent", "attacker"])("%s derives from seeds", (name) => {
    const entry = keys[name]!;
    for (const [alg, seedHex] of Object.entries(entry.seeds)) {
      const pub = publicKeyFromSeed(alg as SigAlg, hexDecode(seedHex));
      expect(b64urlEncode(pub)).toBe(entry.public[alg]);
    }
    expect(kidOf(entry.public)).toBe(entry.kid);
  });
  test("other profiles derive from the same seeds", () => {
    const others = readJson<{
      other_profiles: Record<string, Record<string, Record<string, string>>>;
    }>("keys.json").other_profiles;
    for (const [, byName] of Object.entries(others)) {
      for (const [name, pub] of Object.entries(byName)) {
        for (const [alg, value] of Object.entries(pub)) {
          const seed = new TextEncoder().encode(`${name}:${alg}`);
          const padded = new Uint8Array(32);
          padded.set(seed);
          expect(b64urlEncode(publicKeyFromSeed(alg as SigAlg, padded))).toBe(value);
        }
      }
    }
  });
});

describe("ed25519 edge cases", () => {
  type Case = { name: string; ok: boolean; public_key: string; message: string; signature: string };
  const hex = (s: string) => new Uint8Array(Buffer.from(s, "hex"));
  test.each(readJson<Case[]>("signatures", "ed25519.json"))("$name", (c) => {
    expect(verifyOne("ed25519", hex(c.public_key), hex(c.message), hex(c.signature))).toBe(c.ok);
  });
});

describe("delegation", () => {
  const expected = readJson<Record<string, { ok: boolean; hash: string }>>(
    "delegations",
    "expected.json",
  );
  test.each(Object.keys(expected))("vector %s", (name) => {
    const d = readJson<Delegation>("delegations", name);
    if (expected[name]!.ok) expect(verifyDelegation(d)).toBeNull();
    else expect(verifyDelegation(d)).toBe("principal signature invalid");
    expect(d.hash).toBe(expected[name]!.hash);
  });
  test("forged agent id is rejected", () => {
    expect(verifyDelegation({ ...validDelegation(), agent_id: "x" })).not.toBeNull();
  });
  test("did principal is rejected", () => {
    const d = { ...validDelegation(), principal_id: "did:web:example.com" };
    expect(verifyDelegation(d)).toContain("did");
  });
});

describe("valid run", () => {
  const records = readRecords("records", "valid-run.jsonl");
  const expected = readJson<Record<string, { seq: number; hash: string; prev_hash: string }[]>>(
    "records",
    "expected.json",
  )["valid-run.jsonl"]!;
  test("hashes reproduce", () => {
    records.forEach((record, i) => {
      expect(checkHash(record)).toBe(true);
      expect(record.hash).toBe(expected[i]!.hash);
      expect(record.prev_hash).toBe(expected[i]!.prev_hash);
    });
  });
  test("verifies end to end", () => {
    const report = verifyRun(records, delegationMap(validDelegation()));
    expect(report.complete).toBe(true);
    expect(report.anchors).toBe(1);
    expect(report.recordCount).toBe(records.length);
    expect(report.labelsSentToCloud).toEqual({ pii: 1 });
  });
});

describe("negative chains", () => {
  type Case = { check: string; seq: number; delegation?: string };
  const expected = readJson<Record<string, Case>>("chains", "expected.json");
  test.each(Object.keys(expected))("%s", (name) => {
    const c = expected[name]!;
    const delegation = c.delegation
      ? readJson<Delegation>("chains", c.delegation)
      : validDelegation();
    expectFailure(
      () => verifyRun(readRecords("chains", name), delegationMap(delegation)),
      c.check,
      c.seq,
    );
  });
});

describe("bundles", () => {
  type Case = {
    ok: boolean;
    check?: string;
    seq?: number;
    runs?: number;
    records?: number;
    complete?: boolean;
    trusted_principals?: string[];
  };
  const expected = readJson<Record<string, Case>>("bundle", "expected.json");
  test.each(Object.keys(expected))("%s", (name) => {
    const c = expected[name]!;
    const data = new Uint8Array(readFileSync(join(VECTORS, "bundle", name)));
    const options = c.trusted_principals ? { trustedPrincipals: c.trusted_principals } : {};
    if (c.ok) {
      const report = verifyBundle(readBundle(data), options);
      expect(report.principalTrusted).toBe(c.trusted_principals !== undefined);
      expect(report.runs).toHaveLength(c.runs!);
      expect(report.runs[0]!.recordCount).toBe(c.records);
      expect(report.runs[0]!.complete).toBe(c.complete);
      return;
    }
    expectFailure(() => verifyBundle(readBundle(data), options), c.check!, c.seq);
  });
  test("unknown principal without a trust anchor is integrity only", () => {
    const data = new Uint8Array(readFileSync(join(VECTORS, "bundle", "unknown-principal.zip")));
    const report = verifyBundle(readBundle(data));
    expect(report.principalTrusted).toBe(false);
    expect(report.principalId).toBe(
      readJson<{ attacker: { kid: string } }>("keys.json").attacker.kid,
    );
    expect(report.exporterAgentId).not.toBe("");
  });
});

test("hex helpers round-trip", () => {
  expect(hexEncode(hexDecode("00ff10"))).toBe("00ff10");
});
