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
  globMatch,
  parseScope,
  scopeWithin,
  parentOf,
  checkParentLinks,
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

describe("context run", () => {
  const records = readRecords("records", "context-run.jsonl");
  const expected = readJson<Record<string, { seq: number; hash: string; prev_hash: string }[]>>(
    "records",
    "expected.json",
  )["context-run.jsonl"]!;
  test("hashes reproduce and the run verifies", () => {
    records.forEach((record, i) => {
      expect(checkHash(record)).toBe(true);
      expect(record.hash).toBe(expected[i]!.hash);
    });
    const report = verifyRun(records, delegationMap(validDelegation()));
    expect(report.complete).toBe(true);
    const context = records[0]!.extensions!["sealedrun.context"]!;
    expect(context.agent_source).toBe("header");
    expect(records[1]!.policy!.policy_set_hash).toBe(context.policy_set_hash);
  });
});

describe("receipt run", () => {
  test("verifies and counts receipts by observer", () => {
    const records = readRecords("records", "receipt-run.jsonl");
    const report = verifyRun(records, delegationMap(validDelegation()));
    expect(report.complete).toBe(true);
    expect(report.receiptsProxy).toBe(1);
    expect(report.receiptsSelfReported).toBe(1);
    const receipt = records[1]!.extensions!["sealedrun.receipt"]!;
    expect(receipt["digest"]).toBe(records[1]!.payload!.response_hash);
  });
});

describe("parent links", () => {
  test("the parent-child bundle resolves and names the asking record", () => {
    const data = new Uint8Array(readFileSync(join(VECTORS, "bundle", "parent-child.zip")));
    const bundle = readBundle(data);
    const [parentId, childId] = [...bundle.runs.keys()];
    const child = bundle.runs.get(childId!)!;
    const link = parentOf(child)!;
    expect(link.runId).toBe(parentId);
    expect(parentOf(bundle.runs.get(parentId!)!)).toBeUndefined();
    expect(checkParentLinks(bundle.runs, bundle.delegations)).toEqual([]);
    const alone = new Map([[childId!, child]]);
    expect(checkParentLinks(alone, bundle.delegations)).toEqual([childId]);
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

describe("scope", () => {
  type Case = {
    findings: { check: string; seq: number }[];
    strict?: { check: string; seq: number };
  };
  const expected = readJson<Record<string, Case>>("scope", "expected.json");
  const scoped = () => readJson<Delegation>("scope", "scoped.delegation.json");
  test.each(Object.keys(expected))("%s", (name) => {
    const c = expected[name]!;
    const records = readRecords("scope", name);
    const report = verifyRun(records, delegationMap(scoped()));
    expect(report.complete).toBe(true);
    expect(report.findings.map((f) => ({ check: f.check, seq: f.seq }))).toEqual(c.findings);
    if (!c.strict) {
      expect(verifyRun(records, delegationMap(scoped()), { strictScope: true }).findings).toEqual(
        [],
      );
      return;
    }
    expectFailure(
      () => verifyRun(records, delegationMap(scoped()), { strictScope: true }),
      c.strict.check,
      c.strict.seq,
    );
  });
  test("the reference run is inside its delegation's scope", () => {
    const report = verifyRun(
      readRecords("records", "valid-run.jsonl"),
      delegationMap(validDelegation()),
    );
    expect(report.findings).toEqual([]);
  });
  test("a malformed structured key fails with schema", () => {
    expect(() => parseScope({ max_records: 0 })).toThrow("max_records");
    expect(() => parseScope({ allowed_targets: [{}] })).toThrow("non-empty");
    expect(() => parseScope({ denied_labels: [1] })).toThrow("denied_labels");
    expect(parseScope(undefined).deniedLabels.size).toBe(0);
    expect(parseScope({ budget_usd: 10 }).allowedTargets).toBeUndefined();
  });
  test("a child scope must stay within its parent's", () => {
    const parent = parseScope({
      allowed_targets: [
        { type: "tool", name: "filesystem/*" },
        { type: "model", provider: "ollama" },
      ],
      allowed_locations: ["local", "cloud"],
      denied_labels: ["secret"],
      max_records: 100,
    });
    const ok = {
      allowed_targets: [{ type: "tool", name: "filesystem/read_*", provider: "mcp:fs" }],
      allowed_locations: ["local"],
      denied_labels: ["secret", "pii"],
      max_records: 50,
    };
    expect(scopeWithin(parseScope(ok), parent)).toBeUndefined();
    expect(scopeWithin(parent, parent)).toBeUndefined();
    expect(scopeWithin(parseScope({ ...ok, allowed_targets: undefined }), parent)).toContain(
      "allowed_targets",
    );
    expect(
      scopeWithin(
        parseScope({ ...ok, allowed_targets: [{ type: "tool", name: "other/*" }] }),
        parent,
      ),
    ).toContain("target");
    expect(
      scopeWithin(parseScope({ ...ok, allowed_targets: [{ type: "model" }] }), parent),
    ).toContain("target");
    expect(
      scopeWithin(parseScope({ ...ok, allowed_locations: ["local", "unknown"] }), parent),
    ).toContain("unknown");
    expect(scopeWithin(parseScope({ ...ok, denied_labels: ["pii"] }), parent)).toContain("secret");
    expect(scopeWithin(parseScope({ ...ok, max_records: 101 }), parent)).toContain("max_records");
    expect(scopeWithin(parseScope({ ...ok, max_records: undefined }), parent)).toContain(
      "max_records",
    );
    expect(scopeWithin(parseScope(undefined), parseScope(undefined))).toBeUndefined();
  });

  test("glob matching knows only *", () => {
    expect(globMatch("filesystem/*", "filesystem/read_file")).toBe(true);
    expect(globMatch("*", "")).toBe(true);
    expect(globMatch("a*b*c", "a-b-c")).toBe(true);
    expect(globMatch("a*b*c", "abc")).toBe(true);
    expect(globMatch("a*c", "ac")).toBe(true);
    expect(globMatch("a*", "a")).toBe(true);
    expect(globMatch("*a", "a")).toBe(true);
    expect(globMatch("ab*ab", "ab")).toBe(false);
    expect(globMatch("filesystem/read_?", "filesystem/read_x")).toBe(false);
    expect(globMatch("filesystem/*", "other/read_file")).toBe(false);
    expect(globMatch("a.b", "axb")).toBe(false);
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
    payloads_omitted?: boolean;
    parents_unresolved?: string[];
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
      expect(report.payloadsOmitted).toBe(c.payloads_omitted ?? false);
      expect(report.parentsUnresolved).toEqual(c.parents_unresolved ?? []);
      return;
    }
    expectFailure(() => verifyBundle(readBundle(data), options), c.check!, c.seq);
  });
  test("a record id repeated across runs names the later run", () => {
    const data = new Uint8Array(
      readFileSync(join(VECTORS, "bundle", "duplicate-record-id-across-runs.zip")),
    );
    const bundle = readBundle(data);
    let failure: unknown;
    try {
      verifyBundle(bundle);
    } catch (e) {
      failure = e;
    }
    expect(failure).toBeInstanceOf(VerificationError);
    const error = failure as VerificationError;
    expect([error.check, error.runId, error.seq]).toEqual([
      "record_id",
      bundle.manifest.runs[1]!.run_id,
      0,
    ]);
    expect(error.message).toContain("across the runs");
  });
  test("each run of the duplicate bundle verifies on its own", () => {
    const data = new Uint8Array(
      readFileSync(join(VECTORS, "bundle", "duplicate-record-id-across-runs.zip")),
    );
    const bundle = readBundle(data);
    for (const records of bundle.runs.values()) {
      expect(verifyRun(records, bundle.delegations).complete).toBe(true);
    }
  });
  test("two runs with record ids of their own verify", () => {
    const data = new Uint8Array(readFileSync(join(VECTORS, "bundle", "two-runs.zip")));
    const report = verifyBundle(readBundle(data));
    expect(report.runs.map((r) => r.recordCount)).toEqual([9, 3]);
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

describe("decision run", () => {
  const records = readRecords("records", "decision-run.jsonl");
  const expected = readJson<Record<string, { seq: number; hash: string; prev_hash: string }[]>>(
    "records",
    "expected.json",
  )["decision-run.jsonl"]!;
  test("hashes reproduce, the gate links the decision, a tampered answer fails", () => {
    records.forEach((record, i) => {
      expect(checkHash(record)).toBe(true);
      expect(record.hash).toBe(expected[i]!.hash);
    });
    const report = verifyRun(records, delegationMap(validDelegation()));
    expect(report.complete).toBe(true);
    const decision = records[1]!.extensions!["sealedrun.decision"] as {
      answers: { value: number }[];
    };
    expect(decision.answers[0]!.value).toBe(0.97);
    expect(records[2]!.parent_record_id).toBe(records[1]!.record_id);
    const tampered = structuredClone(records);
    (
      tampered[1]!.extensions!["sealedrun.decision"] as { answers: { value: number }[] }
    ).answers[0]!.value = 0.01;
    expect(() => verifyRun(tampered, delegationMap(validDelegation()))).toThrow(/hash/);
    const malformed = structuredClone(records);
    (
      malformed[1]!.extensions!["sealedrun.decision"] as { answers: { type: string }[] }
    ).answers[0]!.type = "noul";
    expect(() => verifyRun(malformed, delegationMap(validDelegation()))).toThrow(/not one of/);
  });
});
