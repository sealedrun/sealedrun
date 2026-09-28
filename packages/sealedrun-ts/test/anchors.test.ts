import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import {
  type Delegation,
  type RekorReceipt,
  type Rfc3161Receipt,
  type SealedRunRecord,
  selectWitnesses,
  shippedWitnesses,
  VerificationError,
  verifyBundleAsync,
  verifyReceipt,
  verifyRekor,
  verifyRfc3161,
  verifyRunAsync,
  readBundle,
  type Witness,
  witnessCovers,
} from "../src/index.js";
import { type WitnessJson, witnessFromJson } from "../src/trust.js";

const SPEC = join(import.meta.dirname, "..", "..", "..", "spec");
const VECTORS = join(SPEC, "vectors");
const readJson = <T>(...parts: string[]): T =>
  JSON.parse(readFileSync(join(VECTORS, ...parts), "utf8")) as T;

type Case = {
  name: string;
  type: string;
  witness: string;
  receipt: Rfc3161Receipt | RekorReceipt;
  verified: boolean;
};
type Captured = { witness: string; receipt: Rfc3161Receipt };

const SIGSTORE = "https://timestamp.sigstore.dev/api/v1/timestamp";
const DIGICERT = "http://timestamp.digicert.com";

describe("shipped trust list", () => {
  test("matches the Python copy and names the three witnesses", () => {
    const python = readFileSync(
      join(SPEC, "..", "packages", "sealedrun-py", "src", "sealedrun", "trust", "witnesses.json"),
      "utf8",
    );
    const ours = readFileSync(join(import.meta.dirname, "..", "src", "witnesses.json"), "utf8");
    expect(ours).toBe(python);
    const witnesses = shippedWitnesses();
    expect(witnesses.map((w) => [w.type, w.uri])).toEqual([
      ["rfc3161", SIGSTORE],
      ["rfc3161", DIGICERT],
      ["rekor", "https://rekor.sigstore.dev"],
    ]);
    const rekor = witnesses[2]!;
    expect(rekor.logId).toBe("c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d");
    expect(selectWitnesses(witnesses, "rekor", "x", rekor.logId)).toEqual([rekor]);
    expect(selectWitnesses(witnesses, "rfc3161", DIGICERT)).toEqual([witnesses[1]]);
    expect(witnessCovers(witnesses[0]!, new Date("2026-09-28T00:00:00Z"))).toBe(true);
    expect(witnessCovers(witnesses[0]!, new Date("2025-01-01T00:00:00Z"))).toBe(false);
    expect(witnessCovers(rekor, new Date("2099-01-01T00:00:00Z"))).toBe(true);
  });
});

describe("captured receipt vectors", () => {
  const cases = readJson<Case[]>("anchors", "cases.json");
  test.each(cases.map((c) => [c.name, c] as const))("%s", async (_name, c) => {
    const receipt = Object.fromEntries(
      Object.entries(c.receipt).filter(([, v]) => v !== null),
    ) as unknown as Rfc3161Receipt & RekorReceipt;
    const anchor = { type: c.type, witness: c.witness, receipt };
    expect(await verifyReceipt(anchor, shippedWitnesses())).toBe(c.verified);
  });

  test("the captured public log entry verifies and its proof index is shard-local", async () => {
    const doc = readJson<{ witness: string; receipt: RekorReceipt }>(
      "anchors",
      "rekor-sigstore.json",
    );
    expect(doc.receipt.inclusion_proof.log_index).not.toBe(doc.receipt.log_index);
    expect(await verifyRekor(doc.receipt, doc.witness, shippedWitnesses())).toBe(true);
    const noTime = { ...doc.receipt };
    delete noTime.integrated_time;
    delete noTime.signed_entry_timestamp;
    expect(await verifyRekor(noTime, doc.witness, shippedWitnesses())).toBe(false);
    for (const bad of [0, -5, 1e18, 4_102_444_800, 1.5]) {
      const receipt = { ...doc.receipt, integrated_time: bad };
      expect(await verifyRekor(receipt, doc.witness, shippedWitnesses())).toBe(false);
    }
    const rsaKey = { ...doc.receipt, public_key: doc.receipt.public_key.replace("MFkw", "MFkx") };
    expect(await verifyRekor(rsaKey, doc.witness, shippedWitnesses())).toBe(false);
    const cosigned = {
      ...doc.receipt,
      inclusion_proof: {
        ...doc.receipt.inclusion_proof,
        checkpoint: doc.receipt.inclusion_proof.checkpoint.replace(
          "\n\n",
          "\n\n— witness.example AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n",
        ),
      },
    };
    expect(await verifyRekor(cosigned, doc.witness, shippedWitnesses())).toBe(true);
  });

  test("a self-signed root offered in the receipt chain is never trusted", async () => {
    const sigstore = readJson<Captured>("anchors", "rfc3161-sigstore.json");
    const digicert = shippedWitnesses()[1]!;
    const wrongRoot: Witness = { ...digicert, uri: SIGSTORE };
    expect(sigstore.receipt.chain.length).toBe(2);
    expect(await verifyRfc3161(sigstore.receipt, SIGSTORE, [wrongRoot])).toBe(false);
    const stripped = { ...sigstore.receipt, chain: [] };
    expect(await verifyRfc3161(stripped, SIGSTORE, shippedWitnesses())).toBe(true);
  });

  test("full-chain token verifies without a receipt chain, wrong imprint algorithm fails", async () => {
    const digicert = readJson<Captured>("anchors", "rfc3161-digicert.json");
    expect(digicert.receipt.chain).toEqual([]);
    expect(await verifyRfc3161(digicert.receipt, DIGICERT, shippedWitnesses())).toBe(true);
    const other = { ...digicert.receipt, imprint_alg: "sha512" };
    expect(await verifyRfc3161(other, DIGICERT, shippedWitnesses())).toBe(false);
    const garbage = { ...digicert.receipt, token: "MAA=" };
    expect(await verifyRfc3161(garbage, DIGICERT, shippedWitnesses())).toBe(false);
  });
});

describe("hostile receipt vectors", () => {
  const doc = readJson<{ trust: WitnessJson[]; cases: Case[] }>("anchors", "hostile.json");
  const trust = doc.trust.map(witnessFromJson);
  test.each(doc.cases.map((c) => [c.name, c] as const))(
    "%s",
    async (_name, c) => {
      const receipt = c.receipt as Rfc3161Receipt;
      expect(await verifyRfc3161(receipt, c.witness, trust)).toBe(c.verified);
    },
    10_000,
  );
});

describe("reference run", () => {
  const records = readFileSync(join(VECTORS, "records", "valid-run.jsonl"), "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as SealedRunRecord);
  const delegation = readJson<Delegation>("delegations", "valid.json");
  const delegations = new Map([[delegation.delegation_id, delegation]]);

  test("its anchor is a verified Sigstore time-stamp", async () => {
    const report = await verifyRunAsync(records, delegations);
    expect([report.anchors, report.anchorsWitnessVerified]).toEqual([1, 1]);
    const untrusted = await verifyRunAsync(records, delegations, { witnesses: [] });
    expect([untrusted.anchors, untrusted.anchorsWitnessVerified]).toEqual([1, 0]);
    await expect(
      verifyRunAsync(records, delegations, { witnesses: [], strictWitness: true }),
    ).rejects.toMatchObject({ check: "witness", seq: 6 } satisfies Partial<VerificationError>);
  });

  test("bundle verification fills the count per run", async () => {
    const bundle = readBundle(new Uint8Array(readFileSync(join(VECTORS, "bundle", "valid.zip"))));
    const report = await verifyBundleAsync(bundle);
    expect(report.runs.map((r) => r.anchorsWitnessVerified)).toEqual([1]);
  });
});
