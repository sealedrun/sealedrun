import { zipSync } from "fflate";
import { describe, expect, test } from "vitest";

import {
  assertDelegation,
  assertExtensions,
  assertRecord,
  readBundle,
  VerificationError,
} from "../src/index.js";
import { isHashAlg } from "../src/hashing.js";

/** Rewrites the central-directory uncompressed size of `name`, as a forged archive would. */
const claimSize = (archive: Uint8Array, name: string, size: number): Uint8Array => {
  const data = new Uint8Array(archive);
  const view = new DataView(data.buffer);
  for (let pos = 0; pos + 46 <= data.length; pos++) {
    if (view.getUint32(pos, true) !== 0x02014b50) continue;
    const nameLength = view.getUint16(pos + 28, true);
    const entry = new TextDecoder().decode(data.subarray(pos + 46, pos + 46 + nameLength));
    if (entry === name) view.setUint32(pos + 24, size, true);
  }
  return data;
};

const bomb = (size: number) =>
  zipSync({ "manifest.json": new Uint8Array([123, 125]), "payloads/zeros": new Uint8Array(size) });

describe("structural validation", () => {
  const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
  test("manifest with wrong field types is a schema failure", () => {
    const run = () => readBundle(zipSync({ "manifest.json": encode({ hash_alg: "sha-256" }) }));
    expect(run).toThrow(/^schema:/);
  });
  test("inherited property names are not hash algorithms", () => {
    for (const name of ["constructor", "toString", "__proto__"])
      expect(isHashAlg(name)).toBe(false);
    expect(isHashAlg("sha-256")).toBe(true);
  });
  test("non-object documents are rejected", () => {
    expect(() => assertRecord(null)).toThrow(/not an object/);
    expect(() => assertDelegation([])).toThrow(/not an object/);
    expect(() => assertRecord({ seq: "1" })).toThrow(/schema/);
  });
});

describe("bundle limits", () => {
  test("entry size limit", () => {
    expect(() => readBundle(bomb(2_000_000), { maxEntryBytes: 1_000_000 })).toThrow(
      /entry exceeds/,
    );
  });
  test("total size limit names both sizes", () => {
    expect(() => readBundle(bomb(2_000_000), { maxTotalBytes: 1_000_000 })).toThrow(
      /uncompressed size limit \(2 MB claimed, limit 1 MB\)/,
    );
    expect(() =>
      readBundle(claimSize(bomb(10), "payloads/zeros", 1_190_000_000), {
        maxEntryBytes: 2_000_000_000,
        maxTotalBytes: 1_000_000_000,
      }),
    ).toThrow(/1\.19 GB claimed, limit 1 GB/);
  });
  test("manifest size limit", () => {
    const manifest = new Uint8Array(4 * 1024 * 1024 + 1).fill(32);
    expect(() => readBundle(zipSync({ "manifest.json": manifest }))).toThrow(/entry exceeds/);
  });
  test("malformed archive has a generic message", () => {
    const run = () => readBundle(zipSync({ "manifest.json": new Uint8Array([123, 110]) }));
    expect(run).toThrow(VerificationError);
    expect(run).toThrow(/malformed archive/);
    expect(() => readBundle(new Uint8Array([1, 2, 3]))).toThrow(/malformed archive/);
  });
});

describe("anchor receipts", () => {
  const anchor = (type: string, receipt: unknown) => ({
    "sealedrun.anchor": {
      type,
      anchored_hash: "a".repeat(64),
      anchored_seq: 3,
      receipt,
      witness: "https://w",
    },
  });
  const rfc3161 = {
    digest: "a".repeat(64),
    imprint_alg: "sha256",
    token: "MIIB",
    chain: [],
    nonce: "1",
  };
  const rekor = {
    digest: "a".repeat(64),
    log_url: "https://rekor.sigstore.dev",
    uuid: "1".repeat(80),
    log_index: 5,
    log_id: "b".repeat(64),
    body: "e30=",
    inclusion_proof: {
      log_index: 5,
      root_hash: "c".repeat(64),
      tree_size: 9,
      hashes: [],
      checkpoint: "x",
    },
    public_key: "-----BEGIN PUBLIC KEY-----",
    signature: "MEUC",
  };

  test("both receipt shapes pass", () => {
    expect(() => assertExtensions(anchor("rfc3161", rfc3161))).not.toThrow();
    expect(() => assertExtensions(anchor("rekor", rekor))).not.toThrow();
    expect(() => assertExtensions(anchor("other", { digest: "a".repeat(64) }))).not.toThrow();
  });

  test("missing members are schema failures", () => {
    const noToken = { ...rfc3161, token: undefined };
    expect(() => assertExtensions(anchor("rfc3161", noToken))).toThrow(VerificationError);
    expect(() => assertExtensions(anchor("rekor", { ...rekor, inclusion_proof: {} }))).toThrow(
      VerificationError,
    );
  });
});
