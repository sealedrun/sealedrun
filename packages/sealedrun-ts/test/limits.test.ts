import { zipSync } from "fflate";
import { describe, expect, test } from "vitest";

import { assertDelegation, assertRecord, readBundle, VerificationError } from "../src/index.js";
import { isHashAlg } from "../src/hashing.js";

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
  test("total size limit", () => {
    expect(() => readBundle(bomb(2_000_000), { maxTotalBytes: 1_000_000 })).toThrow(
      /uncompressed size/,
    );
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
