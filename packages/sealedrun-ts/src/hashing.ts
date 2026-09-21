import { sha256, sha384 } from "@noble/hashes/sha2.js";

import { canonicalBytes, type Json } from "./canonical.js";
import { b64urlEncode, hexEncode } from "./encoding.js";

/** Hash algorithms registered in SPEC 4.1. */
export type HashAlg = "sha-256" | "sha-384";

const SIZES: Record<HashAlg, number> = { "sha-256": 32, "sha-384": 48 };

/** Narrows an untrusted `hash_alg` string to a supported algorithm. */
export function isHashAlg(value: string): value is HashAlg {
  return Object.hasOwn(SIZES, value);
}

/** Raw digest of the data. */
export function digest(alg: HashAlg, data: Uint8Array): Uint8Array {
  return alg === "sha-256" ? sha256(data) : sha384(data);
}

/** Digest length in bytes. */
export function digestSize(alg: HashAlg): number {
  return SIZES[alg];
}

/** The all-zero hex string used as `prev_hash` of the record with seq 0 (SPEC 5.3). */
export function zeroHash(alg: HashAlg): string {
  return "0".repeat(SIZES[alg] * 2);
}

/**
 * Hex digest of the canonical form of the protected part of an object (SPEC 5.3).
 *
 * @throws TypeError if the object contains a non-finite number.
 */
export function objectHash(alg: HashAlg, protectedObject: Json): string {
  return hexEncode(digest(alg, canonicalBytes(protectedObject)));
}

/** Base64url digest of a payload body or bundle file, as stored in `payload` and `files`. */
export function payloadDigest(alg: HashAlg, body: Uint8Array): string {
  return b64urlEncode(digest(alg, body));
}
