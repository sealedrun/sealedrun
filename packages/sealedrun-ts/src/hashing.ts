import { sha256, sha384 } from "@noble/hashes/sha2.js";

import { canonicalBytes, type Json } from "./canonical.js";
import { b64urlEncode, hexEncode } from "./encoding.js";

export type HashAlg = "sha-256" | "sha-384";

const SIZES: Record<HashAlg, number> = { "sha-256": 32, "sha-384": 48 };

export function isHashAlg(value: string): value is HashAlg {
  return value in SIZES;
}

export function digest(alg: HashAlg, data: Uint8Array): Uint8Array {
  return alg === "sha-256" ? sha256(data) : sha384(data);
}

export function digestSize(alg: HashAlg): number {
  return SIZES[alg];
}

export function zeroHash(alg: HashAlg): string {
  return "0".repeat(SIZES[alg] * 2);
}

export function objectHash(alg: HashAlg, protectedObject: Json): string {
  return hexEncode(digest(alg, canonicalBytes(protectedObject)));
}

export function payloadDigest(alg: HashAlg, body: Uint8Array): string {
  return b64urlEncode(digest(alg, body));
}
