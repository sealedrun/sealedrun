import type { Json } from "./canonical.js";
import { concat, hexDecode } from "./encoding.js";
import { type HashAlg, isHashAlg, objectHash } from "./hashing.js";
import { type KeySetJson, type SignaturesJson, verifyKeySet } from "./keys.js";

/** Signing domains, one per object type (SPEC 4.4). */
export const DOMAIN_RECORD = "sealedrun/record/v1";
export const DOMAIN_DELEGATION = "sealedrun/delegation/v1";
export const DOMAIN_MANIFEST = "sealedrun/manifest/v1";

const UNPROTECTED = new Set(["hash", "signatures", "principal_signatures"]);

/**
 * Fields shared by every hashed and signed object. `hash` is lowercase hex of the protected part
 * under `hash_alg`.
 */
export type Sealed = { [key: string]: Json } & {
  hash_alg: string;
  hash: string;
  signatures: SignaturesJson;
};

/**
 * Builds the bytes that are signed: `domain || 0x00 || hash_bytes` (SPEC 4.4).
 *
 * @remarks
 * The domain keeps a signature on one object type from being replayed as another.
 *
 * @throws TypeError if `hashHex` is not lowercase hex.
 */
export function signingInput(domain: string, hashHex: string): Uint8Array {
  return concat(new TextEncoder().encode(domain), new Uint8Array([0]), hexDecode(hashHex));
}

/**
 * Copy of the object without `hash`, `signatures` and `principal_signatures`, the fields the hash does not cover.
 */
export function protectedPart(obj: { [key: string]: Json }): { [key: string]: Json } {
  return Object.fromEntries(Object.entries(obj).filter(([k]) => !UNPROTECTED.has(k)));
}

/** Recomputes the hash of the protected part. An unsupported `hash_alg` gives `false`. */
export function checkHash(obj: Sealed): boolean {
  if (!isHashAlg(obj.hash_alg)) return false;
  return objectHash(obj.hash_alg as HashAlg, protectedPart(obj)) === obj.hash;
}

/**
 * Verifies the signatures of an object against a key set over its stored `hash`.
 *
 * @remarks
 * The hash itself is not recomputed here. Call {@link checkHash} first.
 *
 * @param domain - One of the `DOMAIN_*` constants, matching the object type.
 * @param field - `principal_signatures` for the optional Principal countersignature of a manifest
 * (SPEC 8.3).
 */
export function checkSignatures(
  obj: Sealed,
  domain: string,
  keys: KeySetJson,
  field: "signatures" | "principal_signatures" = "signatures",
): boolean {
  const sigs = obj[field];
  if (!sigs || typeof sigs !== "object" || Array.isArray(sigs)) return false;
  return verifyKeySet(keys, signingInput(domain, obj.hash), sigs as SignaturesJson);
}
