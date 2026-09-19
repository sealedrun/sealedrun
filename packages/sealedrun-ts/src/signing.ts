import type { Json } from "./canonical.js";
import { concat, hexDecode } from "./encoding.js";
import { type HashAlg, isHashAlg, objectHash } from "./hashing.js";
import { type KeySetJson, type SignaturesJson, verifyKeySet } from "./keys.js";

export const DOMAIN_RECORD = "sealedrun/record/v1";
export const DOMAIN_DELEGATION = "sealedrun/delegation/v1";
export const DOMAIN_MANIFEST = "sealedrun/manifest/v1";

const UNPROTECTED = new Set(["hash", "signatures", "principal_signatures"]);

export type Sealed = { [key: string]: Json } & {
  hash_alg: string;
  hash: string;
  signatures: SignaturesJson;
};

export function signingInput(domain: string, hashHex: string): Uint8Array {
  return concat(new TextEncoder().encode(domain), new Uint8Array([0]), hexDecode(hashHex));
}

export function protectedPart(obj: { [key: string]: Json }): { [key: string]: Json } {
  return Object.fromEntries(Object.entries(obj).filter(([k]) => !UNPROTECTED.has(k)));
}

export function checkHash(obj: Sealed): boolean {
  if (!isHashAlg(obj.hash_alg)) return false;
  return objectHash(obj.hash_alg as HashAlg, protectedPart(obj)) === obj.hash;
}

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
