import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";

import { canonicalBytes } from "./canonical.js";
import { b64urlDecode, b64urlEncode } from "./encoding.js";

/** Signature algorithms registered in SPEC 4.2. */
export type SigAlg = "ed25519" | "ml-dsa-65" | "es256" | "ml-dsa-87";

/** Registered hybrid profiles: one classical and one post-quantum algorithm each (SPEC 4.2). */
export const PROFILES: Record<string, readonly [SigAlg, SigAlg]> = {
  "sealedrun-hybrid-1": ["ed25519", "ml-dsa-65"],
  "aat-compat-1": ["es256", "ml-dsa-65"],
  "sealedrun-hybrid-2": ["ed25519", "ml-dsa-87"],
};

/** Maps each signature algorithm of a key set to its base64url public key (SPEC 4.3). */
export type KeySetJson = Record<string, string>;
/** Maps each signature algorithm of the signer's key set to a base64url signature (SPEC 4.4). */
export type SignaturesJson = Record<string, string>;

/**
 * Finds the registered profile made of exactly these algorithms, in any order.
 *
 * @returns The profile name, or `undefined` when the set is not a registered pair.
 */
export function profileOf(algs: string[]): string | undefined {
  const sorted = [...algs].sort().join(",");
  return Object.entries(PROFILES).find(([, pair]) => [...pair].sort().join(",") === sorted)?.[0];
}

/** Key identifier of a key set: base64url SHA-256 of its canonical form (SPEC 4.3). */
export function kidOf(keys: KeySetJson): string {
  return b64urlEncode(sha256(canonicalBytes(keys)));
}

/**
 * Tells whether the bytes are the canonical encoding of a point of prime order (SPEC 4.2).
 *
 * @remarks
 * noble verifies with the cofactored equation, which agrees with a cofactorless verifier only
 * when both A and R are in this set.
 *
 * @throws Error if the bytes do not decode to a curve point.
 */
function isPrimeOrder(encoded: Uint8Array): boolean {
  const point = ed25519.Point.fromBytes(encoded, false);
  return point.isTorsionFree() && !point.isSmallOrder();
}

/**
 * Verifies one signature with one algorithm.
 *
 * @remarks
 * Ed25519 is verified strictly: non-canonical encodings are refused, and both the public key and R
 * must be of prime order. ES256 expects a 64-byte `r || s` signature with low S over the SHA-256 of
 * the message.
 *
 * @returns `false` for a bad signature, an unknown algorithm or malformed input. Never throws.
 */
export function verifyOne(
  alg: string,
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    switch (alg) {
      case "ed25519":
        return (
          isPrimeOrder(publicKey) &&
          isPrimeOrder(signature.subarray(0, 32)) &&
          ed25519.verify(signature, message, publicKey, { zip215: false })
        );
      case "es256":
        return p256.verify(signature, message, publicKey, {
          prehash: true,
          format: "compact",
          lowS: true,
        });
      case "ml-dsa-65":
        return ml_dsa65.verify(signature, message, publicKey);
      case "ml-dsa-87":
        return ml_dsa87.verify(signature, message, publicKey);
      default:
        return false;
    }
  } catch {
    return false;
  }
}

/**
 * Verifies a hybrid signature: every algorithm of the key set must have a valid signature.
 *
 * @remarks
 * Returns `false` when the key set is not a registered profile or when `signatures` has a missing
 * or an extra algorithm, so dropping the post-quantum half cannot downgrade a signature.
 */
export function verifyKeySet(
  keys: KeySetJson,
  message: Uint8Array,
  signatures: SignaturesJson,
): boolean {
  const algs = Object.keys(keys);
  if (!profileOf(algs)) return false;
  const sigAlgs = Object.keys(signatures);
  if (sigAlgs.length !== algs.length || !algs.every((a) => a in signatures)) return false;
  return algs.every((alg) => {
    const key = keys[alg];
    const signature = signatures[alg];
    if (key === undefined || signature === undefined) return false;
    return verifyOne(alg, b64urlDecode(key), message, b64urlDecode(signature));
  });
}

/**
 * Derives the public key for a 32-byte seed, as the test vectors do (SPEC 14).
 *
 * @remarks
 * ES256 has no seed-based key generation, so the private scalar is
 * `SHA-256("sealedrun/es256/seed" || seed) mod (n - 1) + 1` and the key is returned uncompressed.
 */
export function publicKeyFromSeed(alg: SigAlg, seed: Uint8Array): Uint8Array {
  switch (alg) {
    case "ed25519":
      return ed25519.getPublicKey(seed);
    case "ml-dsa-65":
      return ml_dsa65.keygen(seed).publicKey;
    case "ml-dsa-87":
      return ml_dsa87.keygen(seed).publicKey;
    case "es256": {
      const domain = new TextEncoder().encode("sealedrun/es256/seed");
      const material = new Uint8Array(domain.length + seed.length);
      material.set(domain);
      material.set(seed, domain.length);
      const n = p256.Point.CURVE().n;
      const scalar = (bytesToBigInt(sha256(material)) % (n - 1n)) + 1n;
      return p256.getPublicKey(bigIntToBytes(scalar, 32), false);
    }
  }
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const b of bytes) value = (value << 8n) | BigInt(b);
  return value;
}

function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}
