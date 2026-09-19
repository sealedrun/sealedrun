import { ed25519 } from "@noble/curves/ed25519.js";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { ml_dsa65, ml_dsa87 } from "@noble/post-quantum/ml-dsa.js";

import { canonicalBytes } from "./canonical.js";
import { b64urlDecode, b64urlEncode } from "./encoding.js";

export type SigAlg = "ed25519" | "ml-dsa-65" | "es256" | "ml-dsa-87";

export const PROFILES: Record<string, readonly [SigAlg, SigAlg]> = {
  "sealedrun-hybrid-1": ["ed25519", "ml-dsa-65"],
  "aat-compat-1": ["es256", "ml-dsa-65"],
  "sealedrun-hybrid-2": ["ed25519", "ml-dsa-87"],
};

export type KeySetJson = Record<string, string>;
export type SignaturesJson = Record<string, string>;

export function profileOf(algs: string[]): string | undefined {
  const sorted = [...algs].sort().join(",");
  return Object.entries(PROFILES).find(([, pair]) => [...pair].sort().join(",") === sorted)?.[0];
}

export function kidOf(keys: KeySetJson): string {
  return b64urlEncode(sha256(canonicalBytes(keys)));
}

export function verifyOne(
  alg: string,
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    switch (alg) {
      case "ed25519":
        return ed25519.verify(signature, message, publicKey);
      case "es256":
        return p256.verify(signature, message, publicKey, { prehash: true, format: "compact" });
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
