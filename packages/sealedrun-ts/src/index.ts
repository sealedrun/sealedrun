/** Version of this package, not of the specification. */
export const VERSION = "0.2.0";

export { canonicalize, canonicalBytes, type Json } from "./canonical.js";
export { b64urlDecode, b64urlEncode, hexDecode, hexEncode } from "./encoding.js";
export { digest, type HashAlg, objectHash, payloadDigest, zeroHash } from "./hashing.js";
export {
  type KeySetJson,
  kidOf,
  PROFILES,
  profileOf,
  publicKeyFromSeed,
  type SigAlg,
  verifyKeySet,
  verifyOne,
} from "./keys.js";
export {
  checkHash,
  checkSignatures,
  DOMAIN_DELEGATION,
  DOMAIN_MANIFEST,
  DOMAIN_RECORD,
  protectedPart,
  signingInput,
} from "./signing.js";
export { covers, verifyDelegation } from "./delegation.js";
export { VerificationError } from "./errors.js";
export { assertDelegation, assertManifest, assertRecord } from "./structure.js";
export type { SealedRunRecord, Delegation, Manifest, Payload, Target } from "./types.js";
export { type RunReport, verifyRun, type VerifyRunOptions } from "./verify.js";
export {
  type Bundle,
  type BundleLimits,
  type BundleReport,
  type VerifyBundleOptions,
  MAX_ENTRIES,
  MAX_ENTRY_BYTES,
  MAX_TOTAL_BYTES,
  readBundle,
  verifyBundle,
} from "./bundle.js";
