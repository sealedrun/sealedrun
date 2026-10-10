/** Version of this package, not of the specification. */
export const VERSION = "0.5.0";

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
export {
  Recorder,
  RecorderError,
  type RecorderOptions,
  type RecordOptions,
  type Step,
  type StepOptions,
} from "./client.js";
export { assertDelegation, assertExtensions, assertManifest, assertRecord } from "./structure.js";
export type { SealedRunRecord, Delegation, Manifest, Payload, Target } from "./types.js";
export {
  type RunReport,
  verifyRun,
  verifyReceipt,
  verifyRunAsync,
  type VerifyRunOptions,
  verifyWitnesses,
  type WitnessOptions,
} from "./verify.js";
export { type Rfc3161Receipt, verifyRfc3161 } from "./anchors/rfc3161.js";
export { type RekorReceipt, verifyRekor } from "./anchors/rekor.js";
export {
  parseInstant,
  selectWitnesses,
  shippedWitnesses,
  type Witness,
  witnessCovers,
  witnessFromJson,
  type WitnessJson,
} from "./trust.js";
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
  verifyBundleAsync,
} from "./bundle.js";
