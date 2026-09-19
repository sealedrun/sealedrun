import { kidOf, profileOf } from "./keys.js";
import { checkHash, checkSignatures, DOMAIN_DELEGATION } from "./signing.js";
import { parseTimestamp } from "./time.js";
import type { Delegation } from "./types.js";

export function verifyDelegation(doc: Delegation): string | null {
  if (!profileOf(Object.keys(doc.principal_keys)) || !profileOf(Object.keys(doc.agent_keys))) {
    return "key set does not match a registered profile";
  }
  if (kidOf(doc.agent_keys) !== doc.agent_id) return "agent_id does not match agent_keys";
  if (!doc.principal_id.startsWith("did:") && kidOf(doc.principal_keys) !== doc.principal_id) {
    return "principal_id does not match principal_keys";
  }
  if (parseTimestamp(doc.not_before) >= parseTimestamp(doc.not_after)) {
    return "not_before is not earlier than not_after";
  }
  if (!checkHash(doc)) return "hash mismatch";
  if (!checkSignatures(doc, DOMAIN_DELEGATION, doc.principal_keys)) {
    return "principal signature invalid";
  }
  return null;
}

export function covers(doc: Delegation, at: number): boolean {
  return parseTimestamp(doc.not_before) <= at && at <= parseTimestamp(doc.not_after);
}
