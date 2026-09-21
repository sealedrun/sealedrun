import type { Json } from "./canonical.js";
import type { Sealed } from "./signing.js";

/** What the agent acted on (SPEC 5.4). */
export interface Target {
  type: string;
  name: string;
  endpoint?: string;
  location?: "local" | "cloud" | "unknown";
  provider?: string;
}

/**
 * Digests and sizes of the request and response bodies (SPEC 5.5).
 *
 * @remarks
 * Hashes are base64url, computed with the run's `hash_alg` over the exact bytes sent or received.
 * `storage` tells where the bodies are: `inline`, `bundle`, `external`, `deleted` or `none`.
 */
export interface Payload {
  storage: string;
  request_hash?: string;
  request_size?: number;
  response_hash?: string;
  response_size?: number;
}

/** One signed step of a run (SPEC 5.1). `prev_hash` is the `hash` of the record before it. */
export type SealedRunRecord = Sealed & {
  spec_version: string;
  record_id: string;
  run_id: string;
  seq: number;
  occurred_at: string;
  principal_id: string;
  agent_id: string;
  kind: string;
  actor: { type: string; id: string };
  target: Target;
  payload?: Payload;
  data_labels: string[];
  policy?: { rule_id: string; decision: string; reason: string };
  outcome: string;
  parent_record_id?: string;
  extensions?: { [key: string]: { [key: string]: Json } };
  prev_hash: string;
};

/**
 * A Principal's signed statement that an Agent key set may record on its behalf within a time
 * window (SPEC 6). Both ids are the key identifiers of the matching key sets.
 */
export type Delegation = Sealed & {
  delegation_id: string;
  principal_id: string;
  principal_keys: Record<string, string>;
  agent_id: string;
  agent_keys: Record<string, string>;
  not_before: string;
  not_after: string;
};

/**
 * The signed table of contents of a bundle (SPEC 13.1).
 *
 * @remarks
 * `files` maps every archive path except `manifest.json` to its base64url digest. In a run entry,
 * `first_hash` is the `prev_hash` of the first included record, so a slice can be joined to an
 * earlier bundle.
 */
export type Manifest = Sealed & {
  bundle_id: string;
  created_at: string;
  exporter: { agent_id: string; software: string };
  principal_id: string;
  delegations: string[];
  runs: {
    run_id: string;
    hash_alg: string;
    record_count: number;
    first_seq: number;
    first_hash: string;
    last_hash: string;
    complete: boolean;
  }[];
  files: Record<string, string>;
  principal_signatures?: Record<string, string>;
};
