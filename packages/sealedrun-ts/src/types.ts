import type { Json } from "./canonical.js";
import type { Sealed } from "./signing.js";

export interface Target {
  type: string;
  name: string;
  endpoint?: string;
  location?: "local" | "cloud" | "unknown";
  provider?: string;
}

export interface Payload {
  storage: string;
  request_hash?: string;
  request_size?: number;
  response_hash?: string;
  response_size?: number;
}

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

export type Delegation = Sealed & {
  delegation_id: string;
  principal_id: string;
  principal_keys: Record<string, string>;
  agent_id: string;
  agent_keys: Record<string, string>;
  not_before: string;
  not_after: string;
};

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
