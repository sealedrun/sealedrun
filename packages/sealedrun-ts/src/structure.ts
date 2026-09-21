import { VerificationError } from "./errors.js";
import type { Delegation, Manifest, SealedRunRecord } from "./types.js";

type Kind = "string" | "integer" | "boolean" | "object" | "strings" | "stringMap";
type Shape = Record<string, Kind>;

const SEALED: Shape = {
  spec_version: "string",
  hash_alg: "string",
  hash: "string",
  signatures: "stringMap",
};

const RECORD: Shape = {
  ...SEALED,
  record_id: "string",
  run_id: "string",
  seq: "integer",
  occurred_at: "string",
  principal_id: "string",
  agent_id: "string",
  kind: "string",
  actor: "object",
  target: "object",
  data_labels: "strings",
  outcome: "string",
  prev_hash: "string",
};

const DELEGATION: Shape = {
  ...SEALED,
  delegation_id: "string",
  principal_id: "string",
  principal_keys: "stringMap",
  agent_id: "string",
  agent_keys: "stringMap",
  not_before: "string",
  not_after: "string",
};

const MANIFEST: Shape = {
  ...SEALED,
  bundle_id: "string",
  created_at: "string",
  exporter: "object",
  principal_id: "string",
  delegations: "strings",
  files: "stringMap",
};

const RUN_ENTRY: Shape = {
  run_id: "string",
  hash_alg: "string",
  record_count: "integer",
  first_seq: "integer",
  first_hash: "string",
  last_hash: "string",
  complete: "boolean",
};

/**
 * Required shape of each `sealedrun.*` extension registered in SPEC 9, mirroring
 * spec/schema/extensions/sealedrun.json. Unregistered keys are not constrained, as in Python.
 */
const EXTENSIONS: Record<string, Shape> = {
  "sealedrun.delegation": { delegation_id: "string", hash: "string" },
  "sealedrun.tombstone": { record_id: "string", fields: "strings", reason: "string" },
  "sealedrun.anchor": {
    type: "string",
    anchored_hash: "string",
    anchored_seq: "integer",
    receipt: "object",
    witness: "string",
  },
  "sealedrun.llm": { model: "string" },
  "sealedrun.mcp": { server: "string", transport: "string", method: "string" },
  "sealedrun.otel": { trace_id: "string", span_id: "string" },
  "sealedrun.imported": { source_format: "string" },
};

const EXTENSION_ENUMS: Record<string, Record<string, readonly string[]>> = {
  "sealedrun.anchor": { type: ["rekor", "rfc3161", "scitt", "other"] },
  "sealedrun.mcp": { transport: ["stdio", "http"] },
  "sealedrun.imported": { source_format: ["otel", "aat", "sep-3004", "other"] },
};

/** Array bounds from the JSON Schemas (`maxItems`), keyed by field name. */
const MAX_ITEMS: Record<string, number> = {
  data_labels: 64,
  delegations: 1024,
  runs: 1024,
  fields: 2,
};

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function matches(value: unknown, kind: Kind): boolean {
  switch (kind) {
    case "string":
      return typeof value === "string";
    case "integer":
      return Number.isSafeInteger(value) && (value as number) >= 0;
    case "boolean":
      return typeof value === "boolean";
    case "object":
      return isObject(value);
    case "strings":
      return Array.isArray(value) && value.every((v) => typeof v === "string");
    case "stringMap":
      return isObject(value) && Object.values(value).every((v) => typeof v === "string");
  }
}

function checkLength(value: unknown, field: string, what: string): void {
  const max = MAX_ITEMS[field];
  if (max !== undefined && Array.isArray(value) && value.length > max) {
    throw new VerificationError("schema", `${what}: field ${field} has more than ${max} items`);
  }
}

function check(value: unknown, shape: Shape, what: string): void {
  if (!isObject(value)) throw new VerificationError("schema", `${what} is not an object`);
  for (const [field, kind] of Object.entries(shape)) {
    if (!matches(value[field], kind)) {
      throw new VerificationError("schema", `${what}: field ${field} is missing or not ${kind}`);
    }
    checkLength(value[field], field, what);
  }
}

/**
 * Checks the required fields and types of a Record, its nested objects and registered extensions.
 *
 * @remarks
 * This is the structural subset of the JSON Schema that the verifier relies on. Of the optional
 * fields only `payload.storage` and the registered extensions are checked.
 *
 * @throws VerificationError with check `schema`.
 */
export function assertRecord(value: unknown): asserts value is SealedRunRecord {
  check(value, RECORD, "record");
  const record = value as Record<string, unknown>;
  check(record.actor, { type: "string", id: "string" }, "record.actor");
  check(record.target, { type: "string", name: "string" }, "record.target");
  if (record.payload !== undefined) check(record.payload, { storage: "string" }, "record.payload");
  if (record.extensions !== undefined) assertExtensions(record.extensions);
}

/**
 * Checks each registered `sealedrun.*` extension that is present, including its enum values.
 *
 * @throws VerificationError with check `schema`.
 */
export function assertExtensions(value: unknown): void {
  if (!isObject(value)) throw new VerificationError("schema", "record.extensions is not an object");
  for (const [key, shape] of Object.entries(EXTENSIONS)) {
    const ext = value[key];
    if (ext === undefined) continue;
    check(ext, shape, `extensions/${key}`);
    if (key === "sealedrun.anchor") {
      check(
        (ext as Record<string, unknown>).receipt,
        { digest: "string" },
        `extensions/${key}/receipt`,
      );
    }
    for (const [field, allowed] of Object.entries(EXTENSION_ENUMS[key] ?? {})) {
      const actual = (ext as Record<string, unknown>)[field];
      if (!allowed.includes(actual as string)) {
        throw new VerificationError(
          "schema",
          `extensions/${key}: field ${field} is not one of ${allowed.join(", ")}`,
        );
      }
    }
  }
}

/**
 * Checks the required fields and types of a Delegation.
 *
 * @throws VerificationError with check `schema`.
 */
export function assertDelegation(value: unknown): asserts value is Delegation {
  check(value, DELEGATION, "delegation");
}

/**
 * Checks the required fields, types and array bounds of a Manifest, including every run entry.
 *
 * @throws VerificationError with check `schema`.
 */
export function assertManifest(value: unknown): asserts value is Manifest {
  check(value, MANIFEST, "manifest");
  const manifest = value as Record<string, unknown>;
  check(manifest.exporter, { agent_id: "string", software: "string" }, "manifest.exporter");
  if (!Array.isArray(manifest.runs)) {
    throw new VerificationError("schema", "manifest: field runs is missing or not an array");
  }
  checkLength(manifest.runs, "runs", "manifest");
  for (const entry of manifest.runs) check(entry, RUN_ENTRY, "manifest.runs entry");
  if (manifest.principal_signatures !== undefined) {
    check(manifest, { principal_signatures: "stringMap" }, "manifest");
  }
}
