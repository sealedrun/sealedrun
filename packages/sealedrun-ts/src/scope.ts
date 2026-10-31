import type { SealedRunRecord } from "./types.js";

/** Record kinds exempt from the target, location and label checks (SPEC 6.5). */
const STRUCTURAL_KINDS = new Set(["run_start", "run_end", "anchor", "tombstone"]);
const TARGET_FIELDS = new Set(["type", "name", "provider", "location"]);
const DATA_TARGET_TYPES = new Set(["model", "tool", "memory"]);

/**
 * One record that a verified run reports as outside its delegation's scope (SPEC 6.5).
 *
 * @remarks
 * A finding does not break integrity: the record is genuine and signed. It says the agent acted
 * where the Principal did not allow it to.
 */
export interface Finding {
  /** `scope.target`, `scope.location`, `scope.label` or `scope.max_records`. */
  check: string;
  seq: number;
  recordId: string;
  reason: string;
}

/** Parsed structured part of `Delegation.scope`; other keys are ignored. */
export interface Scope {
  allowedTargets?: Record<string, string>[];
  allowedLocations?: Set<string>;
  deniedLabels: Set<string>;
  maxRecords?: number;
}

/**
 * Reads the structured keys of a scope object.
 *
 * @throws Error naming the key whose shape is wrong.
 */
export function parseScope(scope: unknown): Scope {
  const out: Scope = { deniedLabels: new Set() };
  if (scope === undefined || scope === null) return out;
  if (typeof scope !== "object" || Array.isArray(scope)) throw new Error("scope is not an object");
  const obj = scope as Record<string, unknown>;
  if (obj.allowed_targets !== undefined) {
    if (!Array.isArray(obj.allowed_targets))
      throw new Error("scope.allowed_targets is not an array");
    out.allowedTargets = obj.allowed_targets.map((item) => {
      if (typeof item !== "object" || item === null || Array.isArray(item)) {
        throw new Error("scope.allowed_targets item is not a non-empty object");
      }
      const entries = Object.entries(item as Record<string, unknown>);
      if (entries.length === 0)
        throw new Error("scope.allowed_targets item is not a non-empty object");
      for (const [key, value] of entries) {
        if (!TARGET_FIELDS.has(key) || typeof value !== "string") {
          throw new Error(`scope.allowed_targets item has bad field ${key}`);
        }
      }
      return item as Record<string, string>;
    });
  }
  const locations = stringList(obj, "allowed_locations");
  if (locations) out.allowedLocations = new Set(locations);
  out.deniedLabels = new Set(stringList(obj, "denied_labels") ?? []);
  if (obj.max_records !== undefined) {
    if (!Number.isInteger(obj.max_records) || (obj.max_records as number) < 1) {
      throw new Error("scope.max_records is not a positive integer");
    }
    out.maxRecords = obj.max_records as number;
  }
  return out;
}

function stringList(obj: Record<string, unknown>, key: string): string[] | undefined {
  const value = obj[key];
  if (value === undefined) return undefined;
  if (!Array.isArray(value) || !value.every((v) => typeof v === "string")) {
    throw new Error(`scope.${key} is not an array of strings`);
  }
  return value as string[];
}

/**
 * Matches `value` against `pattern`, where `*` stands for any run of characters and every other
 * character matches itself (SPEC 6.5).
 */
export function globMatch(pattern: string, value: string): boolean {
  const parts = pattern.split("*");
  if (parts.length === 1) return pattern === value;
  let position = 0;
  for (const [index, part] of parts.entries()) {
    if (index === 0) {
      if (!value.startsWith(part)) return false;
      position = part.length;
    } else if (index === parts.length - 1) {
      return value.length - position >= part.length && value.endsWith(part);
    } else {
      const found = value.indexOf(part, position);
      if (found < 0) return false;
      position = found + part.length;
    }
  }
  return true;
}

function targetMatches(pattern: Record<string, string>, target: Record<string, unknown>): boolean {
  for (const [field, expected] of Object.entries(pattern)) {
    const actual = target[field];
    if (typeof actual !== "string") return false;
    if (field === "name" ? !globMatch(expected, actual) : actual !== expected) return false;
  }
  return true;
}

/** Returns the scope findings of one record, given how many records the run has so far. */
export function scopeFindings(
  scope: Scope,
  record: SealedRunRecord,
  recordCount: number,
): Finding[] {
  const out: Finding[] = [];
  const { seq, record_id: recordId } = record;
  if (scope.maxRecords !== undefined && recordCount === scope.maxRecords + 1) {
    out.push({
      check: "scope.max_records",
      seq,
      recordId,
      reason: `run exceeds ${scope.maxRecords} records`,
    });
  }
  if (STRUCTURAL_KINDS.has(record.kind)) return out;
  const target = record.target as unknown as Record<string, unknown>;
  if (scope.allowedTargets && !scope.allowedTargets.some((p) => targetMatches(p, target))) {
    out.push({
      check: "scope.target",
      seq,
      recordId,
      reason: `target ${record.target.name} is not in allowed_targets`,
    });
  }
  const location = record.target.location ?? "unknown";
  if (
    scope.allowedLocations &&
    DATA_TARGET_TYPES.has(record.target.type) &&
    !scope.allowedLocations.has(location)
  ) {
    out.push({
      check: "scope.location",
      seq,
      recordId,
      reason: `location ${location} is not in allowed_locations`,
    });
  }
  const denied = record.data_labels.filter((label) => scope.deniedLabels.has(label)).sort();
  if (denied.length > 0) {
    out.push({
      check: "scope.label",
      seq,
      recordId,
      reason: `labels ${denied.join(", ")} are denied`,
    });
  }
  return out;
}

/** Returns why `child` is not within `parent` (SPEC 6.4), or undefined when it is. */
export function scopeWithin(child: Scope, parent: Scope): string | undefined {
  if (parent.allowedTargets) {
    if (!child.allowedTargets) return "child scope lacks allowed_targets";
    for (const pattern of child.allowedTargets) {
      if (!parent.allowedTargets.some((wide) => covers(wide, pattern))) {
        return `child allows target ${JSON.stringify(pattern)} outside the parent's`;
      }
    }
  }
  if (parent.allowedLocations) {
    if (!child.allowedLocations) return "child scope lacks allowed_locations";
    const allowed = parent.allowedLocations;
    const extra = [...child.allowedLocations].filter((l) => !allowed.has(l)).sort();
    if (extra.length > 0) return `child allows locations ${extra.join(", ")} outside the parent's`;
  }
  const missing = [...parent.deniedLabels].filter((l) => !child.deniedLabels.has(l)).sort();
  if (missing.length > 0) return `child does not deny labels ${missing.join(", ")}`;
  if (
    parent.maxRecords !== undefined &&
    (child.maxRecords === undefined || child.maxRecords > parent.maxRecords)
  ) {
    return "child max_records exceeds the parent's";
  }
  return undefined;
}

function covers(wide: Record<string, string>, narrow: Record<string, string>): boolean {
  for (const [field, expected] of Object.entries(wide)) {
    const actual = narrow[field];
    if (actual === undefined) return false;
    if (
      field === "name" ? actual !== expected && !globMatch(expected, actual) : actual !== expected
    ) {
      return false;
    }
  }
  return true;
}
