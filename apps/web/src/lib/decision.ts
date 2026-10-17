import type { SealedRunRecord } from "@sealedrun/core";

/** One normalised answer of `sealedrun.decision` (SPEC 10.7), as far as the record carries it. */
export interface DecisionAnswer {
  name: string;
  type: string;
  value?: number | string;
  confidence?: number;
  probabilities?: Record<string, number>;
  refused: boolean;
}

/** The gate an application reported on a decision (SPEC 10.8). */
export interface GateView {
  seq: number;
  recordId: string;
  outcome: string;
  thresholds: Record<string, number>;
  reason?: string;
}

const GATE_OUTCOMES = new Set(["approve", "block", "review"]);

function isNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

/** The answers of a decision call, or null when the record carries none. */
export function decisionAnswers(record: SealedRunRecord): DecisionAnswer[] | null {
  const raw = record.extensions?.["sealedrun.decision"]?.answers;
  if (!Array.isArray(raw)) return null;
  const answers: DecisionAnswer[] = [];
  for (const item of raw) {
    if (typeof item !== "object" || item === null || Array.isArray(item)) continue;
    const entry = item as Record<string, unknown>;
    if (typeof entry.name !== "string" || typeof entry.type !== "string") continue;
    const answer: DecisionAnswer = {
      name: entry.name,
      type: entry.type,
      refused: entry.refused === true,
    };
    if (isNumber(entry.value) || typeof entry.value === "string") answer.value = entry.value;
    if (isNumber(entry.confidence)) answer.confidence = entry.confidence;
    if (typeof entry.probabilities === "object" && entry.probabilities !== null) {
      const probabilities: Record<string, number> = {};
      for (const [label, p] of Object.entries(entry.probabilities as Record<string, unknown>)) {
        if (isNumber(p)) probabilities[label] = p;
      }
      if (Object.keys(probabilities).length > 0) answer.probabilities = probabilities;
    }
    answers.push(answer);
  }
  return answers.length > 0 ? answers : null;
}

/** The gate step of `record`, or null when none in `records` reports one for it. */
export function gateOf(
  record: SealedRunRecord,
  records: readonly SealedRunRecord[],
): GateView | null {
  for (const step of records) {
    if (step.parent_record_id !== record.record_id) continue;
    const gate = step.extensions?.["sealedrun.gate"];
    if (!gate || typeof gate.outcome !== "string" || !GATE_OUTCOMES.has(gate.outcome)) continue;
    const thresholds: Record<string, number> = {};
    if (typeof gate.thresholds === "object" && gate.thresholds !== null) {
      for (const [name, value] of Object.entries(gate.thresholds as Record<string, unknown>)) {
        if (isNumber(value)) thresholds[name] = value;
      }
    }
    const view: GateView = {
      seq: step.seq,
      recordId: step.record_id,
      outcome: gate.outcome,
      thresholds,
    };
    if (typeof gate.reason === "string" && gate.reason) view.reason = gate.reason;
    return view;
  }
  return null;
}

/** The gate outcome a gate step itself reports (`sealedrun.gate.outcome`), or null. */
export function gateOutcome(record: SealedRunRecord): string | null {
  const outcome = record.extensions?.["sealedrun.gate"]?.outcome;
  return typeof outcome === "string" && GATE_OUTCOMES.has(outcome) ? outcome : null;
}

/** Whether the record is a decision call (SPEC 10.7) or a gate on one (SPEC 10.8). */
export function isDecisionStep(record: SealedRunRecord): boolean {
  return decisionAnswers(record) !== null || gateOutcome(record) !== null;
}

/**
 * Bars for one answer: a predicate shows yes against its probability, a choice or score each
 * label against its probability (the chosen one marked), a refusal nothing.
 */
export function answerBars(
  answer: DecisionAnswer,
): { label: string; share: number; chosen: boolean }[] {
  if (answer.refused) return [];
  if (answer.type === "predicate" && isNumber(answer.value)) {
    return [{ label: "yes", share: answer.value, chosen: answer.value >= 0.5 }];
  }
  if (answer.probabilities) {
    const chosen = answer.value === undefined ? undefined : String(answer.value);
    return Object.entries(answer.probabilities).map(([label, share]) => ({
      label,
      share,
      chosen: chosen !== undefined && (label === chosen || isNearestLevel(answer, label)),
    }));
  }
  return [];
}

function isNearestLevel(answer: DecisionAnswer, label: string): boolean {
  if (answer.type !== "score" || !isNumber(answer.value) || !answer.probabilities) return false;
  const labels = Object.keys(answer.probabilities);
  const index = Math.min(labels.length - 1, Math.max(0, Math.round(answer.value)));
  return labels[index] === label;
}

/** Percent text for a probability, `97%`. */
export function percent(share: number): string {
  return `${Math.round(Math.min(1, Math.max(0, share)) * 100)}%`;
}
