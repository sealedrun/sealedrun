import type { SealedRunRecord } from "@sealedrun/core";
import { describe, expect, test } from "vitest";

import {
  answerBars,
  decisionAnswers,
  gateOf,
  gateOutcome,
  isDecisionStep,
  percent,
} from "./decision";

function record(
  seq: number,
  extensions?: SealedRunRecord["extensions"],
  parent?: string,
): SealedRunRecord {
  const base: SealedRunRecord = {
    record_id: `r${seq}`,
    run_id: "run",
    seq,
    occurred_at: "2026-10-17T00:00:00.000Z",
    principal_id: "p",
    agent_id: "a",
    kind: "llm_call",
    actor: { type: "agent", id: "a" },
    target: { type: "model", name: "typesafe/jev-1.13", location: "cloud" },
    data_labels: [],
    outcome: "success",
    hash_alg: "sha-256",
    prev_hash: "0",
    hash: "1",
    signatures: {},
    spec_version: "0.1",
  } as unknown as SealedRunRecord;
  if (extensions) base.extensions = extensions;
  if (parent) base.parent_record_id = parent;
  return base;
}

const DECISION: SealedRunRecord["extensions"] = {
  "sealedrun.decision": {
    answers: [
      { name: "touches_prod", type: "predicate", value: 0.97 },
      {
        name: "team",
        type: "choice",
        value: "engineering",
        confidence: 0.9,
        probabilities: { billing: 0.05, engineering: 0.95 },
      },
      {
        name: "severity",
        type: "score",
        value: 1.99,
        probabilities: { harmless: 0, recoverable: 0.01, destructive: 0.99 },
      },
      { name: "intent", type: "choice", refused: true },
      { name: 7, type: "choice" },
    ],
  },
};

describe("decision answers", () => {
  test("parses each answer type and skips malformed entries", () => {
    const answers = decisionAnswers(record(1, DECISION))!;
    expect(answers.map((a) => a.name)).toEqual(["touches_prod", "team", "severity", "intent"]);
    expect(answers[0]).toEqual({
      name: "touches_prod",
      type: "predicate",
      value: 0.97,
      refused: false,
    });
    expect(answers[1]!.probabilities).toEqual({ billing: 0.05, engineering: 0.95 });
    expect(answers[3]!.refused).toBe(true);
    expect(decisionAnswers(record(1))).toBeNull();
    expect(decisionAnswers(record(1, { "sealedrun.decision": { answers: [] } }))).toBeNull();
  });

  test("bars: predicate against yes, choice and score by label with the chosen one marked", () => {
    const [predicate, choice, score, refusal] = decisionAnswers(record(1, DECISION))!;
    expect(answerBars(predicate!)).toEqual([{ label: "yes", share: 0.97, chosen: true }]);
    expect(answerBars(choice!).map((b) => [b.label, b.chosen])).toEqual([
      ["billing", false],
      ["engineering", true],
    ]);
    expect(answerBars(score!).map((b) => [b.label, b.chosen])).toEqual([
      ["harmless", false],
      ["recoverable", false],
      ["destructive", true],
    ]);
    expect(answerBars(refusal!)).toEqual([]);
    expect(percent(0.974)).toBe("97%");
    expect(percent(2)).toBe("100%");
  });
});

describe("gates", () => {
  const decision = record(1, DECISION);
  const gate = record(
    2,
    {
      "sealedrun.step": { source: "self_reported" },
      "sealedrun.gate": {
        outcome: "block",
        thresholds: { touches_prod: 0.5 },
        reason: "0.97 > 0.5",
      },
    },
    "r1",
  );
  const stray = record(3, { "sealedrun.gate": { outcome: "maybe" } }, "r1");

  test("gateOf finds the gate step linked by parent_record_id", () => {
    expect(gateOf(decision, [decision, stray, gate])).toEqual({
      seq: 2,
      recordId: "r2",
      outcome: "block",
      thresholds: { touches_prod: 0.5 },
      reason: "0.97 > 0.5",
    });
    expect(gateOf(decision, [decision, stray])).toBeNull();
  });

  test("gateOutcome and isDecisionStep", () => {
    expect(gateOutcome(gate)).toBe("block");
    expect(gateOutcome(stray)).toBeNull();
    expect(isDecisionStep(decision)).toBe(true);
    expect(isDecisionStep(gate)).toBe(true);
    expect(isDecisionStep(record(4))).toBe(false);
  });
});
