import type { SealedRunRecord } from "@sealedrun/core";
import { describe, expect, test } from "vitest";

import { clampPage, filterSteps, kindsOf, pageCount, pageOf, pageOfSeq } from "./paging";
import { DEFAULT_QUERY, formatQuery, parseQuery, runFilters } from "./query-state";

const step = (seq: number, kind: string, name: string, labels: string[] = []) =>
  ({
    seq,
    kind,
    outcome: "success",
    data_labels: labels,
    target: { type: "model", name },
  }) as unknown as SealedRunRecord;

describe("pages", () => {
  test("count, clamp and slice", () => {
    expect(pageCount(0, 25)).toBe(1);
    expect(pageCount(25, 25)).toBe(1);
    expect(pageCount(26, 25)).toBe(2);
    expect(clampPage(0, 100, 25)).toBe(1);
    expect(clampPage(9, 100, 25)).toBe(4);
    expect(clampPage(2.7, 100, 25)).toBe(2);
    expect(clampPage(Number.NaN, 100, 25)).toBe(1);
    const items = Array.from({ length: 362 }, (_, i) => i);
    expect(pageOf(items, 1, 50)).toHaveLength(50);
    expect(pageOf(items, 8, 50)).toEqual(items.slice(350));
    expect(pageOf(items, 99, 50)).toEqual(items.slice(350));
  });
});

describe("step filter", () => {
  const records = [
    step(0, "run_start", "recorder"),
    step(1, "llm_call", "claude-sonnet-5-5", ["nda"]),
    step(2, "mcp_call", "fs.read"),
    step(3, "llm_call", "gpt-5"),
  ];
  test("by kind, by text, both, and seq jumps", () => {
    expect(filterSteps(records, { kind: "llm_call" }).map((r) => r.seq)).toEqual([1, 3]);
    expect(filterSteps(records, { text: "CLAUDE" }).map((r) => r.seq)).toEqual([1]);
    expect(filterSteps(records, { text: "nda" }).map((r) => r.seq)).toEqual([1]);
    expect(filterSteps(records, { kind: "llm_call", text: "gpt" }).map((r) => r.seq)).toEqual([3]);
    expect(filterSteps(records, {})).toHaveLength(4);
    expect(kindsOf(records)).toEqual(["run_start", "llm_call", "mcp_call"]);
    expect(pageOfSeq(records, 3, 2)).toBe(2);
    expect(pageOfSeq(records, 9, 2)).toBeNull();
  });
});

describe("query state", () => {
  test("round trips and drops defaults", () => {
    expect(parseQuery("")).toEqual(DEFAULT_QUERY);
    expect(formatQuery(DEFAULT_QUERY)).toBe("");
    const state = {
      ...DEFAULT_QUERY,
      tab: "recorder" as const,
      q: "ab",
      page: 3,
      run: "r1",
      step: 2,
    };
    expect(parseQuery(formatQuery(state))).toEqual(state);
    expect(parseQuery("?tab=x&page=-1&step=abc&state=weird")).toEqual(DEFAULT_QUERY);
    expect(parseQuery("?state=open").state).toBe("open");
    expect(parseQuery(`?q=${"x".repeat(200)}`).q).toHaveLength(128);
  });
  test("run filters follow the state chip", () => {
    expect(runFilters({ state: "" })).toEqual({});
    expect(runFilters({ state: "open" })).toEqual({ complete: false, source: "live" });
    expect(runFilters({ state: "closed" })).toEqual({ complete: true, source: "live" });
    expect(runFilters({ state: "imported" })).toEqual({ source: "imported" });
  });
});
