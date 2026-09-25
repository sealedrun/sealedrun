import { describe, expect, test } from "vitest";

import type { RunSummary } from "./api";
import { isGrowing, runBadge, shouldPoll } from "./recorder-view";

const base: RunSummary = {
  run_id: "r1",
  bundle_id: null,
  source: "live",
  agent_id: "a",
  principal_id: "p",
  principal_trusted: true,
  hash_alg: "sha-256",
  started_at: "2026-09-25T00:00:00.000Z",
  ended_at: null,
  record_count: 3,
  first_seq: 0,
  last_hash: "h",
  complete: false,
  anchors: 0,
  labels_sent_to_cloud: {},
};

describe("shouldPoll", () => {
  test("polls only the visible recorder tab of a connected recorder", () => {
    expect(shouldPoll("recorder", "ready", "visible")).toBe(true);
    expect(shouldPoll("recorder", "ready", "hidden")).toBe(false);
    expect(shouldPoll("bundle", "ready", "visible")).toBe(false);
    expect(shouldPoll("recorder", "locked", "visible")).toBe(false);
    expect(shouldPoll("recorder", "offline", "visible")).toBe(false);
  });
});

describe("runBadge", () => {
  test("names the source and whether a live run is still open", () => {
    expect(runBadge(base).label).toBe("live, open");
    expect(runBadge({ ...base, complete: true }).label).toBe("live, closed");
    expect(runBadge({ ...base, source: "imported", bundle_id: "b" }).label).toBe("imported");
  });
});

describe("isGrowing", () => {
  test("only an open live run can still grow", () => {
    expect(isGrowing(base)).toBe(true);
    expect(isGrowing({ ...base, complete: true })).toBe(false);
    expect(isGrowing({ ...base, source: "imported" })).toBe(false);
    expect(isGrowing(null)).toBe(false);
  });
});
