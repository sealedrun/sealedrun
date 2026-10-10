import { describe, expect, test } from "vitest";

import type { RunSummary } from "./api";
import { describeAnchors, isGrowing, runBadge, shouldPoll } from "./recorder-view";

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

describe("describeAnchors", () => {
  test("says off, ok, failing and untried", () => {
    expect(describeAnchors(undefined)).toEqual({ text: "", warn: false });
    expect(describeAnchors({ configured: [], last_ok: {}, last_error: {} })).toMatchObject({
      warn: true,
    });
    const ok = describeAnchors({
      configured: ["tsa", "rekor"],
      last_ok: { tsa: { at: "2026-10-10T09:00:00.000Z", url: "https://t" } },
      last_error: {},
    });
    expect(ok).toEqual({
      text: "Anchors: tsa ok 2026-10-10 09:00 · rekor not tried yet",
      warn: false,
    });
    const bad = describeAnchors({
      configured: ["tsa"],
      last_ok: {},
      last_error: { tsa: { at: "2026-10-10T09:00:00.000Z", message: "answered 503" } },
    });
    expect(bad).toEqual({ text: "Anchors: tsa failing (answered 503)", warn: true });
  });
});

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
