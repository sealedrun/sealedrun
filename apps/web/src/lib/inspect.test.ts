import type { SealedRunRecord } from "@sealedrun/core";
import { describe, expect, test } from "vitest";

import { isSelfReported, recordKey, summarize, witnessResults } from "./inspect";

function record(extensions?: SealedRunRecord["extensions"]): SealedRunRecord {
  return {
    record_id: "r",
    run_id: "run",
    seq: 1,
    prev_hash: "0",
    hash: "1",
    hash_alg: "sha-256",
    kind: "tool_call",
    occurred_at: "2026-09-28T00:00:00.000Z",
    agent_id: "a",
    principal_id: "p",
    actor: { type: "agent", id: "a" },
    target: { type: "tool", name: "add", location: "cloud" },
    outcome: "success",
    data_labels: ["nda"],
    signatures: {},
    ...(extensions ? { extensions } : {}),
  } as SealedRunRecord;
}

describe("isSelfReported", () => {
  test("a step marker makes the record self-reported, a proxy extension does not", () => {
    expect(isSelfReported(record({ "sealedrun.step": { source: "self_reported" } }))).toBe(true);
    expect(isSelfReported(record({ "sealedrun.proxy": { dialect: "mcp" } }))).toBe(false);
    expect(isSelfReported(record())).toBe(false);
  });

  test("summary still counts every record", () => {
    const summary = summarize([
      record({ "sealedrun.step": { source: "self_reported" } }),
      record(),
    ]);
    expect(summary.steps).toBe(2);
    expect(summary.labels).toEqual(["nda"]);
  });
});

import { anchorInfo, capText, decodePayload, DISPLAY_CAP } from "./inspect";

function anchorRecord(receipt: Record<string, unknown>, type = "rekor"): SealedRunRecord {
  const extensions = {
    "sealedrun.anchor": { type, witness: "https://rekor.sigstore.dev", receipt },
  } as unknown as SealedRunRecord["extensions"];
  return { ...record(extensions), kind: "anchor" } as SealedRunRecord;
}

const receipt = { log_index: 12, log_url: "https://evil.example", integrated_time: 1 };

describe("anchorInfo", () => {
  const rekor = { verified: true, witness: "https://rekor.sigstore.dev", subject: "Rekor" };
  test("links the log entry from the trust entry that verified it, never from the record", () => {
    const info = anchorInfo(anchorRecord(receipt), rekor);
    expect(info?.entryUrl).toBe("https://search.sigstore.dev/?logIndex=12");
    expect(info?.witness).toBe("https://rekor.sigstore.dev");
    expect(info?.subject).toBe("Rekor");
    const other = { ...rekor, witness: "https://log.example//" };
    expect(anchorInfo(anchorRecord(receipt), other)?.entryUrl).toBe(
      "https://log.example/api/v1/log/entries?logIndex=12",
    );
    expect(anchorInfo(anchorRecord(receipt), { verified: false })?.entryUrl).toBeUndefined();
    expect(anchorInfo(anchorRecord(receipt), { verified: false })?.witness).toBe(
      "https://rekor.sigstore.dev",
    );
    expect(anchorInfo(anchorRecord(receipt))?.entryUrl).toBeUndefined();
    expect(
      anchorInfo(anchorRecord({ ...receipt, log_index: "12" }), rekor)?.entryUrl,
    ).toBeUndefined();
    expect(anchorInfo(anchorRecord(receipt, "rfc3161"), rekor)?.entryUrl).toBeUndefined();
  });

  test("a rekor time is the log's integrated_time even when the record claims a gen_time", () => {
    const backdated = { ...receipt, gen_time: "2020-01-01T00:00:00Z" };
    expect(anchorInfo(anchorRecord(backdated), rekor)?.time).toBe("1970-01-01T00:00:01.000Z");
    expect(anchorInfo(anchorRecord({ gen_time: "2026-01-01T00:00:00Z" }, "rfc3161"))?.time).toBe(
      "2026-01-01T00:00:00Z",
    );
  });

  test("a long witness value does not stall the page", () => {
    const long = { ...rekor, witness: `https:${"/".repeat(200_000)}x` };
    const started = performance.now();
    anchorInfo(anchorRecord(receipt), long);
    expect(performance.now() - started).toBeLessThan(500);
  });
});

describe("witnessResults", () => {
  test("verdicts are keyed per run, so two runs may reuse a record id", async () => {
    const one = { ...anchorRecord(receipt), run_id: "run-1" } as SealedRunRecord;
    const two = { ...anchorRecord(receipt), run_id: "run-2" } as SealedRunRecord;
    const results = await witnessResults([one, two]);
    expect([...results.keys()]).toEqual(["run-1/r", "run-2/r"]);
    expect(results.get(recordKey(one))).toEqual({ verified: false });
  });
});

describe("display cap", () => {
  test("long bodies are cut with a note and never pretty-printed whole", () => {
    const big = new TextEncoder().encode(`[${"1,".repeat(DISPLAY_CAP)}1]`);
    const shown = decodePayload(big);
    expect(shown.length).toBeLessThan(DISPLAY_CAP + 200);
    expect(shown).toContain("more bytes not shown");
    expect(decodePayload(new TextEncoder().encode('{"a":1}'))).toBe('{\n  "a": 1\n}');
    expect(capText("abc", 5)).toBe("abc");
    expect(capText("abcdefgh", 5)).toContain("… 3 more characters");
  });
});
