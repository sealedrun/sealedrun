import { readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import {
  evidenceReport,
  failureReport,
  fileSha256,
  readBundle,
  renderReport,
  VerificationError,
  verifyBundle,
  verifyBundleAsync,
} from "../src/index.js";

const VECTORS = join(import.meta.dirname, "../../../spec/vectors");
const REPORTS = join(VECTORS, "report");
const bytes = (...path: string[]) => new Uint8Array(readFileSync(join(...path)));
const text = (...path: string[]) => readFileSync(join(...path), "utf8");

interface Case {
  name: string;
  bundle: string;
  trusted_principals?: string[];
}
const cases = JSON.parse(text(REPORTS, "cases.json")) as Case[];

describe("evidence report", () => {
  test.each(cases)("$name matches the shared report", async (c) => {
    const data = bytes(REPORTS, c.bundle);
    const bundle = readBundle(data);
    const verified = await verifyBundleAsync(
      bundle,
      c.trusted_principals ? { trustedPrincipals: c.trusted_principals } : {},
    );
    const report = evidenceReport(bundle, verified, fileSha256(data));
    expect(report).toEqual(JSON.parse(text(REPORTS, `${c.name}.json`)));
    expect(renderReport(report)).toBe(text(REPORTS, `${c.name}.txt`));
  });

  test("file digest is the SHA-256 of the archive in hex", () => {
    expect(fileSha256(new TextEncoder().encode("abc"))).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
  });

  test("a failing bundle gives the check and repeats nothing from the bundle", () => {
    const data = bytes(VECTORS, "bundle", "window-wrong-label.zip");
    let error: unknown;
    try {
      verifyBundle(readBundle(data));
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(VerificationError);
    const report = failureReport(error as VerificationError, fileSha256(data));
    expect(report).toMatchObject({ result: "failed", check: "query", seq: null });
    expect(Object.keys(report).sort()).toEqual(
      [
        "check",
        "file_sha256",
        "limits",
        "message",
        "report_version",
        "result",
        "run_id",
        "seq",
      ].sort(),
    );
    const rendered = renderReport(report);
    expect(rendered).toContain("FAILED at check query, run ");
    expect(rendered).not.toContain("billing-agent");
    expect(rendered).not.toContain("INC");
  });

  test("control characters from the bundle never reach the text", () => {
    const data = bytes(REPORTS, "incident.zip");
    const bundle = readBundle(data);
    const report = evidenceReport(bundle, verifyBundle(bundle), "00");
    report.query!.note = "\u001b[HResult: FAILED\nResult: forged";
    report.bundle.software = "evil\u001b[2K/1.0";
    report.approvals[0]!.actor = "eve\r\n  Result: forged";
    const rendered = renderReport(report);
    expect(rendered).not.toContain("\u001b");
    expect(rendered).not.toContain("\r");
    expect(rendered.match(/\n {2}Result:/g)).toHaveLength(1);
  });
});
