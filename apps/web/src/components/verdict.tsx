"use client";

import { Check, Copy, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { useState } from "react";

import type { BundleReport } from "@sealedrun/core";

import type { LocalVerification } from "@/lib/inspect";

/** Colours and icon for each verdict: verified, intact but signer unknown, failed. */
const TONES = {
  ok: { box: "border-ok bg-ok-soft", text: "text-ok", Icon: ShieldCheck },
  warn: { box: "border-warn bg-warn-soft", text: "text-warn", Icon: ShieldAlert },
  bad: { box: "border-bad bg-bad-soft", text: "text-bad", Icon: ShieldX },
} as const;

/**
 * Verification result banner. Green when the chain holds and the signer is trusted, amber when the
 * chain holds but the signer is not confirmed, red with the failed check otherwise.
 */
export function Verdict({ verification }: { verification: LocalVerification }) {
  const { report, failure } = verification;
  const tone = failure ? "bad" : report?.principalTrusted ? "ok" : "warn";
  const { box, text, Icon } = TONES[tone];
  const runs = report ? `${report.runs.length} run${report.runs.length === 1 ? "" : "s"}` : "";

  return (
    <section className={`rounded-lg border-l-4 p-5 sm:p-6 ${box}`} aria-live="polite">
      <div className="flex items-start gap-4">
        <Icon aria-hidden className={`mt-0.5 size-9 shrink-0 ${text}`} strokeWidth={1.75} />
        <div className="min-w-0 flex-1">
          <h2 className={`text-2xl font-semibold tracking-tight ${text}`}>
            {tone === "ok" && "Verified"}
            {tone === "warn" && "Intact, signer not confirmed"}
            {tone === "bad" && "Verification failed"}
          </h2>
          <p className="mt-1 max-w-[70ch]">
            {tone === "ok" &&
              `Nothing was changed after signing, and the signer is a principal you trust. ${runs}.`}
            {tone === "warn" &&
              `Nothing was changed after signing (${runs}), but anyone can make a bundle that passes this check. To confirm who signed it, get the signer's principal id from the signer and enter it below.`}
            {failure &&
              `Check "${failure.check}"${failure.seq !== undefined ? ` at step #${failure.seq}` : ""}: ${failure.message}`}
          </p>
          {report && <Mandate report={report} />}
          {report?.payloadsOmitted && (
            <p className="mt-2 max-w-[70ch] text-sm" data-testid="payloads-omitted">
              Payloads omitted by the exporter: the records carry every body hash and size, but the
              bodies themselves are not in this file and were not checked.
            </p>
          )}
          <dl className="mt-4 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
            <dt className="text-ink-soft">File</dt>
            <dd>
              {verification.fileName}{" "}
              <span className="text-ink-soft">{(verification.sizeBytes / 1024).toFixed(1)} KB</span>
            </dd>
            {report?.query && (
              <>
                <dt className="text-ink-soft">Exported window</dt>
                <dd data-testid="query-window">
                  {report.query.since} to {report.query.until}
                  {report.query.label && `, run label ${report.query.label}`}
                  {report.query.note && (
                    <span className="block text-ink-soft [overflow-wrap:anywhere]">
                      Exporter&apos;s note: {report.query.note}
                    </span>
                  )}
                </dd>
              </>
            )}
            {report && (
              <>
                <dt className="text-ink-soft">Signed by (principal)</dt>
                <dd>
                  <Copyable value={report.principalId} />
                </dd>
                <dt className="text-ink-soft">Exported by (agent)</dt>
                <dd>
                  <Copyable value={report.exporterAgentId} />
                </dd>
              </>
            )}
          </dl>
        </div>
      </div>
    </section>
  );
}

/**
 * What the verifier found beyond integrity (SPEC 6.4, 6.5, 6.6, 10.9): steps outside the
 * delegation's scope, steps that ran without the human approval their policy required, receipts
 * from the systems the agent touched, and runs whose parent run is in another bundle.
 */
function Mandate({ report }: { report: BundleReport }) {
  const findings = report.runs.flatMap((run) =>
    run.findings.map((finding) => ({ runId: run.runId, ...finding })),
  );
  const scopeCount = findings.filter((f) => f.check.startsWith("scope.")).length;
  const approvalCount = findings.filter((f) => f.check.startsWith("approval.")).length;
  const proxy = report.runs.reduce((n, run) => n + run.receiptsProxy, 0);
  const self = report.runs.reduce((n, run) => n + run.receiptsSelfReported, 0);
  const several = report.runs.length > 1;
  return (
    <div className="mt-3 space-y-2 text-sm" data-testid="mandate">
      <p className={findings.length > 0 ? "text-warn" : ""}>
        {findings.length === 0
          ? "Every step stayed within the delegation's scope, and every step that required a human's approval had it."
          : [
              scopeCount > 0 &&
                `${scopeCount} step${scopeCount === 1 ? "" : "s"} outside the delegation's scope`,
              approvalCount > 0 &&
                `${approvalCount} step${approvalCount === 1 ? "" : "s"} ran without the human approval required`,
            ]
              .filter(Boolean)
              .join("; ") + ":"}
      </p>
      {findings.length > 0 && (
        <ul className="list-disc space-y-0.5 pl-5">
          {findings.map((f) => (
            <li key={`${f.runId}/${f.seq}/${f.check}`}>
              {several && <span className="hash mr-1">{f.runId.slice(0, 8)}</span>}
              step #{f.seq} <span className="font-mono">{f.check}</span>: {f.reason}
            </li>
          ))}
        </ul>
      )}
      <p className="text-ink-soft">
        Receipts from the systems touched: {proxy} seen by the recorder, {self} reported by the
        agent.
        {proxy + self === 0 && " None: the record is the agent's account alone."}
      </p>
      {report.parentsUnresolved.length > 0 && (
        <p className="text-warn" data-testid="parents-unresolved">
          {report.parentsUnresolved.length === 1
            ? "This run was started by a run in another bundle; "
            : `${report.parentsUnresolved.length} runs were started by runs in other bundles; `}
          the link is checked only when both bundles are verified together.
        </p>
      )}
    </div>
  );
}

/**
 * The one-page evidence report as text, with a button that copies it. The text is the one the
 * command line prints, so what is pasted into a claim or a notice can be reproduced there.
 */
export function ReportText({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    void navigator.clipboard?.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <section data-testid="report">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-[60ch] text-sm text-ink-soft">
          One page for a claim file or an incident notice. The command line prints the same text:{" "}
          <span className="font-mono">python -m sealedrun --report</span>.
        </p>
        <button type="button" className="btn" onClick={copy}>
          {copied ? (
            <Check aria-hidden className="size-4" />
          ) : (
            <Copy aria-hidden className="size-4" />
          )}
          {copied ? "Copied" : "Copy as text"}
        </button>
      </div>
      <pre className="max-w-full overflow-x-auto rounded-lg border border-line p-4 font-mono text-xs leading-relaxed">
        {text}
      </pre>
    </section>
  );
}

/** A hash or id with a copy button that shows a check mark for 1.5 s after copying. */
function Copyable({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    void navigator.clipboard?.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  };
  return (
    <span className="inline-flex max-w-full items-start gap-2">
      <span className="hash">{value}</span>
      <button
        type="button"
        onClick={copy}
        className="shrink-0 cursor-pointer rounded p-0.5 text-ink-soft hover:text-ink"
        aria-label={copied ? "Copied" : "Copy"}
      >
        {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
      </button>
    </span>
  );
}
