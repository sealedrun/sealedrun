"use client";

import { Check, Copy, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import { useState } from "react";

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
          <dl className="mt-4 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
            <dt className="text-ink-soft">File</dt>
            <dd>
              {verification.fileName}{" "}
              <span className="text-ink-soft">{(verification.sizeBytes / 1024).toFixed(1)} KB</span>
            </dd>
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
