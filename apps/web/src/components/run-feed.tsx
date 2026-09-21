"use client";

import type { SealedRunRecord } from "@sealedrun/core";
import { ChevronDown, Download } from "lucide-react";
import { useState } from "react";

import { decodePayload, describeTarget, summarize } from "@/lib/inspect";

/**
 * Downloads a payload from the recorder. Left undefined for a local bundle, which has no server
 * copy.
 */
type OnDownload = ((recordId: string, side: "request" | "response") => void) | undefined;

/** Tag colours by location, policy decision or outcome. Tags not listed use the neutral default. */
const TAG_TONES: Record<string, string> = {
  local: "bg-ok-soft text-ok",
  cloud: "bg-warn-soft text-warn",
  blocked: "bg-bad-soft text-bad",
  error: "bg-bad-soft text-bad",
  deny: "bg-bad-soft text-bad",
  block: "bg-bad-soft text-bad",
  redirect: "bg-warn-soft text-warn",
  require_approval: "bg-warn-soft text-warn",
};

/**
 * Summary counts for a run followed by its steps as a timeline. One step can be expanded at a time.
 *
 * @param payloads - Bodies from a local bundle, keyed by digest, shown inline in the step detail.
 * @param onDownload - Set for recorder runs, where bodies are downloaded instead of shown.
 */
export function RunFeed({
  records,
  payloads,
  onDownload,
}: {
  records: SealedRunRecord[];
  payloads?: Map<string, Uint8Array> | undefined;
  onDownload?: OnDownload;
}) {
  const [open, setOpen] = useState<string | null>(null);
  const summary = summarize(records);
  const facts: [number, string, string?][] = [
    [summary.steps, "steps recorded"],
    [summary.cloudCalls, "left the host", summary.cloudCalls > 0 ? "text-warn" : undefined],
    [summary.blocked, "blocked by policy", summary.blocked > 0 ? "text-bad" : undefined],
    [summary.anchors, "anchors"],
  ];
  return (
    <div>
      <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-line bg-line sm:grid-cols-4">
        {facts.map(([value, label, tone]) => (
          <div key={label} className="bg-surface px-4 py-3">
            <dd className={`text-2xl font-semibold tabular-nums ${tone ?? ""}`}>{value}</dd>
            <dt className="text-sm text-ink-soft">{label}</dt>
          </div>
        ))}
      </dl>
      <p className="mt-3 text-sm text-ink-soft">
        {summary.labels.length > 0 && (
          <>
            Data labels seen: <span className="text-ink">{summary.labels.join(", ")}</span>.{" "}
          </>
        )}
        {summary.anchors > 0 &&
          "Anchor receipts are tied to the chain here, but the witness proof is not checked: confirm it with the witness."}
      </p>
      <ol className="mt-6">
        {records.map((record, index) => (
          <Step
            key={record.record_id}
            record={record}
            first={index === 0}
            last={index === records.length - 1}
            open={open === record.record_id}
            onToggle={() => setOpen(open === record.record_id ? null : record.record_id)}
            payloads={payloads}
            onDownload={onDownload}
          />
        ))}
      </ol>
    </div>
  );
}

/**
 * Colour of a step's timeline node. Failure wins over a cloud target, which wins over an anchor.
 */
function nodeTone(record: SealedRunRecord): string {
  if (record.outcome === "blocked" || record.outcome === "error") return "border-bad bg-bad";
  if (record.target.location === "cloud") return "border-warn bg-warn";
  if (record.kind === "anchor") return "border-seal bg-seal";
  return "border-ink-soft bg-surface";
}

/**
 * One timeline row: sequence number, kind, target, tags and the policy reason, expandable to the
 * record detail. The vertical rail stands for the hash chain, where every step is linked to the
 * one before it, so it starts at the first node and ends at the last.
 */
function Step({
  record,
  first,
  last,
  open,
  onToggle,
  payloads,
  onDownload,
}: {
  record: SealedRunRecord;
  first: boolean;
  last: boolean;
  open: boolean;
  onToggle: () => void;
  payloads?: Map<string, Uint8Array> | undefined;
  onDownload?: OnDownload;
}) {
  const location = record.target.location;
  const decision = record.policy?.decision;
  const tags: string[] = [
    ...(location ? [location] : []),
    ...(decision && decision !== "allow" ? [decision] : []),
    ...(record.outcome !== "success" ? [record.outcome] : []),
  ];
  return (
    <li className="relative pl-8">
      <span
        aria-hidden
        className={`absolute left-[6.5px] w-0.5 bg-ink-soft/35 ${first ? "top-[18px]" : "top-0"} ${
          last ? "h-[18px]" : "bottom-0"
        } ${first && last ? "hidden" : ""}`}
      />
      <span
        aria-hidden
        className={`absolute top-[18px] left-0 size-[15px] rounded-full border-2 ${nodeTone(record)}`}
      />
      <div className={`rounded-lg ${open ? "bg-surface shadow-sm ring-1 ring-line" : ""}`}>
        <button
          type="button"
          onClick={onToggle}
          aria-expanded={open}
          className="flex w-full cursor-pointer items-start gap-3 rounded-lg px-3 py-3 text-left hover:bg-surface"
        >
          <span className="w-8 shrink-0 pt-0.5 font-mono text-xs text-ink-soft tabular-nums">
            #{record.seq}
          </span>
          <span className="min-w-0 flex-1">
            <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <span className="font-semibold">{record.kind.replaceAll("_", " ")}</span>
              <span className="min-w-0 text-ink-soft [overflow-wrap:anywhere]">
                {describeTarget(record)}
              </span>
              {tags.map((tag) => (
                <Tag key={tag} tone={TAG_TONES[tag]}>
                  {tag.replaceAll("_", " ")}
                </Tag>
              ))}
              {record.data_labels.map((label) => (
                <Tag key={label} tone="bg-seal-soft text-seal">
                  {label}
                </Tag>
              ))}
              {record.payload?.request_size !== undefined && (
                <span className="text-xs text-ink-soft tabular-nums">
                  {record.payload.request_size} B sent
                </span>
              )}
            </span>
            {record.policy && (
              <span className="mt-0.5 block text-sm text-ink-soft">
                {record.policy.rule_id}: {record.policy.reason}
              </span>
            )}
          </span>
          <ChevronDown
            aria-hidden
            className={`mt-1 size-4 shrink-0 text-ink-soft transition-transform ${open ? "rotate-180" : ""}`}
          />
        </button>
        {open && <Detail record={record} payloads={payloads} onDownload={onDownload} />}
      </div>
    </li>
  );
}

/** Small coloured label. */
function Tag({ tone, children }: { tone?: string | undefined; children: React.ReactNode }) {
  return (
    <span
      className={`rounded px-1.5 py-0.5 text-xs font-medium ${tone ?? "bg-paper text-ink-soft"}`}
    >
      {children}
    </span>
  );
}

/**
 * Expanded view of a record: ids, hashes, payload digests, stored bodies and extensions. Rows
 * without a value are skipped.
 */
function Detail({
  record,
  payloads,
  onDownload,
}: {
  record: SealedRunRecord;
  payloads?: Map<string, Uint8Array> | undefined;
  onDownload?: OnDownload;
}) {
  const stored = record.payload?.storage === "bundle" || record.payload?.storage === "inline";
  const rows: [string, string | undefined, boolean][] = [
    ["Record id", record.record_id, true],
    ["Time", record.occurred_at, true],
    ["Actor", `${record.actor.type} ${record.actor.id}`, false],
    ["Hash", record.hash, true],
    ["Previous hash", record.prev_hash, true],
    ["Parent record", record.parent_record_id, true],
    ["Request digest", record.payload?.request_hash, true],
    ["Response digest", record.payload?.response_hash, true],
  ];
  return (
    <div className="border-t border-line px-3 pt-3 pb-4 sm:pl-14">
      <dl className="grid gap-x-6 gap-y-1.5 text-sm sm:grid-cols-[9rem_1fr]">
        {rows.map(
          ([label, value, mono]) =>
            value && (
              <div key={label} className="contents">
                <dt className="text-ink-soft">{label}</dt>
                <dd className={mono ? "hash" : ""}>{value}</dd>
              </div>
            ),
        )}
      </dl>
      {stored &&
        (["request", "response"] as const).map((side) => {
          if (!record.payload?.[`${side}_hash`]) return null;
          const local = payloads?.get(record.payload[`${side}_hash`] ?? "");
          return (
            <div key={side} className="mt-4">
              <div className="flex items-center gap-3">
                <h4 className="text-sm font-semibold">
                  {side === "request" ? "Request" : "Response"} body
                </h4>
                {onDownload && (
                  <button
                    type="button"
                    className="btn px-2 py-1 text-xs"
                    onClick={() => onDownload(record.record_id, side)}
                  >
                    <Download aria-hidden className="size-3.5" /> Download
                  </button>
                )}
              </div>
              {local && <Code>{decodePayload(local)}</Code>}
            </div>
          );
        })}
      {record.extensions && (
        <div className="mt-4">
          <h4 className="text-sm font-semibold">Extensions</h4>
          <Code>{JSON.stringify(record.extensions, null, 2)}</Code>
        </div>
      )}
    </div>
  );
}

/** Scrollable monospace block for a payload body or JSON. */
function Code({ children }: { children: string }) {
  return (
    <pre className="mt-1.5 max-h-80 overflow-auto rounded-md bg-paper p-3 font-mono text-[12.5px] leading-relaxed whitespace-pre-wrap">
      {children}
    </pre>
  );
}
