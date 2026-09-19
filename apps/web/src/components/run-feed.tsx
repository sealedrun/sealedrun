"use client";

import type { SealedRunRecord } from "@sealedrun/core";
import { useState } from "react";

import { decodePayload, describeTarget, summarize } from "@/lib/inspect";

export function RunFeed({
  records,
  payloads,
  payloadUrl,
}: {
  records: SealedRunRecord[];
  payloads?: Map<string, Uint8Array> | undefined;
  payloadUrl?: ((recordId: string, side: "request" | "response") => string) | undefined;
}) {
  const [open, setOpen] = useState<string | null>(null);
  const summary = summarize(records);
  return (
    <div>
      <div className="summary">
        <div>
          <b>{summary.steps}</b>
          <span>steps</span>
        </div>
        <div>
          <b>{summary.cloudCalls}</b>
          <span>left the host</span>
        </div>
        <div>
          <b>{summary.blocked}</b>
          <span>blocked</span>
        </div>
        <div>
          <b>{summary.anchors}</b>
          <span>anchors</span>
        </div>
        <div>
          <b>{summary.labels.length}</b>
          <span>{summary.labels.join(", ") || "no labels"}</span>
        </div>
      </div>
      <div className="feed">
        {records.map((record) => (
          <Step
            key={record.record_id}
            record={record}
            open={open === record.record_id}
            onToggle={() => setOpen(open === record.record_id ? null : record.record_id)}
            payloads={payloads}
            payloadUrl={payloadUrl}
          />
        ))}
      </div>
    </div>
  );
}

function Step({
  record,
  open,
  onToggle,
  payloads,
  payloadUrl,
}: {
  record: SealedRunRecord;
  open: boolean;
  onToggle: () => void;
  payloads?: Map<string, Uint8Array> | undefined;
  payloadUrl?: ((recordId: string, side: "request" | "response") => string) | undefined;
}) {
  const location = record.target.location;
  const decision = record.policy?.decision;
  return (
    <div className={`step ${open ? "open" : ""}`} onClick={onToggle}>
      <div className="seq">#{record.seq}</div>
      <div>
        <div className="line">
          <span className="kind">{record.kind}</span>
          <span className="arrow">→</span>
          <span>{describeTarget(record)}</span>
          {location && <span className={`tag ${location}`}>{location}</span>}
          {record.data_labels.map((label) => (
            <span key={label} className="tag label">
              {label}
            </span>
          ))}
          {record.payload?.request_size !== undefined && (
            <span className="tag">{record.payload.request_size} B sent</span>
          )}
          {decision && decision !== "allow" && (
            <span className={`tag ${decision}`}>{decision}</span>
          )}
          {record.outcome !== "success" && (
            <span className={`tag ${record.outcome}`}>{record.outcome}</span>
          )}
        </div>
        {record.policy && (
          <div className="why">
            {record.policy.rule_id}: {record.policy.reason}
          </div>
        )}
        {open && <Detail record={record} payloads={payloads} payloadUrl={payloadUrl} />}
      </div>
    </div>
  );
}

function Detail({
  record,
  payloads,
  payloadUrl,
}: {
  record: SealedRunRecord;
  payloads?: Map<string, Uint8Array> | undefined;
  payloadUrl?: ((recordId: string, side: "request" | "response") => string) | undefined;
}) {
  const stored = record.payload?.storage === "bundle" || record.payload?.storage === "inline";
  return (
    <div className="detail" onClick={(event) => event.stopPropagation()}>
      <dl>
        <dt>record_id</dt>
        <dd className="mono">{record.record_id}</dd>
        <dt>occurred_at</dt>
        <dd className="mono">{record.occurred_at}</dd>
        <dt>actor</dt>
        <dd>
          {record.actor.type} {record.actor.id}
        </dd>
        <dt>hash</dt>
        <dd className="mono">{record.hash}</dd>
        <dt>prev_hash</dt>
        <dd className="mono">{record.prev_hash}</dd>
        {record.parent_record_id && (
          <>
            <dt>parent</dt>
            <dd className="mono">{record.parent_record_id}</dd>
          </>
        )}
        {record.payload && (
          <>
            <dt>payload</dt>
            <dd className="mono">
              {record.payload.storage}
              {record.payload.request_hash ? ` · req ${record.payload.request_hash}` : ""}
              {record.payload.response_hash ? ` · res ${record.payload.response_hash}` : ""}
            </dd>
          </>
        )}
      </dl>
      {stored &&
        (["request", "response"] as const).map((side) => {
          const digest = record.payload?.[`${side}_hash`];
          if (!digest) return null;
          const local = payloads?.get(digest);
          return (
            <div key={side}>
              <p className="muted" style={{ margin: "8px 0 0" }}>
                {side}{" "}
                {payloadUrl && (
                  <a href={payloadUrl(record.record_id, side)} target="_blank" rel="noreferrer">
                    open
                  </a>
                )}
              </p>
              {local && <pre className="mono">{decodePayload(local)}</pre>}
            </div>
          );
        })}
      {record.extensions && (
        <pre className="mono">{JSON.stringify(record.extensions, null, 2)}</pre>
      )}
    </div>
  );
}
