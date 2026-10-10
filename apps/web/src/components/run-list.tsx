"use client";

import type { RunSummary } from "@/lib/api";
import { formatBytes } from "@/lib/inspect";
import { RUNS_PER_PAGE } from "@/lib/paging";
import type { QueryState } from "@/lib/query-state";
import { runBadge } from "@/lib/recorder-view";

import { Pager } from "./pager";

const STATES: { value: QueryState["state"]; label: string }[] = [
  { value: "", label: "All" },
  { value: "open", label: "Open" },
  { value: "closed", label: "Closed" },
  { value: "imported", label: "Imported" },
];

/**
 * The recorder's runs: a filter bar, one page of runs as a table (cards on narrow screens) and
 * a pager. The filters and page live in the URL, so the parent owns them.
 */
export function RunList({
  runs,
  total,
  query,
  selected,
  onQuery,
  onSelect,
}: {
  runs: RunSummary[];
  total: number;
  query: Pick<QueryState, "q" | "page" | "state">;
  selected: string | null;
  onQuery: (next: Partial<Pick<QueryState, "q" | "page" | "state">>) => void;
  onSelect: (run: RunSummary) => void;
}) {
  return (
    <section aria-label="Runs">
      <div className="flex flex-wrap items-center gap-2">
        <input
          type="search"
          value={query.q}
          onChange={(event) => onQuery({ q: event.target.value, page: 1 })}
          placeholder="Run id or label"
          aria-label="Find runs"
          className="min-w-0 flex-1 rounded border border-line bg-surface px-3 py-1.5 text-sm"
        />
        <div className="flex gap-1" role="group" aria-label="Run state">
          {STATES.map((state) => (
            <button
              key={state.value || "all"}
              type="button"
              aria-pressed={query.state === state.value}
              onClick={() => onQuery({ state: state.value, page: 1 })}
              className={`rounded px-2 py-1 text-xs font-medium ${
                query.state === state.value
                  ? "bg-seal-soft text-seal"
                  : "bg-line text-ink-soft hover:text-ink"
              }`}
            >
              {state.label}
            </button>
          ))}
        </div>
      </div>
      {runs.length === 0 ? (
        <p className="mt-4 text-ink-soft">No runs match.</p>
      ) : (
        <ul className="mt-3 divide-y divide-line rounded-lg border border-line bg-surface">
          {runs.map((run) => {
            const badge = runBadge(run);
            const active = selected === run.run_id;
            return (
              <li key={run.run_id}>
                <button
                  type="button"
                  onClick={() => onSelect(run)}
                  aria-pressed={active}
                  className={`flex w-full cursor-pointer flex-col gap-1 px-3 py-2.5 text-left text-sm ${
                    active ? "bg-seal-soft" : "hover:bg-line/50"
                  }`}
                >
                  <span className="hash block [overflow-wrap:anywhere]">
                    {run.run_label ?? run.run_id}
                  </span>
                  {run.run_label && (
                    <span className="hash block text-xs text-ink-soft [overflow-wrap:anywhere]">
                      {run.run_id}
                    </span>
                  )}
                  <span className="flex flex-wrap items-center gap-x-3 gap-y-1 text-ink-soft tabular-nums">
                    <time dateTime={run.started_at}>
                      {run.started_at.slice(0, 16).replace("T", " ")}
                    </time>
                    <span>
                      {run.record_count} steps
                      {run.anchors > 0 ? ` · ${run.anchors} anchors` : ""}
                      {run.payload_bytes !== undefined
                        ? ` · ${formatBytes(run.payload_bytes)}`
                        : ""}
                    </span>
                  </span>
                  <span className="flex items-center gap-2">
                    <span className={`rounded px-1.5 py-0.5 text-xs font-medium ${badge.tone}`}>
                      {badge.label}
                    </span>
                    <span
                      className={`text-xs ${run.principal_trusted ? "text-ok" : "text-warn"}`}
                      title={`Principal ${run.principal_id}`}
                    >
                      {run.principal_trusted ? "trusted" : "unconfirmed"}
                    </span>
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
      <div className="mt-3">
        <Pager
          page={query.page}
          total={total}
          perPage={RUNS_PER_PAGE}
          onPage={(page) => onQuery({ page })}
          label="Runs"
        />
      </div>
    </section>
  );
}
