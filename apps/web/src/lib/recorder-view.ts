import type { RunSummary } from "./api";

/** How often the recorder tab re-reads the run list and the open run's timeline. */
export const POLL_MS = 5000;

/**
 * Tells whether the recorder tab should keep polling: only while it is the visible tab of a
 * connected recorder, so a hidden page or an offline recorder costs nothing.
 */
export function shouldPoll(
  view: "bundle" | "recorder",
  state: "loading" | "ready" | "locked" | "offline",
  visibility: DocumentVisibilityState,
): boolean {
  return view === "recorder" && state === "ready" && visibility === "visible";
}

/** Short label and tone for a run's origin and state, shown as a badge in the run list. */
export function runBadge(run: RunSummary): { label: string; tone: string } {
  if (run.source === "imported") return { label: "imported", tone: "bg-line text-ink-soft" };
  if (run.complete) return { label: "live, closed", tone: "bg-ok-soft text-ok" };
  return { label: "live, open", tone: "bg-seal-soft text-seal" };
}

/** True when a run's timeline can still grow, so the open one is worth re-reading. */
export function isGrowing(run: RunSummary | null): boolean {
  return run !== null && run.source === "live" && !run.complete;
}
