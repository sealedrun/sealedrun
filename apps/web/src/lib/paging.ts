import type { SealedRunRecord } from "@sealedrun/core";

/** Runs per page in the recorder list. */
export const RUNS_PER_PAGE = 25;
/** Steps per page in a run's timeline. */
export const STEPS_PER_PAGE = 50;

/** Number of pages for `total` items, at least 1 so an empty list still has a page. */
export function pageCount(total: number, perPage: number): number {
  return Math.max(1, Math.ceil(total / perPage));
}

/** Clamps a requested page into `1..pageCount`. */
export function clampPage(page: number, total: number, perPage: number): number {
  const count = pageCount(total, perPage);
  if (!Number.isFinite(page) || page < 1) return 1;
  return Math.min(Math.floor(page), count);
}

/** The items of page `page` (1-based). */
export function pageOf<T>(items: readonly T[], page: number, perPage: number): T[] {
  const start = (clampPage(page, items.length, perPage) - 1) * perPage;
  return items.slice(start, start + perPage);
}

/** Filters a timeline: a step kind, a case-insensitive text over target and labels, or both. */
export interface StepFilter {
  kind?: string;
  text?: string;
}

/** Steps matching `filter`, in their original order. */
export function filterSteps(records: readonly SealedRunRecord[], filter: StepFilter) {
  const kind = filter.kind?.trim();
  const needle = filter.text?.trim().toLowerCase();
  return records.filter((record) => {
    if (kind && record.kind !== kind) return false;
    if (!needle) return true;
    const haystack = [
      record.target.name,
      record.target.type,
      record.kind,
      record.outcome,
      record.policy?.decision ?? "",
      ...record.data_labels,
      String(record.seq),
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(needle);
  });
}

/** The page on which the step with sequence number `seq` sits, or null when it is not listed. */
export function pageOfSeq(records: readonly SealedRunRecord[], seq: number, perPage: number) {
  const index = records.findIndex((record) => record.seq === seq);
  return index < 0 ? null : Math.floor(index / perPage) + 1;
}

/** Distinct step kinds in the order first seen, for the filter chips. */
export function kindsOf(records: readonly SealedRunRecord[]): string[] {
  const seen: string[] = [];
  for (const record of records) if (!seen.includes(record.kind)) seen.push(record.kind);
  return seen;
}
