"use client";

import { pageCount } from "@/lib/paging";

/** Previous/next controls with the page position, hidden when everything fits on one page. */
export function Pager({
  page,
  total,
  perPage,
  onPage,
  label,
}: {
  page: number;
  total: number;
  perPage: number;
  onPage: (page: number) => void;
  label: string;
}) {
  const count = pageCount(total, perPage);
  if (count <= 1) return null;
  const first = (page - 1) * perPage + 1;
  const last = Math.min(page * perPage, total);
  return (
    <nav className="flex flex-wrap items-center gap-2 text-sm" aria-label={label}>
      <button
        type="button"
        className="btn"
        onClick={() => onPage(page - 1)}
        disabled={page <= 1}
        aria-label="Previous page"
      >
        ‹
      </button>
      <span className="text-ink-soft tabular-nums">
        {first}–{last} of {total}
      </span>
      <button
        type="button"
        className="btn"
        onClick={() => onPage(page + 1)}
        disabled={page >= count}
        aria-label="Next page"
      >
        ›
      </button>
      <label className="ml-auto flex items-center gap-1 text-ink-soft">
        Page
        <input
          type="number"
          min={1}
          max={count}
          value={page}
          onChange={(event) => onPage(Number(event.target.value))}
          className="w-16 rounded border border-line bg-surface px-2 py-1 text-ink tabular-nums"
          aria-label={`${label} page number`}
        />
        <span className="tabular-nums">of {count}</span>
      </label>
    </nav>
  );
}
