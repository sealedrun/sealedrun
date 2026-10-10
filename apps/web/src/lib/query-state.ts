/**
 * The part of the Inspector's state that lives in the page URL, so a page of the run list or a
 * run with its step page can be linked and the browser's back button works.
 */
export interface QueryState {
  tab: "bundle" | "recorder";
  /** Run list filter text. */
  q: string;
  /** Run list page, 1-based. */
  page: number;
  /** Run list state filter. */
  state: "open" | "closed" | "imported" | "";
  /** Selected run id. */
  run: string;
  /** Step page of the selected run, 1-based. */
  step: number;
}

export const DEFAULT_QUERY: QueryState = {
  tab: "bundle",
  q: "",
  page: 1,
  state: "",
  run: "",
  step: 1,
};

const STATES = new Set(["open", "closed", "imported"]);

/** Reads the state from a query string; unknown or malformed values fall back to the default. */
export function parseQuery(search: string): QueryState {
  const params = new URLSearchParams(search.startsWith("?") ? search.slice(1) : search);
  const page = Number(params.get("page"));
  const step = Number(params.get("step"));
  const state = params.get("state") ?? "";
  return {
    tab: params.get("tab") === "recorder" ? "recorder" : "bundle",
    q: (params.get("q") ?? "").slice(0, 128),
    page: Number.isInteger(page) && page > 0 ? page : 1,
    state: STATES.has(state) ? (state as QueryState["state"]) : "",
    run: (params.get("run") ?? "").slice(0, 36),
    step: Number.isInteger(step) && step > 0 ? step : 1,
  };
}

/** Writes the state as a query string, leaving out every value equal to the default. */
export function formatQuery(state: QueryState): string {
  const params = new URLSearchParams();
  if (state.tab !== DEFAULT_QUERY.tab) params.set("tab", state.tab);
  if (state.q) params.set("q", state.q);
  if (state.state) params.set("state", state.state);
  if (state.page > 1) params.set("page", String(state.page));
  if (state.run) params.set("run", state.run);
  if (state.step > 1) params.set("step", String(state.step));
  const text = params.toString();
  return text ? `?${text}` : "";
}

/** The run list filters a state asks for, in the API's terms. */
export function runFilters(state: Pick<QueryState, "state">): {
  complete?: boolean;
  source?: "live" | "imported";
} {
  switch (state.state) {
    case "open":
      return { complete: false, source: "live" };
    case "closed":
      return { complete: true, source: "live" };
    case "imported":
      return { source: "imported" };
    default:
      return {};
  }
}
