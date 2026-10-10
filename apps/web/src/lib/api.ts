import { assertRecord, type SealedRunRecord } from "@sealedrun/core";

/** One run as listed by the recorder's `GET /api/runs`. Field names follow the JSON response. */
export interface RunSummary {
  run_id: string;
  bundle_id: string | null;
  source: "live" | "imported";
  agent_id: string;
  principal_id: string;
  principal_trusted: boolean;
  hash_alg: string;
  started_at: string;
  ended_at: string | null;
  record_count: number;
  first_seq: number;
  last_hash: string;
  complete: boolean;
  anchors: number;
  labels_sent_to_cloud: Record<string, number>;
  /** Labels on cloud-target steps the caller reported itself; absent on older recorders. */
  labels_self_reported?: Record<string, number>;
  /** X-SealedRun-Run label of a live run opened through the proxy, else null. */
  run_label?: string | null;
  /** Bytes a full export would carry in bodies; only on `GET /api/runs/{id}`. */
  payload_bytes?: number;
}

/** The part of `GET /api/identity` the page shows. */
export interface Identity {
  principal_id: string;
  agent_id: string;
  anchors?: AnchorStatus;
}

/** Which anchors a recorder is set to use and how each one fared last. */
export interface AnchorStatus {
  configured: string[];
  last_ok: Record<string, { at: string; url: string }>;
  last_error: Record<string, { at: string; message: string }>;
}

const PAGE_SIZE = 1000;

/** Filters and page of the run list, as `GET /api/runs` takes them. */
export interface RunQuery {
  /** Run id prefix or part of the run label. */
  q?: string;
  complete?: boolean;
  source?: "live" | "imported";
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}

/** One page of runs plus how many match the filters before paging. */
export interface RunPage {
  runs: RunSummary[];
  total: number;
}

/** The query string for `GET /api/runs`, empty when nothing is set. */
export function runQueryString(query: RunQuery): string {
  const params = new URLSearchParams();
  if (query.q?.trim()) params.set("q", query.q.trim());
  if (query.complete !== undefined) params.set("complete", String(query.complete));
  if (query.source) params.set("source", query.source);
  if (query.since) params.set("since", query.since);
  if (query.until) params.set("until", query.until);
  if (query.limit !== undefined) params.set("limit", String(query.limit));
  if (query.offset) params.set("offset", String(query.offset));
  const text = params.toString();
  return text ? `?${text}` : "";
}
const TOKEN_KEY = "sealedrun.token";

/** Thrown when the recorder answers 401, meaning the API token is missing or wrong. */
export class UnauthorizedError extends Error {
  /** Takes no arguments: the message is always the same. */
  constructor() {
    super("recorder requires a token");
  }
}

/**
 * Returns the recorder API token kept for this tab, or an empty string when none is set or
 * sessionStorage is unavailable.
 *
 * The token lives in sessionStorage and travels as a Bearer header only. The recorder issues no
 * Basic challenge, so the browser never holds a credential it would attach to a cross-site request.
 */
export function getToken(): string {
  try {
    return sessionStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

/**
 * Remembers the token for this tab; an empty string forgets it. When sessionStorage is unavailable
 * the token is simply not remembered.
 */
export function setToken(token: string): void {
  try {
    if (token) sessionStorage.setItem(TOKEN_KEY, token);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch {}
}

/**
 * `fetch` with the Bearer token attached.
 *
 * @throws {@link UnauthorizedError} on a 401 response.
 */
async function request(path: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  const token = getToken();
  if (token) headers.set("authorization", `Bearer ${token}`);
  const response = await fetch(path, { ...init, headers });
  if (response.status === 401) throw new UnauthorizedError();
  return response;
}

/** GETs a JSON resource and throws on any non-2xx status. */
async function getJson<T>(path: string): Promise<T> {
  const response = await request(path, { headers: { accept: "application/json" } });
  if (!response.ok) throw new Error(`${path}: ${response.status}`);
  return (await response.json()) as T;
}

/** Client for the recorder HTTP API, called on the page's own origin. */
export const api = {
  /** Liveness probe. */
  health: () => getJson<{ status: string }>("/api/health"),
  /** The recorder's keys and the state of its anchors. */
  identity: () => getJson<Identity>("/api/identity"),
  /** One page of the runs stored in the recorder, latest first, with the total that matches. */
  runs: async (query: RunQuery = {}): Promise<RunPage> => {
    const path = `/api/runs${runQueryString(query)}`;
    const response = await request(path, { headers: { accept: "application/json" } });
    if (!response.ok) throw new Error(`${path}: ${response.status}`);
    const runs = (await response.json()) as RunSummary[];
    const header = response.headers.get("x-total-count");
    const total = header === null ? Number.NaN : Number(header);
    return { runs, total: Number.isInteger(total) && total >= 0 ? total : runs.length };
  },
  /** One run's summary, with `payload_bytes`. Throws on 404. */
  run: (runId: string) => getJson<RunSummary>(`/api/runs/${encodeURIComponent(runId)}`),
  /** Every record of a run, fetched page by page until a short page ends the list. */
  records: async (runId: string) => {
    const records: SealedRunRecord[] = [];
    const id = encodeURIComponent(runId);
    for (;;) {
      const page = await getJson<unknown>(
        `/api/runs/${id}/records?limit=${PAGE_SIZE}&offset=${records.length}`,
      );
      if (!Array.isArray(page)) throw new Error("recorder returned a malformed record list");
      for (const item of page) {
        try {
          assertRecord(item);
        } catch (error) {
          const detail = error instanceof Error ? error.message : String(error);
          throw new Error(`recorder returned a malformed record: ${detail}`);
        }
        records.push(item);
      }
      if (page.length < PAGE_SIZE) return records;
    }
  },
  /** Stores a bundle file in the recorder. Throws with the recorder's own error text on refusal. */
  upload: async (file: File) => {
    const body = new FormData();
    body.append("file", file);
    const response = await request("/api/bundles", { method: "POST", body });
    const payload = (await response.json()) as unknown;
    if (!response.ok) throw new Error(describeError(payload));
    return payload as { bundle_id: string; runs: string[] };
  },
  /** Fetches a stored request or response body and saves it through a temporary download link. */
  downloadPayload: async (recordId: string, side: "request" | "response") => {
    const response = await request(
      `/api/records/${encodeURIComponent(recordId)}/payload/${encodeURIComponent(side)}`,
    );
    if (!response.ok) throw new Error(`payload: ${response.status}`);
    saveFile(await response.blob(), `${recordId}-${side}`);
  },
  /**
   * Exports a live run as a bundle signed by the recorder and returns it as a File named like
   * the recorder's attachment. With `end` the recorder closes the run first; with
   * `omitPayloads` the archive holds no bodies and its manifest says so. Throws with the
   * recorder's own error text on refusal.
   */
  export: async (runId: string, end = false, omitPayloads = false): Promise<File> => {
    const query = new URLSearchParams();
    if (end) query.set("end", "true");
    if (omitPayloads) query.set("payloads", "omit");
    const suffix = query.size > 0 ? `?${query.toString()}` : "";
    const path = `/api/runs/${encodeURIComponent(runId)}/export${suffix}`;
    const response = await request(path, {
      method: "POST",
    });
    if (!response.ok) throw new Error(describeError(await response.json()));
    const name = `sealedrun-${runId}${omitPayloads ? "-records" : ""}.zip`;
    return new File([await response.blob()], name, {
      type: "application/zip",
    });
  },
};

/** Saves a blob through a temporary download link. */
export function saveFile(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  URL.revokeObjectURL(url);
}

/** Extracts the message from a FastAPI-style `{ detail }` error body. */
function describeError(payload: unknown): string {
  if (payload && typeof payload === "object" && "detail" in payload) {
    const detail = (payload as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
    if (detail && typeof detail === "object" && "message" in detail) {
      return String((detail as { message: unknown }).message);
    }
  }
  return "upload failed";
}
