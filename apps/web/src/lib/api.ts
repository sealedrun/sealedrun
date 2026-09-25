import type { SealedRunRecord } from "@sealedrun/core";

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
}

const PAGE_SIZE = 1000;
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
  /** All runs stored in the recorder. */
  runs: () => getJson<RunSummary[]>("/api/runs"),
  /** Every record of a run, fetched page by page until a short page ends the list. */
  records: async (runId: string) => {
    const records: SealedRunRecord[] = [];
    for (;;) {
      const page = await getJson<SealedRunRecord[]>(
        `/api/runs/${runId}/records?limit=${PAGE_SIZE}&offset=${records.length}`,
      );
      records.push(...page);
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
    const response = await request(`/api/records/${recordId}/payload/${side}`);
    if (!response.ok) throw new Error(`payload: ${response.status}`);
    saveFile(await response.blob(), `${recordId}-${side}`);
  },
  /**
   * Exports a live run as a bundle signed by the recorder and returns it as a File named like
   * the recorder's attachment. With `end` the recorder closes the run first. Throws with the
   * recorder's own error text on refusal.
   */
  export: async (runId: string, end = false): Promise<File> => {
    const response = await request(`/api/runs/${runId}/export${end ? "?end=true" : ""}`, {
      method: "POST",
    });
    if (!response.ok) throw new Error(describeError(await response.json()));
    return new File([await response.blob()], `sealedrun-${runId}.zip`, {
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
