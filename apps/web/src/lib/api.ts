import type { SealedRunRecord } from "@sealedrun/core";

export interface RunSummary {
  run_id: string;
  bundle_id: string;
  agent_id: string;
  principal_id: string;
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

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { headers: { accept: "application/json" } });
  if (!response.ok) throw new Error(`${path}: ${response.status}`);
  return (await response.json()) as T;
}

export const api = {
  health: () => getJson<{ status: string }>("/api/health"),
  runs: () => getJson<RunSummary[]>("/api/runs"),
  records: (runId: string) => getJson<SealedRunRecord[]>(`/api/runs/${runId}/records`),
  upload: async (file: File) => {
    const body = new FormData();
    body.append("file", file);
    const response = await fetch("/api/bundles", { method: "POST", body });
    const payload = (await response.json()) as unknown;
    if (!response.ok) throw new Error(describeError(payload));
    return payload as { bundle_id: string; runs: string[] };
  },
  payloadUrl: (recordId: string, side: "request" | "response") =>
    `/api/records/${recordId}/payload/${side}`,
};

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
