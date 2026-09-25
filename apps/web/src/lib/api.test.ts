import { afterEach, describe, expect, test, vi } from "vitest";

import { api, setToken } from "./api";

const store = new Map<string, string>();
vi.stubGlobal("sessionStorage", {
  getItem: (k: string) => store.get(k) ?? null,
  setItem: (k: string, v: string) => void store.set(k, v),
  removeItem: (k: string) => void store.delete(k),
});

afterEach(() => {
  vi.unstubAllGlobals();
  store.clear();
});

describe("api.export", () => {
  test("posts with the token and returns the zip as a named File", async () => {
    setToken("t0k");
    const fetchMock = vi.fn(async () => new Response(new Uint8Array([80, 75]), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const file = await api.export("run-1", true);
    const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe("/api/runs/run-1/export?end=true");
    expect(init.method).toBe("POST");
    expect(new Headers(init.headers).get("authorization")).toBe("Bearer t0k");
    expect(file.name).toBe("sealedrun-run-1.zip");
    expect(file.type).toBe("application/zip");
    expect(file.size).toBe(2);
  });

  test("surfaces the recorder's refusal text", async () => {
    vi.stubGlobal("fetch", async () => Response.json({ detail: "imported run" }, { status: 409 }));
    await expect(api.export("run-2")).rejects.toThrow("imported run");
  });

  test("a 401 becomes UnauthorizedError", async () => {
    vi.stubGlobal("fetch", async () => new Response(null, { status: 401 }));
    await expect(api.export("run-3")).rejects.toThrow("recorder requires a token");
  });
});
