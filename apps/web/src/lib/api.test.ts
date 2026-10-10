import { afterEach, describe, expect, test, vi } from "vitest";

import { api, runQueryString, setToken } from "./api";

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

  test("asks for a bundle without payloads and names the file so", async () => {
    setToken("t0k");
    const fetchMock = vi.fn(async () => new Response(new Uint8Array([80, 75]), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);
    const file = await api.export("run-1", false, true);
    const [url] = fetchMock.mock.calls[0] as unknown as [string];
    expect(url).toBe("/api/runs/run-1/export?payloads=omit");
    expect(file.name).toBe("sealedrun-run-1-records.zip");
    const both = await api.export("run-1", true, true);
    expect((fetchMock.mock.calls[1] as unknown as [string])[0]).toBe(
      "/api/runs/run-1/export?end=true&payloads=omit",
    );
    expect(both.name).toBe("sealedrun-run-1-records.zip");
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

describe("api.runs", () => {
  test("sends the filters and reads the total from the header", async () => {
    setToken("t0k");
    const fetchMock = vi.fn(
      async () => new Response("[]", { status: 200, headers: { "x-total-count": "362" } }),
    );
    vi.stubGlobal("fetch", fetchMock);
    const page = await api.runs({
      q: " ab ",
      complete: false,
      source: "live",
      limit: 25,
      offset: 50,
    });
    const [url] = fetchMock.mock.calls[0] as unknown as [string];
    expect(url).toBe("/api/runs?q=ab&complete=false&source=live&limit=25&offset=50");
    expect(page).toEqual({ runs: [], total: 362 });
    expect(runQueryString({})).toBe("");
    expect(runQueryString({ q: "  ", offset: 0 })).toBe("");
  });
  test("falls back to the page length when the header is missing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response("[{}]", { status: 200 })),
    );
    expect((await api.runs()).total).toBe(1);
  });
});

describe("api.records", () => {
  test("encodes the run id and refuses malformed records", async () => {
    const calls: string[] = [];
    vi.stubGlobal("fetch", async (input: string) => {
      calls.push(input);
      return new Response(JSON.stringify([{ record_id: "r", seq: 0 }]), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    });
    await expect(api.records("../x?y")).rejects.toThrow("malformed record");
    expect(calls[0]).toContain("/api/runs/..%2Fx%3Fy/records");
  });
});
