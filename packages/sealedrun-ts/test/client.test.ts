import { createServer, type Server } from "node:http";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { Recorder, RecorderError } from "../src/index.js";

type Post = { headers: Record<string, string>; body: Record<string, unknown> };

let server: Server;
let url: string;
let posts: Post[];
let status = 201;

beforeEach(async () => {
  posts = [];
  status = 201;
  server = createServer((req, res) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => {
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) headers[k] = String(v);
      posts.push({ headers, body: JSON.parse(data) });
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify(
          status < 400
            ? { record_id: "r-1", seq: posts.length }
            : { detail: "record would not verify" },
        ),
      );
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("no port");
  url = `http://127.0.0.1:${address.port}`;
});

afterEach(async () => {
  await new Promise<void>((resolve) => server.close(() => resolve()));
});

describe("Recorder", () => {
  test("a redirect is refused, the token never travels", async () => {
    const lure = createServer((_req, res) => {
      res.writeHead(307, { Location: `${url}/api/steps` });
      res.end();
    });
    await new Promise<void>((resolve) => lure.listen(0, "127.0.0.1", resolve));
    const address = lure.address();
    if (!address || typeof address === "string") throw new Error("no port");
    try {
      const recorder = new Recorder(`http://127.0.0.1:${address.port}`, { token: "tok" });
      await expect(recorder.record("note", "x")).rejects.toBeInstanceOf(RecorderError);
      expect(posts).toEqual([]);
    } finally {
      await new Promise<void>((resolve) => lure.close(() => resolve()));
    }
  });

  test("agent option sets the header", async () => {
    await new Recorder(url, { agent: "acme-planner/2.3.1" }).record("note", "x");
    expect(posts.at(-1)!.headers["x-sealedrun-agent"]).toBe("acme-planner/2.3.1");
    expect(() => new Recorder(url, { agent: "no version" })).toThrow("agent");
  });

  test("record posts body and headers", async () => {
    const recorder = new Recorder(url + "/", { token: "tok", run: "job-1" });
    const record = await recorder.record("tool_call", "db.query", {
      request: "select 1",
      response: { rows: [1] },
      provider: "postgres",
      dataLabels: ["pii"],
      extensions: { "acme.sql": { ms: 3 } },
    });
    expect(record).toEqual({ record_id: "r-1", seq: 1 });
    const [post] = posts;
    expect(post!.headers["authorization"]).toBe("Bearer tok");
    expect(post!.headers["x-sealedrun-run"]).toBe("job-1");
    expect(post!.body).toEqual({
      kind: "tool_call",
      target: { type: "tool", name: "db.query", location: "local", provider: "postgres" },
      outcome: "success",
      data_labels: ["pii"],
      extensions: { "acme.sql": { ms: 3 } },
      request: "select 1",
      request_media_type: "text/plain",
      response: '{"rows":[1]}',
      response_media_type: "application/json",
    });
  });

  test("target type follows the kind and options", async () => {
    const recorder = new Recorder(url);
    await recorder.record("memory_read", "vectors", { location: "cloud", endpoint: "https://v" });
    await recorder.record("llm_call", "gpt-4.1", { provider: "openai" });
    await recorder.record("human_approval", "reviewer", { actor: { type: "human", id: "alice" } });
    expect(posts.map((p) => p.body["target"])).toEqual([
      { type: "memory", name: "vectors", location: "cloud", endpoint: "https://v" },
      { type: "model", name: "gpt-4.1", location: "local", provider: "openai" },
      { type: "human", name: "reviewer", location: "local" },
    ]);
    expect(posts[2]!.body["actor"]).toEqual({ type: "human", id: "alice" });
    expect(posts[0]!.headers["authorization"]).toBeUndefined();
    expect(posts[0]!.headers["x-sealedrun-run"]).toBeUndefined();
    expect(posts[1]!.body).not.toHaveProperty("request");
  });

  test("step posts when the body returns", async () => {
    const recorder = new Recorder(url, { run: "job-2" });
    const result = await recorder.step("tool_call", "shell", async (step) => {
      step.request = ["ls", "-la"];
      expect(posts).toHaveLength(0);
      step.response = "total 0\n";
      return 42;
    });
    expect(result).toBe(42);
    expect(posts[0]!.body).toMatchObject({
      request: '["ls","-la"]',
      request_media_type: "application/json",
      response: "total 0\n",
      response_media_type: "text/plain",
      outcome: "success",
    });
  });

  test("a throwing step is recorded as error and rethrown", async () => {
    const recorder = new Recorder(url);
    await expect(
      recorder.step("tool_call", "calc", (step) => {
        step.request = { expr: "1/0" };
        throw new RangeError("division by zero");
      }),
    ).rejects.toThrow(RangeError);
    expect(posts[0]!.body).toMatchObject({
      outcome: "error",
      response: "RangeError: division by zero",
    });
  });

  test("wrap records sync and async functions", async () => {
    const recorder = new Recorder(url);
    const add = recorder.wrap((a: number, b: number) => a + b, "add");
    const fetchPage = recorder.wrap(
      async function fetchPage2(u: string) {
        return { url: u, size: 3n };
      },
      undefined,
      { provider: "http", location: "cloud" },
    );
    expect(await add(2, 3)).toBe(5);
    expect(await fetchPage("https://x")).toEqual({ url: "https://x", size: 3n });
    expect(posts[0]!.body).toMatchObject({
      target: { type: "tool", name: "add", location: "local" },
      request: "[2,3]",
      response: "5",
    });
    expect(posts[1]!.body).toMatchObject({
      target: { type: "tool", name: "fetchPage2", location: "cloud", provider: "http" },
      response: '{"url":"https://x","size":"3"}',
    });
  });

  test("wrap records a failing call", async () => {
    const recorder = new Recorder(url);
    const boom = recorder.wrap(() => {
      throw new Error("no");
    }, "boom");
    await expect(boom()).rejects.toThrow("no");
    expect(posts[0]!.body).toMatchObject({ outcome: "error", response: "Error: no" });
  });

  test("refusal and unreachable recorder throw without the token", async () => {
    status = 400;
    const recorder = new Recorder(url, { token: "secret-token" });
    const refused = await recorder.record("tool_call", "x").catch((e: unknown) => e);
    expect(refused).toBeInstanceOf(RecorderError);
    expect((refused as RecorderError).status).toBe(400);
    expect(String(refused)).toContain("would not verify");
    expect(String(refused)).not.toContain("secret-token");
    expect(() => new Recorder("http://user:secret-token@127.0.0.1:9")).toThrow(/credentials/);
    const down = new Recorder("http://127.0.0.1:9", { token: "secret-token" });
    const unreachable = await down.record("tool_call", "x").catch((e: unknown) => e);
    expect(unreachable).toBeInstanceOf(RecorderError);
    expect((unreachable as RecorderError).status).toBe(0);
    expect(String(unreachable)).not.toContain("secret-token");
  });

  test("bad url is refused", () => {
    expect(() => new Recorder("ftp://x")).toThrow(/http/);
  });
});
