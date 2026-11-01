import { createServer, type Server } from "node:http";
import { afterEach, beforeEach, describe, expect, test } from "vitest";

import { payloadDigest, Recorder, RecorderError, receiptFor } from "../src/index.js";

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

  test("parent link is sent as a header", async () => {
    const link =
      "0192b3c4-5d6e-7f80-9a1b-0000000000a7/0192b3c4-5d6e-7f80-9a1b-000000000701/" + "c".repeat(64);
    const recorder = new Recorder(url, { token: "tok", run: "job-1", parent: link });
    await recorder.record("tool_call", "x");
    expect(posts[0]!.headers["x-sealedrun-parent"]).toBe(link);
  });

  test("record with a receipt marks it self_reported", async () => {
    const recorder = new Recorder(url, { token: "tok", run: "job-1" });
    await recorder.record("tool_call", "out.txt", {
      provider: "fs",
      receipt: receiptFor("file_hash", {
        ref: "/tmp/out.txt",
        data: new TextEncoder().encode("hello"),
      }),
      extensions: { "sealedrun.mcp": { server: "fs", transport: "stdio", method: "tools/call" } },
    });
    const extensions = posts[0]!.body.extensions as Record<string, Record<string, unknown>>;
    expect(extensions["sealedrun.receipt"]).toEqual({
      kind: "file_hash",
      ref: "/tmp/out.txt",
      digest: payloadDigest("sha-256", new TextEncoder().encode("hello")),
      digest_alg: "sha-256",
      observed_by: "self_reported",
    });
    expect(extensions["sealedrun.mcp"]!["server"]).toBe("fs");
  });

  test("approve records the human answer with the request it concerns", async () => {
    const recorder = new Recorder(url, { token: "tok", run: "job-1" });
    const request = { to: "jane@example.com", body: "summary" };
    await recorder.approve("mail/send", request, "denied", {
      actorId: "jane.doe@example.com",
      note: "not today",
    });
    expect(posts[0]!.body).toEqual({
      kind: "human_approval",
      target: { type: "human", name: "mail/send", location: "local" },
      outcome: "success",
      data_labels: [],
      extensions: { "sealedrun.approval": { decision: "denied", note: "not today" } },
      actor: { type: "human", id: "jane.doe@example.com" },
      request: JSON.stringify(request),
      request_media_type: "application/json",
    });
    const policy = { rule_id: "r/approve", decision: "require_approval", reason: "external" };
    await recorder.record("tool_call", "mail/send", { request, policy });
    expect(posts[1]!.body.request).toBe(posts[0]!.body.request);
    expect(posts[1]!.body.policy).toEqual(policy);
    await expect(
      recorder.approve("mail/send", request, "maybe" as unknown as "granted", { actorId: "x" }),
    ).rejects.toThrow("granted or denied");
  });

  test("record passes the system prompt for the recorder to hash", async () => {
    const recorder = new Recorder(url, { token: "tok", run: "job-1" });
    await recorder.record("llm_call", "gpt-4.1", {
      request: { messages: [] },
      systemPrompt: "You summarise contracts.",
    });
    expect(posts[0]!.body.system_prompt).toBe("You summarise contracts.");
    await recorder.record("llm_call", "gpt-4.1", { request: { messages: [] } });
    expect(posts[1]!.body).not.toHaveProperty("system_prompt");
  });

  test("recordGate links the decision and maps the outcome", async () => {
    const recorder = new Recorder(url, { token: "tok", run: "job-1" });
    const record = await recorder.recordGate("0192b3c4-5d6e-7f80-9a1b-000000000201", "block", {
      thresholds: { touches_prod: 0.5 },
      reason: "touches_prod 0.97 above 0.5",
    });
    expect(record).toEqual({ record_id: "r-1", seq: 1 });
    expect(posts[0]!.body).toEqual({
      kind: "policy_decision",
      target: { type: "none", name: "gate", location: "local" },
      outcome: "blocked",
      data_labels: [],
      extensions: {
        "sealedrun.gate": {
          outcome: "block",
          thresholds: { touches_prod: 0.5 },
          reason: "touches_prod 0.97 above 0.5",
        },
      },
      parent_record_id: "0192b3c4-5d6e-7f80-9a1b-000000000201",
    });
    await recorder.recordGate("0192b3c4-5d6e-7f80-9a1b-000000000201", "review");
    expect(posts[1]!.body.outcome).toBe("pending");
    await expect(recorder.recordGate("x", "maybe" as unknown as "approve")).rejects.toThrow(
      "approve, block or review",
    );
  });

  test("bad url is refused", () => {
    expect(() => new Recorder("ftp://x")).toThrow(/http/);
  });
});
