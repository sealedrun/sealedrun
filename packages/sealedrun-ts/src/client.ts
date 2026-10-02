/**
 * Report steps from your own code to a running recorder.
 *
 * @remarks
 * `Recorder` posts self-reported steps to `POST /api/steps`; the recorder validates and signs
 * each one onto the live run named by the run label (the same label the proxies use), so
 * in-process actions such as SQL, files or shell commands sit in one chain with the proxied
 * model calls. Uses the global `fetch` (Node 22 and browsers).
 *
 * A step whose body throws is recorded with outcome `error` and the error is rethrown. A
 * recorder that refuses or cannot be reached throws {@link RecorderError}: the caller asked for
 * the record, so silence would be a lie.
 */

import type { Target } from "./types.js";

const JSON_TYPE = "application/json";
const AGENT = /^[A-Za-z0-9._-]{1,64}\/[A-Za-z0-9._+-]{1,32}$/;
const TARGET_TYPES: Record<string, string> = {
  llm_call: "model",
  tool_call: "tool",
  memory_read: "memory",
  memory_write: "memory",
  human_approval: "human",
  policy_decision: "none",
  note: "none",
};

/** Thrown when the recorder refuses a step or cannot be reached; `status` is the HTTP code or 0. */
export class RecorderError extends Error {
  /**
   * @param message - Human-readable detail.
   * @param status - HTTP status of the refusal, or 0 when the recorder was unreachable.
   */
  constructor(
    message: string,
    public readonly status = 0,
  ) {
    super(message);
    this.name = "RecorderError";
  }
}

/** Options shared by every way of reporting a step. */
export interface StepOptions {
  /** `target.provider`, for example `postgres` or `mcp:github`. */
  provider?: string;
  /** Where the data went; defaults to `local`. */
  location?: Target["location"];
  /** `target.endpoint`, the resolved address when there is one. */
  endpoint?: string;
  /** `target.type`; derived from the kind when omitted. */
  targetType?: string;
  /** Data labels the step carries. */
  dataLabels?: string[];
  /** Extensions of the record. */
  extensions?: Record<string, unknown>;
  /** Actor of the step; required as `{type: "human"}` for `human_approval`. */
  actor?: { type: "agent" | "human" | "system"; id: string };
}

/** Options of {@link Recorder.record}: a finished step with its payloads and outcome. */
export interface RecordOptions extends StepOptions {
  /** Request payload: a string is stored as text, anything else as JSON. */
  request?: unknown;
  /** Response payload: a string is stored as text, anything else as JSON. */
  response?: unknown;
  /** Outcome of the step; defaults to `success`. */
  outcome?: string;
}

/** The step handed to the body of {@link Recorder.step}; set its payloads before returning. */
export interface Step {
  /** Request payload. */
  request?: unknown;
  /** Response payload. */
  response?: unknown;
  /** Outcome; set to `error` automatically when the body throws. */
  outcome: string;
  /** The signed record, once posted. */
  record?: Record<string, unknown>;
}

/** Settings of a {@link Recorder}. */
export interface RecorderOptions {
  /** Recorder API token, sent as a bearer token. */
  token?: string;
  /** Run label, sent as `X-SealedRun-Run`; joins the run of proxied calls with the same label. */
  run?: string;
  /** Agent `<name>/<version>`, sent as `X-SealedRun-Agent`; lands in the run's `sealedrun.context`. */
  agent?: string;
  /** Seconds to wait for the recorder; defaults to 5. */
  timeout?: number;
  /** `fetch` to use; defaults to the global one. */
  fetch?: typeof fetch;
}

/** Post steps to one recorder under one run label. */
export class Recorder {
  readonly url: string;
  private readonly options: RecorderOptions;

  /**
   * @param url - Recorder base URL, for example `http://127.0.0.1:8080`.
   * @param options - Token, run label, timeout.
   */
  constructor(url: string, options: RecorderOptions = {}) {
    if (!/^https?:\/\//.test(url)) throw new Error("url must start with http:// or https://");
    if (/^\w+:\/\/[^/]*@/.test(url)) throw new Error("url must not carry credentials");
    if (options.agent !== undefined && !AGENT.test(options.agent)) {
      throw new Error("agent must be <name>/<version>");
    }
    this.url = url.replace(/\/+$/, "");
    this.options = options;
  }

  /**
   * Post one finished step and return the signed record.
   *
   * @param kind - Record kind, for example `tool_call`.
   * @param name - `target.name`.
   * @param options - Payloads, outcome and target details.
   */
  async record(
    kind: string,
    name: string,
    options: RecordOptions = {},
  ): Promise<Record<string, unknown>> {
    const body = stepBody(kind, target(kind, name, options), options, {
      request: options.request,
      response: options.response,
      outcome: options.outcome ?? "success",
    });
    return this.post(body);
  }

  /**
   * Run `body` with a step, then post it; an exception sets outcome `error` and is rethrown.
   *
   * @param kind - Record kind.
   * @param name - `target.name`.
   * @param body - Sets `step.request` and `step.response`; its return value is returned.
   * @param options - Target details.
   */
  async step<T>(
    kind: string,
    name: string,
    body: (step: Step) => T | Promise<T>,
    options: StepOptions = {},
  ): Promise<T> {
    const step: Step = { outcome: "success" };
    let result: T;
    try {
      result = await body(step);
    } catch (error) {
      step.outcome = "error";
      if (step.response === undefined) step.response = describe(error);
      step.record = await this.post(stepBody(kind, target(kind, name, options), options, step));
      throw error;
    }
    step.record = await this.post(stepBody(kind, target(kind, name, options), options, step));
    return result;
  }

  /**
   * Wrap a function so every call becomes a `tool_call` record.
   *
   * @param fn - Sync or async function; its arguments are the request, its result the response.
   * @param name - Tool name; defaults to the function's name.
   * @param options - Target details.
   */
  wrap<A extends unknown[], R>(
    fn: (...args: A) => R | Promise<R>,
    name?: string,
    options: StepOptions = {},
  ): (...args: A) => Promise<R> {
    const toolName = name ?? fn.name ?? "tool";
    return (...args: A) =>
      this.step(
        "tool_call",
        toolName,
        async (step) => {
          step.request = args;
          const result = await fn(...args);
          step.response = result;
          return result;
        },
        options,
      );
  }

  /**
   * Post a prepared body to `/api/steps` and return the signed record.
   *
   * @param body - JSON body as `/api/steps` expects it.
   */
  async post(body: Record<string, unknown>): Promise<Record<string, unknown>> {
    const headers: Record<string, string> = { "Content-Type": JSON_TYPE };
    if (this.options.token) headers["Authorization"] = `Bearer ${this.options.token}`;
    if (this.options.run) headers["X-SealedRun-Run"] = this.options.run;
    if (this.options.agent) headers["X-SealedRun-Agent"] = this.options.agent;
    const doFetch = this.options.fetch ?? fetch;
    let reply: Response;
    try {
      reply = await doFetch(`${this.url}/api/steps`, {
        method: "POST",
        headers,
        body: JSON.stringify(body),
        // The bearer token must not travel to a host the caller did not name.
        redirect: "error",
        signal: AbortSignal.timeout((this.options.timeout ?? 5) * 1000),
      });
    } catch (error) {
      throw new RecorderError(`recorder unreachable at ${publicUrl(this.url)}: ${describe(error)}`);
    }
    const text = await reply.text();
    if (!reply.ok) {
      throw new RecorderError(
        `recorder answered ${reply.status}: ${text.slice(0, 300)}`,
        reply.status,
      );
    }
    return (text ? JSON.parse(text) : {}) as Record<string, unknown>;
  }
}

function target(kind: string, name: string, options: StepOptions): Target {
  const out: Target = {
    type: options.targetType ?? TARGET_TYPES[kind] ?? "tool",
    name,
    location: options.location ?? "local",
  };
  if (options.provider) out.provider = options.provider;
  if (options.endpoint) out.endpoint = options.endpoint;
  return out;
}

function stepBody(
  kind: string,
  targetValue: Target,
  options: StepOptions,
  step: { request?: unknown; response?: unknown; outcome: string },
): Record<string, unknown> {
  const body: Record<string, unknown> = {
    kind,
    target: targetValue,
    outcome: step.outcome,
    data_labels: options.dataLabels ?? [],
    extensions: options.extensions ?? {},
  };
  if (options.actor) body["actor"] = options.actor;
  for (const [side, value] of [
    ["request", step.request],
    ["response", step.response],
  ] as const) {
    if (value === undefined || value === null) continue;
    if (typeof value === "string") {
      body[side] = value;
      body[`${side}_media_type`] = "text/plain";
    } else {
      body[side] = JSON.stringify(value, replacer) ?? String(value);
      body[`${side}_media_type`] = JSON_TYPE;
    }
  }
  return body;
}

function replacer(_key: string, value: unknown): unknown {
  if (typeof value === "bigint") return value.toString();
  if (typeof value === "function" || typeof value === "symbol") return String(value);
  return value;
}

function describe(error: unknown): string {
  if (error instanceof Error) return `${error.name}: ${error.message}`;
  return String(error);
}

function publicUrl(url: string): string {
  return url.replace(/^(\w+:\/\/)[^@/]*@/, "$1");
}
