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

import { payloadDigest } from "./hashing.js";
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
  /**
   * Record this step follows from (SPEC 5.1), for example the proxied call whose id came back
   * in the `X-SealedRun-Record` reply header.
   */
  parentRecordId?: string;
  /**
   * The decision that allowed or altered the step (SPEC 5.7). A step that ran under
   * `require_approval` is bound to the human's answer recorded with {@link Recorder.approve}.
   */
  policy?: { rule_id: string; decision: string; reason: string; [key: string]: unknown };
}

/** Options of {@link Recorder.recordGate}. */
export interface GateOptions {
  /** `target.name` of the gate step; defaults to `gate`. */
  name?: string;
  /** Question names mapped to the figures the application compared against (SPEC 10.8). */
  thresholds?: Record<string, number>;
  /** Why the gate decided as it did. */
  reason?: string;
  /** Data labels the step carries. */
  dataLabels?: string[];
}

/** Options of {@link Recorder.approve}. */
export interface ApprovalOptions {
  /** Who decided; becomes `actor.id` of the `human_approval` record. */
  actorId: string;
  /** The human's remark. */
  note?: string;
  /** Provider of the system the decision concerns. */
  provider?: string;
  /** Location of that system; defaults to `local`. */
  location?: Target["location"];
  /** Data labels the step carries. */
  dataLabels?: string[];
}

/** A human's answer to a step that required approval (SPEC 10.10). */
export type ApprovalDecision = "granted" | "denied";

/** What an application did with a decision-model verdict (SPEC 10.8). */
export type GateOutcome = "approve" | "block" | "review";

const GATE_OUTCOMES: Record<GateOutcome, string> = {
  approve: "success",
  block: "blocked",
  review: "pending",
};

/** Options of {@link Recorder.record}: a finished step with its payloads and outcome. */
export interface RecordOptions extends StepOptions {
  /** Request payload: a string is stored as text, anything else as JSON. */
  request?: unknown;
  /** Response payload: a string is stored as text, anything else as JSON. */
  response?: unknown;
  /** Outcome of the step; defaults to `success`. */
  outcome?: string;
  /** The changed system's own proof of the step (SPEC 10.9), from {@link receiptFor}. */
  receipt?: Record<string, unknown>;
  /**
   * System instructions of an `llm_call`; the recorder keeps only their digest
   * (`sealedrun.llm.system_prompt_hash`, SPEC 10.1).
   */
  systemPrompt?: string;
}

/** Kinds of a `sealedrun.receipt` (SPEC 10.9). */
export type ReceiptKind = "http_response" | "git_commit" | "file_hash" | "db_tx" | "opaque";

/** What the changed system returned, for {@link receiptFor}. */
export interface ReceiptOptions {
  /** Commit sha, file path, transaction id. */
  ref?: string;
  /** Bytes whose SHA-256 digest the receipt carries: the response body, the file after the write. */
  data?: Uint8Array;
  /** Host or service name of the system. */
  issuer?: string;
  /** HTTP status of the reply. */
  status?: number;
}

/**
 * Builds a `sealedrun.receipt` (SPEC 10.9) from what the changed system returned;
 * {@link Recorder.record} marks it `self_reported`.
 */
export function receiptFor(
  kind: ReceiptKind,
  options: ReceiptOptions = {},
): Record<string, unknown> {
  const receipt: Record<string, unknown> = { kind };
  if (options.ref !== undefined) receipt["ref"] = options.ref;
  if (options.data !== undefined) {
    receipt["digest"] = payloadDigest("sha-256", options.data);
    receipt["digest_alg"] = "sha-256";
  }
  if (options.issuer !== undefined) receipt["issuer"] = options.issuer;
  if (options.status !== undefined) receipt["status"] = options.status;
  return receipt;
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
  /**
   * The `X-SealedRun-Parent` value this agent received with the request it is working on
   * (SPEC 6.4), `<run_id>/<record_id>/<delegation_hash>`; the recorder writes it into the run it
   * opens for these steps.
   */
  parent?: string;
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
    const withReceipt = options.receipt
      ? {
          ...options,
          extensions: {
            ...(options.extensions ?? {}),
            "sealedrun.receipt": { ...options.receipt, observed_by: "self_reported" },
          },
        }
      : options;
    const body = stepBody(kind, target(kind, name, options), withReceipt, {
      request: options.request,
      response: options.response,
      outcome: options.outcome ?? "success",
    });
    if (options.systemPrompt !== undefined) body["system_prompt"] = options.systemPrompt;
    return this.post(body);
  }

  /**
   * Record a human's answer to a step that required approval (SPEC 6.6, 10.10).
   *
   * @param name - The system the decision concerns (`target.name`).
   * @param request - The very request the human was shown; pass the same value to
   *   {@link Recorder.record} for the step that then runs, so both hash alike and the verifier
   *   binds them.
   * @param decision - `granted` or `denied`.
   * @param options - Who decided, their note, target details and labels.
   */
  async approve(
    name: string,
    request: unknown,
    decision: ApprovalDecision,
    options: ApprovalOptions,
  ): Promise<Record<string, unknown>> {
    if (decision !== "granted" && decision !== "denied") {
      throw new RecorderError("decision must be granted or denied");
    }
    const answer: Record<string, unknown> = { decision };
    if (options.note) answer["note"] = options.note;
    return this.record("human_approval", name, {
      request,
      ...(options.provider ? { provider: options.provider } : {}),
      location: options.location ?? "local",
      ...(options.dataLabels ? { dataLabels: options.dataLabels } : {}),
      actor: { type: "human", id: options.actorId },
      extensions: { "sealedrun.approval": answer },
    });
  }

  /**
   * Record what the application did with a decision-model verdict (SPEC 10.8): a
   * `policy_decision` step whose parent is the `llm_call` carrying the answers.
   *
   * @param decisionRecordId - The decision call's record id, from its `X-SealedRun-Record` reply header.
   * @param outcome - `approve`, `block` or `review`; the step's own outcome follows it.
   * @param options - Thresholds compared, reason, name and labels.
   */
  async recordGate(
    decisionRecordId: string,
    outcome: GateOutcome,
    options: GateOptions = {},
  ): Promise<Record<string, unknown>> {
    const stepOutcome = GATE_OUTCOMES[outcome];
    if (stepOutcome === undefined) throw new Error("outcome must be approve, block or review");
    const gate: Record<string, unknown> = { outcome };
    if (options.thresholds && Object.keys(options.thresholds).length > 0) {
      gate["thresholds"] = { ...options.thresholds };
    }
    if (options.reason) gate["reason"] = options.reason;
    const step: RecordOptions = {
      outcome: stepOutcome,
      extensions: { "sealedrun.gate": gate },
      parentRecordId: decisionRecordId,
    };
    if (options.dataLabels) step.dataLabels = options.dataLabels;
    return this.record("policy_decision", options.name ?? "gate", step);
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
    if (this.options.parent) headers["X-SealedRun-Parent"] = this.options.parent;
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
  if (options.parentRecordId) body["parent_record_id"] = options.parentRecordId;
  if (options.policy) body["policy"] = options.policy;
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
