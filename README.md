# SealedRun

A tamper-evident, signed record of every step an AI agent takes. Every step an agent takes — model call, MCP tool
call, memory access, policy decision, human approval — becomes a signed record in an append-only
hash chain. Records are exported as an evidence bundle that anyone can verify offline, without
trusting the operator.

Status: early development. 0.3.0 records every channel of an agent: LLM proxy (OpenAI, Anthropic,
Ollama and Gemini wire formats), MCP servers (HTTP proxy and stdio wrapper), A2A agents, self-reported
steps from the SDKs and OpenTelemetry GenAI spans, anchored in Sigstore Rekor and RFC 3161 witnesses
that both verifiers check offline, after a security pass over the whole surface.

## Why

Agent observability tools store traces in databases the operator can edit. When a regulator,
insurer or counterparty asks "what did your agent send to which model, and who allowed it", an
editable log is a claim, not evidence. SealedRun turns each step into a signed link of a hash chain
bound to a delegation from the accountable party, anchored in an external witness, and exported
as a bundle that any third party verifies offline.

## How it works

1. A **Principal** (the accountable organisation) signs a **Delegation** for an **Agent** key set.
2. Every step of a **Run** becomes a **Record**: kind, target and its location (local or cloud),
   payload digests, data labels, policy decision and reason, `prev_hash`, `hash`, and a hybrid
   Ed25519 + ML-DSA-65 signature by the Agent.
3. The chain head is periodically **anchored** in an external witness (Sigstore Rekor, RFC 3161).
4. Records, delegations, optional payload bodies and a signed manifest are exported as a
   **Bundle**. The verifier recomputes everything and reports the first failing check and seq.

Read [SPEC.md](SPEC.md) for the format and [TRUST.md](TRUST.md) for what a bundle proves.

## Five minutes to a verified run

```bash
git clone https://github.com/sealedrun/sealedrun && cd sealedrun
SEALEDRUN_API_TOKEN=change-me docker compose up -d                # recorder + Inspector on :8080
cd examples/langgraph-mcp && uv sync && SEALEDRUN_TOKEN=change-me uv run agent.py
```

The agent (LangGraph `create_agent`) asks a model what `notes.txt` is about; the model goes
through the recorder's proxy and the filesystem MCP server runs under `sealedrun-mcp-wrap`, so
model and tool calls land in one run. Export it and verify it with the CLI, `@sealedrun/core`
or the Inspector at http://127.0.0.1:8080; the walk-through is in
[examples/langgraph-mcp](examples/langgraph-mcp/README.md). The compose file mounts
`upstreams.yaml` (Ollama on the host at `host.docker.internal`, which needs
`OLLAMA_HOST=0.0.0.0`, and OpenAI with `OPENAI_API_KEY`); edit it for your providers.

## Quick start (Python)

```python
from sealedrun import PrivateKeySet, RunWriter, create_delegation, payload_ref, verify_run

principal = PrivateKeySet.generate()
agent = PrivateKeySet.generate()
delegation = create_delegation(principal, agent.public, agent_name="demo")

run = RunWriter(agent, delegation)
run.start()
run.append(
    "llm_call",
    target={"type": "model", "name": "gpt-4.1", "location": "cloud", "provider": "openai"},
    payload=payload_ref("sha-256", b'{"messages": []}', b'{"choices": []}'),
    data_labels=["pii"],
    policy={"rule_id": "default", "decision": "allow", "reason": "no rule matched"},
)
run.end()

report = verify_run(run.records, {delegation["delegation_id"]: delegation})
print(report.complete, report.labels_sent_to_cloud)
```

## Layout

| Path                     | What                                                                                         | License    |
| ------------------------ | -------------------------------------------------------------------------------------------- | ---------- |
| `SPEC.md`                | The SealedRun format specification                                                           | CC-BY-4.0  |
| `TRUST.md`               | What a bundle proves and what it does not (threat model)                                     | CC-BY-4.0  |
| `spec/schema/`           | JSON Schema for records, delegations and bundles                                             | Apache-2.0 |
| `spec/vectors/`          | Known-answer test vectors for independent implementations                                    | Apache-2.0 |
| `spec/examples/`         | Example records and an example bundle                                                        | Apache-2.0 |
| `packages/sealedrun-py/` | Reference Python implementation (`sealedrun` on PyPI)                                        | Apache-2.0 |
| `packages/sealedrun-ts/` | TypeScript verification library (`@sealedrun/core`), used by the web UI                      | Apache-2.0 |
| `services/recorder/`     | FastAPI service: bundle upload and verification API, hosts the UI (proxy arrives in stage 1) | Apache-2.0 |
| `apps/web/`              | Next.js UI: bundle inspector and verifier                                                    | Apache-2.0 |

## Install

```bash
pip install sealedrun              # Python library: write, read and verify records and bundles
npm install @sealedrun/core        # TypeScript verifier, runs in Node.js and in the browser
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/sealedrun/sealedrun:0.3.0   # recorder + Inspector
```

Releases are published from GitHub Actions through PyPI and npm trusted publishing; both registries
show the provenance attestation that links a package to the commit and workflow that built it.

## Cryptography

- Canonicalization: JSON Canonicalization Scheme (RFC 8785).
- Hash chain: SHA-256 by default, SHA-384 allowed (`hash_alg`).
- Signatures: hybrid, every record carries both an Ed25519 and an ML-DSA-65 (FIPS 204) signature.
  Verifiers require both to be valid.
- Anchors: chain heads time-stamped by an RFC 3161 authority and published to a Sigstore Rekor
  transparency log; receipts are verified offline against a witness trust list (see Anchoring).

## Run with Docker

```bash
docker compose up -d                      # SQLite in the sealedrun-data volume, UI and API on :8080
docker compose --profile postgres up -d   # with PostgreSQL; set SEALEDRUN_DATABASE_URL, see .env.example
```

Open http://localhost:8080, drop a bundle (for example `spec/examples/bundle.zip`) and the browser
verifies it. "Store in recorder" keeps it on the server.

Upgrading keeps the data: at start the recorder adds the columns a database written by an earlier
release lacks (SQLite and PostgreSQL) and logs what it added. Going back to an older image on the
same volume is not supported.

> **No authentication by default.** The recorder listens on `127.0.0.1` only and compose publishes
> the port to localhost. Before exposing it to a network, set `SEALEDRUN_API_TOKEN` to a long random
> value and put TLS in front. Clients send `Authorization: Bearer <token>`; the Inspector asks for
> the token and keeps it for the current tab only. `/api/health` stays open.
>
> **A bundle carries its own keys, so "it verifies" is not "it is genuine".** Get the signer's
> `principal_id` from the signer, not from the bundle, and give it to the verifier:
> `verify_bundle(bundle, trusted_principals=[...])` in Python, `verifyBundle(bundle, { trustedPrincipals })`
> in TypeScript, the "Trusted principal ids" box in the Inspector, or
> `SEALEDRUN_TRUSTED_PRINCIPALS='["<principal_id>"]'` for the recorder, which then refuses bundles
> from anyone else. Without it a report says `principal_trusted: false`: integrity, not origin.
>
> The recorder answers only to the Host names in `SEALEDRUN_ALLOWED_HOSTS` (default
> `["127.0.0.1", "localhost"]`; add your public name when you expose it; a proxy in front of it
> must forward the browser's name in `X-Forwarded-Host`, which is held to the same list).
> Uploads are accepted from the Inspector's own origin (`Sec-Fetch-Site: same-origin`; a sibling subdomain does not count),
> or from a script that presents the token; a request a foreign web page makes your browser send
> is refused. Errors the proxy returns to a client never name the upstream, its key variable or
> the failure class; that detail goes to the recorder's log, and the access log drops query
> strings, so a `?key=` token never lands in a log line.

## Record live traffic and export it

The recorder is also an LLM proxy. Point an agent's SDK at it, and every model call becomes a
signed record in a live run; export the run as a bundle at any time.

```bash
cp services/recorder/upstreams.example.yaml upstreams.yaml   # keep the upstreams you use
export SEALEDRUN_API_TOKEN=change-me OPENAI_API_KEY=sk-...
SEALEDRUN_UPSTREAMS_FILE=./upstreams.yaml uv run sealedrun-recorder
```

```bash
OPENAI_BASE_URL=http://127.0.0.1:8080/v1 OPENAI_API_KEY=change-me python agent.py   # the token goes where the key went
curl -s -H "Authorization: Bearer change-me" http://127.0.0.1:8080/api/runs | jq '.[0].run_id'
curl -s -X POST -H "Authorization: Bearer change-me" \
  "http://127.0.0.1:8080/api/runs/<run_id>/export?end=true" -o run.zip     # end=true closes the run first
```

The upstreams file is read once at start; edit it, then restart the recorder. A call the proxy
cannot route (no upstream for the model, or the model is reachable only through another wire
format) is answered 400/404 and leaves no record: nothing was sent to a model. In Docker, a
recorder that must reach Ollama on the same box needs host networking, because Ollama listens on
127.0.0.1 only: `network_mode: host` plus `SEALEDRUN_HOST=127.0.0.1` (and drop `ports:`), or start
Ollama with `OLLAMA_HOST=0.0.0.0` and point the upstream at `host.docker.internal:11434` with
`extra_hosts: ["host.docker.internal:host-gateway"]`. A bind-mounted `upstreams.yaml` is read
from the mounted inode, so replace its content in place rather than swapping the file.

`run.zip` verifies with `verify_bundle`, `verifyBundle` or the Inspector like any bundle; the
recorder's `principal_id` is at `/api/identity`. Anthropic, Ollama and Gemini SDKs use their own
base-URL setting (`ANTHROPIC_BASE_URL`, `OLLAMA_HOST`, Gemini `http_options.base_url`). Calls
that send the same `X-SealedRun-Run` header share a run until it has been idle for
`SEALEDRUN_PROXY_RUN_IDLE_SECONDS` (900), like the unlabelled run; the Inspector's "Runs in the recorder"
tab lists live runs as they grow and has the Export buttons. Details in `CHANGELOG.md`.

Claude Code on a Pro/Max login needs no API key: mark the Anthropic upstream
`client_auth: passthrough` and send the recorder token in its own header, so the login token
reaches Anthropic and the recorder token stays behind the proxy.

```bash
export ANTHROPIC_BASE_URL=http://127.0.0.1:8080
export ANTHROPIC_CUSTOM_HEADERS="X-SealedRun-Token: $SEALEDRUN_API_TOKEN"
claude
```

Codex speaks the Responses API; give it a provider in `~/.codex/config.toml` and the token in
`SEALEDRUN_TOKEN`:

```toml
model_provider = "sealedrun"

[model_providers.sealedrun]
name = "SealedRun"
base_url = "http://127.0.0.1:8080/v1"
env_key = "SEALEDRUN_TOKEN"
wire_api = "responses"
```

Coding agents on Ollama send prompts of 10k tokens and more, while Ollama may run a model with a
smaller context and cut the prompt silently, tool definitions included. Raise it with
`OLLAMA_CONTEXT_LENGTH` or a model alias with `PARAMETER num_ctx 16384`.

### MCP servers

MCP servers that speak Streamable HTTP go behind the same recorder, listed under `mcp_servers` in
the upstreams file and reached at `/mcp/<name>`:

```yaml
mcp_servers:
  - name: github
    url: https://api.githubcopilot.com/mcp/
    key_env: GITHUB_MCP_TOKEN # sent as a bearer token unless auth says otherwise
    location: cloud
```

`tools/call`, `resources/read`, `prompts/get` and `tools/list` become `tool_call` records in the
same run as the model calls when they carry the same `X-SealedRun-Run` label (or none).
`tools/list` is recorded once per run and server until its result changes. Everything else passes
through unrecorded: notifications, `initialize`, `server/discover`, `subscriptions/listen`, GET
streams, DELETE, and requests the server refused. Both protocol eras pass through unchanged: the
stateless 2026-07-28 one and the session-based 2025-03-26 to 2025-11-25 one. Three shapes are
refused with 400 and never forwarded, because they could slip a call past the record and the
policy rule: a JSON-RPC batch, a request whose `id` is not a string or an integer, and a recorded
method sent without an `id`. Errors the proxy itself generates are JSON-RPC error objects with
the application code `40000` (`40003` when the policy rule refused the call).

```bash
claude mcp add --transport http github http://127.0.0.1:8080/mcp/github \
  --header "X-SealedRun-Token: $SEALEDRUN_API_TOKEN" --header "X-SealedRun-Run: my-task"
```

```toml
# ~/.codex/config.toml
[mcp_servers.github]
url = "http://127.0.0.1:8080/mcp/github"
bearer_token_env_var = "SEALEDRUN_TOKEN"
http_headers = { "X-SealedRun-Run" = "my-task" }
default_tools_approval_mode = "approve" # codex exec cannot ask; interactive Codex can
```

#### MCP servers over stdio

A server the client launches as a subprocess is wrapped instead of proxied. `sealedrun-mcp-wrap`
comes with `pip install sealedrun`, starts the real server, relays its stdin and stdout unchanged
and posts each `tools/call`, `resources/read`, `prompts/get` and `tools/list` to the recorder as a
`tool_call` record (`transport: stdio`) before the reply reaches the client. The rules are the
ones of the HTTP proxy; the server's stderr and exit code pass through. The recorder address and
token come from `--url` / `SEALEDRUN_URL` and `SEALEDRUN_TOKEN` or `--token-file` (never a
command-line token: `/proc` shows it to every local user); `--run` (or
`SEALEDRUN_RUN`) is the same label as `X-SealedRun-Run`, so the tool calls land in the run of the
model calls. A recorder that cannot be reached does not stop the call: the reply is delivered and
a warning goes to stderr; with `--strict` the client gets a JSON-RPC error instead. The wrapper
keeps at most 1024 open requests (older ones are recorded as truncated), relays a line above 16 MB
in pieces without recording it (warning), and gives a recorder post up to `--timeout` seconds in
total before it gives up. POSIX only.

```bash
claude mcp add --env SEALEDRUN_TOKEN=$SEALEDRUN_API_TOKEN --transport stdio fs -- \
  sealedrun-mcp-wrap --server fs --run my-task -- npx -y @modelcontextprotocol/server-filesystem .
```

```toml
# ~/.codex/config.toml
[mcp_servers.fs]
command = "sealedrun-mcp-wrap"
args = ["--server", "fs", "--run", "my-task", "--", "npx", "-y", "@modelcontextprotocol/server-filesystem", "."]
env = { SEALEDRUN_TOKEN = "..." }
```

Any integration can post its own steps the same way: `POST /api/steps` (bearer token, optional
`X-SealedRun-Run`) or `POST /api/runs/<id>/steps` takes a JSON body with `kind`, `target`,
`actor`, `outcome`, `policy`, `data_labels`, `extensions` and the payload bodies as `request` /
`response` text or `request_base64` / `response_base64`, validates the whole record against the
schema before sealing it and returns the signed record; the recorder sets `occurred_at`. Every
such record carries `extensions["sealedrun.step"] = {"source": "self_reported"}` (SPEC 10.5): it is
the caller's own account, and the Inspector tags it "self-reported". A step cannot carry the
extensions only the recorder writes (`sealedrun.proxy`, `sealedrun.otel`, `sealedrun.anchor`,
`sealedrun.delegation`, ...) and its label sources are limited to `manual` and `header`; run
summaries count the labels of self-reported cloud steps in `labels_self_reported`, apart from
`labels_sent_to_cloud`, which only counts what the recorder itself saw leave.

### A2A agents

Agents that speak A2A 1.0 go behind the recorder too, listed under `a2a_agents` in the
upstreams file (same fields as `mcp_servers`; `url` is the agent's JSON-RPC endpoint from its
card) and reached at `/a2a/<name>`. The proxy serves `/a2a/<name>/.well-known/agent-card.json`
with the interface URLs rewritten to itself, so an SDK client that discovers the agent there
keeps talking through the recorder; a signed card no longer matches its signature after the
rewrite, so verify the original directly when that matters. `SendMessage`, `SendStreamingMessage`
and `CancelTask` (and the REST `message:send`, `message:stream`, `tasks/{id}:cancel`) become
`tool_call` records with `sealedrun.a2a` (task, context and message ids, last task state); the
outcome follows the task state (`COMPLETED` success, `FAILED` / `REJECTED` / `CANCELED` error,
`INPUT_REQUIRED` and other open states pending). The A2A 0.3 names `message/send`,
`message/stream` and `tasks/cancel` are recorded the same way. To a `local` agent, `GetTask`,
`ListTasks`, `SubscribeToTask` and push-notification configs pass through unrecorded. To a
`cloud` agent every POST, PUT and PATCH is recorded and governed by the policy rule, whatever its
method or sub-path (the record names it, for example `GetTask` or `PUT /tasks/t-1/
pushNotificationConfigs/c-1`), so no body can leave for a cloud agent unseen; a cloud request the
proxy cannot read (not a JSON object, a batch, an `id` that is not a string or an integer) is
refused with 400. A sub-path with `.` or `..` segments or percent-encoded delimiters is refused
for every agent. Proxy-generated JSON-RPC errors carry the application code `40000`.

```yaml
a2a_agents:
  - name: planner
    url: http://127.0.0.1:9999/
    location: local
```

```python
card = await A2ACardResolver(http, "http://127.0.0.1:8080/a2a/planner").get_agent_card()
```

### Report steps from your own code

Actions an agent takes inside its own process (SQL, files, shell, HTTP) never pass a proxy.
Report them with the SDKs; the recorder validates and signs each step onto the run named by the
label, next to the proxied model calls. Python (`pip install sealedrun`, standard library only):

```python
from sealedrun import Recorder

recorder = Recorder("http://127.0.0.1:8080", token="...", run="my-task")

with recorder.step("tool_call", "db.query", provider="postgres") as step:
    step.request = sql
    step.response = rows  # anything JSON-serialisable, or text/bytes


@recorder.tool("fetch_page", location="cloud")
def fetch_page(url: str) -> str: ...  # arguments and return value are recorded
```

TypeScript (`npm install @sealedrun/core`, Node 22):

```ts
import { Recorder } from "@sealedrun/core";

const recorder = new Recorder("http://127.0.0.1:8080", { token: "...", run: "my-task" });
await recorder.step(
  "tool_call",
  "db.query",
  async (step) => {
    step.request = sql;
    step.response = await db.query(sql);
  },
  { provider: "postgres" },
);
const fetchPage = recorder.wrap(fetchPageImpl, "fetch_page", { location: "cloud" });
```

A step whose body throws is recorded with outcome `error` and the error is rethrown. A recorder
that refuses a step (schema) or cannot be reached raises `RecorderError`; unlike the MCP wrapper
there is no fail-open, because the caller asked for the record.

### OpenTelemetry spans

Frameworks that already emit OpenTelemetry GenAI spans (LangChain and LangGraph through
`opentelemetry-instrumentation-langchain`, the OpenAI Agents SDK, LangSmith's OTel export) can
send them straight to the recorder: point an OTLP/HTTP exporter at `POST /otlp/v1/traces`
(binary protobuf or JSON, gzip accepted) with the recorder token in a header.

```bash
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=http://127.0.0.1:8080/otlp/v1/traces
export OTEL_EXPORTER_OTLP_HEADERS="X-SealedRun-Token=$SEALEDRUN_API_TOKEN,X-SealedRun-Run=my-task"
```

`execute_tool` spans become `tool_call` records (tool name, `gen_ai.tool.call.arguments` and
`gen_ai.tool.call.result` as payloads), model spans (`chat`, `embeddings`, ...) become `llm_call`
records with `sealedrun.llm` from the `gen_ai.*` attributes, memory operations `memory_read` /
`memory_write`; other spans are dropped. The spans of one trace land in one run: the
`X-SealedRun-Run` header, else the trace id (`gen_ai.conversation.id` is kept on the record but
cannot group, because batch exporters send child spans before the agent span that carries it).
Ollama, llama.cpp and vLLM providers are `local`, the OTel-listed cloud providers `cloud`,
anything else `unknown`. A span with status
`ERROR` gives outcome `error`; a span whose record would not verify is counted in the OTLP
`partial_success` reply and skipped; a re-sent span is recorded once. SPEC 11 has the mapping.

Servers that log users in with OAuth cannot do that through the proxy: their tokens are bound to
the server's own URL, and clients refuse the discovery answer for a different address. Give such
a server a static token (`key_env`, for example a GitHub personal access token), or mark it
`client_auth: passthrough` and let the client send its own `Authorization` header next to
`X-SealedRun-Token`. Otherwise connect the client to the server directly; those calls are not
recorded.

### Anchoring

A run's own keys prove that nothing changed after signing. They cannot prove _when_ a record
existed, or that the operator did not rewrite the whole run and sign it again. Anchoring closes
that gap: every ten minutes, and again on export, the recorder sends the current chain head to a
witness the operator does not control and stores the witness's receipt as a signed `anchor`
record in the chain (SPEC 8). Two witness types are supported and can run together:

- `rfc3161`: a time-stamp authority signs the head with the current time. The token is
  verifiable offline against the authority's root certificate and carries the time.
- `rekor`: the head is published to a Sigstore Rekor v1 transparency log, an append-only public
  log; the receipt holds the entry, its inclusion proof and the log's signed checkpoint. The
  recorder signs the head with a P-256 anchoring key it keeps next to its other keys
  (`keys/anchor.pem`, public part in `GET /api/identity`); that key carries no identity claim,
  the chain does.

Anchoring is off by default. Turn it on with URLs:

```bash
SEALEDRUN_ANCHOR_TSA_URL=https://timestamp.sigstore.dev/api/v1/timestamp   # free, run by Sigstore
SEALEDRUN_ANCHOR_TSA_FALLBACK_URL=http://timestamp.digicert.com            # tried when the first fails
SEALEDRUN_ANCHOR_REKOR_URL=https://rekor.sigstore.dev                        # public transparency log
SEALEDRUN_ANCHOR_INTERVAL_SECONDS=600                                        # default
```

A witness that is down never blocks a run: the recorder retries once, tries the fallback, then
logs the failure and carries on; the next cycle anchors the head that moved. Run summaries show
`last_anchor_at`. Note that the log is public: the chain head (a hash) and the anchoring public
key become visible to anyone, nothing else does.

Verifiers check the receipts offline. `verify_run` / `verify_bundle` (Python) and
`verifyRunAsync` / `verifyBundleAsync` (TypeScript, the synchronous functions skip this step)
report `anchors` (receipts bound to the chain) and `anchors_witness_verified` (receipts that
verified against a witness in the trust list); the Inspector shows the witness, the witness
time and the verdict per anchor. A verified anchor means: this chain head existed no later than
the witness time. `python -m sealedrun run.zip` prints the same summary. A relying party that
wants the strongest statement also re-queries the witness: for Rekor, search the public log by
the head hash (`POST https://rekor.sigstore.dev/api/v1/index/retrieve {"hash":"sha256:<head>"}`
or the Inspector's link to the entry); for a time-stamp, the token itself is the statement.

The trust list ships in both packages as `witnesses.json` (Sigstore's time-stamp authority and
Rekor log key from Sigstore's `trusted_root.json`, DigiCert Trusted Root G4). Pass your own with
`witnesses=` / `witnesses:` to add a witness or to trust nobody (`[]`), and `strict_witness` /
`strictWitness` to fail verification on an anchor that does not verify. To refresh the shipped
list, take the `timestampAuthorities[].certChain` root and `validFor`, and the `tlogs[]` entry
for `rekor.sigstore.dev` (`publicKey.rawBytes` as PEM, `logId.keyId` as hex), from
`https://raw.githubusercontent.com/sigstore/root-signing/main/targets/trusted_root.json`, and
DigiCert's root from `https://cacerts.digicert.com/DigiCertTrustedRootG4.crt.pem`; never take a
certificate from a receipt. Regulated deployments that need a qualified time-stamp under eIDAS
point `SEALEDRUN_ANCHOR_TSA_URL` at their qualified trust service provider and add its root to
the trust list; the EU AI Act's logging duty (Art. 12) does not itself require one.

### Data labels and the first policy rule

A record carries `data_labels` (SPEC 5.6: `pii`, `nda`, `secret`, `acme:tier-1`, ...) so that a
reader can see which kind of data each step touched and which of it left the host. Through the
proxies the caller states the labels itself, in a request header on every channel the recorder
records (LLM, MCP HTTP, A2A, and `POST /api/steps` when the step body names none):

```
X-SealedRun-Labels: nda, pii
```

The header is checked (lowercase labels, at most 64; a bad one is a 400 and nothing is
forwarded), never passed on to an upstream, and lands in the record as `data_labels` with
`sealedrun.labels[label].source = "header"`, so a label the caller asserted is never mistaken
for one a classifier found. Run summaries count `labels_sent_to_cloud` per label.

On top of that sits one policy rule, off by default:

```bash
SEALEDRUN_POLICY_BLOCK_TO_CLOUD=["nda","secret"]   # labels that must not reach a cloud target
```

A call that carries one of those labels to an upstream, MCP server or A2A agent whose
`location` is `cloud` is refused before any byte reaches it: the LLM proxy answers 403 in the
SDK's own error shape, the MCP proxy a JSON-RPC error `40003`, the A2A proxy the same or a
`PERMISSION_DENIED` status on the REST binding, each naming the rule. The chain keeps the
evidence: a record with `outcome: blocked`, `policy: {rule_id: "recorder/no-nda-to-cloud",
decision: block, reason: "target.location=cloud and labels contain nda"}` and the digest of the
request that was not sent (SPEC 5.7). A labelled cloud call the rule lets through carries
`policy: {rule_id: "default/allow", decision: allow, ...}`, so the reader sees that the rule was
consulted; local targets and unconfigured recorders write no policy object. The Inspector counts
the blocked steps and shows the rule and reason on each. The rule covers `tools/call`,
`resources/read`, `prompts/get`, and every POST, PUT or PATCH to a cloud A2A agent; a configured
label outside the SPEC 5.6 pattern stops the recorder at start. It cannot cover the
stdio wrapper (a stdio server has no known location) or self-reported steps (the caller states
its own outcome), and it decides on stated labels only. Classifiers that find labels in the
payload, redirecting a call to a local model and approval flows are deliberately not here yet.

## Development

```bash
uv sync --all-packages
pnpm install
uv run pytest && pnpm test
pnpm --filter @sealedrun/core build && pnpm --filter @sealedrun/web build   # static UI into apps/web/out
uv run sealedrun-recorder                                             # http://localhost:8080
```

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Standards

Built on, not instead of: RFC 8785 (JCS), FIPS 204 (ML-DSA), RFC 8032 (Ed25519), MCP SEP-3004
and IETF draft-sharif-agent-audit-trail (record model and field names), OpenTelemetry GenAI
semantic conventions (export mapping), EU AI Act Articles 12, 19 and 26 (logging and retention).

## License

Code and schemas: Apache-2.0. Specification text (`SPEC.md`, `TRUST.md`): CC-BY-4.0.
Contributions require the [CLA](CLA.md).

## Security

Report vulnerabilities privately, see [SECURITY.md](SECURITY.md). Please do not open public issues
for them.
