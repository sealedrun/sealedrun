# Changelog

All notable changes are documented here. The format follows Keep a Changelog; the project
follows Semantic Versioning once 1.0.0 is reached.

## [Unreleased]

## [0.2.0] - 2026-09-26

Stage 1: the recorder as a live LLM proxy. Every model call made through it becomes a signed record
in a live run that can be exported as a bundle at any time. Tested live with the OpenAI, Anthropic
and Ollama SDKs, Claude Code (API key and Pro/Max login) and Codex.

### Added

- Recorder LLM proxy, OpenAI wire format: `POST /v1/chat/completions`, `POST /v1/responses`, `POST /v1/embeddings`, `GET /v1/models`. Upstreams come from `upstreams.yaml` (`SEALEDRUN_UPSTREAMS_FILE`) and are routed by wire format and model name pattern, so one model can sit behind several formats; each upstream sets how its key is sent (`bearer`, `x-api-key`, `x-goog-api-key`, `api-key`) and optional static headers. `services/recorder/upstreams.example.yaml` covers OpenAI, Azure OpenAI, Anthropic, Gemini, DeepSeek, Kimi, Qwen, GLM, MiniMax, Mistral, xAI, Groq, OpenRouter, Ollama, LM Studio, vLLM and llama.cpp. The client sends `SEALEDRUN_API_TOKEN` wherever its SDK puts the API key and the upstream key is swapped in server side. Every call becomes a signed `llm_call` record with request and response bodies, never headers. Calls with the same `X-SealedRun-Run` label share a run; unlabelled calls share a run until it is idle for `SEALEDRUN_PROXY_RUN_IDLE_SECONDS`. If the record cannot be written the call fails. `POST /v1/chat/completions` with `"stream": true` is passed through chunk by chunk and recorded as the raw SSE bytes when it ends: usage from the final `usage` chunk (`stream_options.include_usage`), `finish_reason`, tool names from the deltas. A stream cut by a client disconnect, an upstream break or `SEALEDRUN_PROXY_MAX_BODY_BYTES` is recorded with `sealedrun.proxy.truncated` and outcome `error`. `POST /v1/responses` with `"stream": true` is passed through the same way; usage, status or incomplete reason and tool names come from the terminal `response.completed` / `response.incomplete` / `response.failed` event, and `response.failed` gives outcome `error`.
- Recorder LLM proxy, Anthropic Messages wire format: `POST /v1/messages`, `POST /v1/messages/count_tokens`, and `GET /v1/models` in the Anthropic shape when `anthropic-version` is sent. Works with Claude Code and the Anthropic SDKs through `ANTHROPIC_BASE_URL` (token as `x-api-key` or bearer); `anthropic-version` and `anthropic-beta` are passed through. Recorded `input_tokens` include cache writes and reads. `"stream": true` is passed through event by event and recorded as the raw SSE bytes: the model and input tokens from `message_start`, tool names from `content_block_start`, stop reason and output tokens from `message_delta`; an `error` event gives outcome `error`, a stream cut before `message_stop` is `truncated`.
- Recorder LLM proxy, Ollama native wire format: `POST /api/chat`, `/api/generate`, `/api/embed`, `/api/embeddings`, plus unrecorded `GET /api/tags`, `GET /api/version` and `POST /api/show`. Model management endpoints are not proxied. `/api/chat` and `/api/generate` stream by default (NDJSON) and are passed through line by line; the `done: true` line gives the counts and done reason, a stream cut before it is `truncated`, a line with `error` gives outcome `error`.
- Recorder LLM proxy, Gemini native wire format: `POST /v1beta/models/{model}:generateContent`, `:countTokens`, `:embedContent`, `:batchEmbedContents` (also under `/v1`), plus unrecorded `GET /v1beta/models` and `GET /v1beta/models/{model}`. The token is accepted as `x-goog-api-key` or `?key=`; the query key is never forwarded or recorded. Recorded `output_tokens` include thinking tokens. `:streamGenerateContent?alt=sse` is passed through chunk by chunk (other `alt` values are refused); finish reason and usage come from the last chunk, function call names from any chunk.
- `POST /api/runs/{run_id}/export` exports a live run as a bundle signed by the recorder: its agent key is the exporter, its principal key countersigns. An open run exports with `complete: false`; `?end=true` writes `run_end` first. Imported runs answer 409 (download the original bundle). A payload body the database no longer holds is a 500, never a silent gap.
- The recorder reports its own Principal as trusted on the runs it signed itself (`principal_trusted` in `/api/runs`), so live runs need no `SEALEDRUN_TRUSTED_PRINCIPALS` entry. Bundles from other Principals are unaffected.
- Inspector, "Runs in the recorder" tab: live and imported runs are badged, the list and the open live run refresh every 5 s while the tab is visible, and "Export bundle" / "Close run and export" download the bundle and verify it in the browser.
- Test vector `spec/vectors/bundle/open-run.zip`: a run exported before `run_end`; verifiers accept it and report `complete: false` (SPEC 14).
- Claude Code on a subscription login through the proxy: the recorder token is also accepted in `X-SealedRun-Token` (set with `ANTHROPIC_CUSTOM_HEADERS`), and an upstream with `client_auth: passthrough` receives the client's own `Authorization` / `x-api-key` instead of its configured key, with `anthropic-beta` as sent. Other upstreams keep swapping in their key; the client credential and the recorder token are never recorded, and the recorder token is never forwarded.
- README: Codex through the proxy (Responses API provider), and the Ollama context length that coding agents need.
- The proxy forwards the upstream response headers SDKs act on: for the Anthropic format `x-should-retry`, `retry-after`, `request-id` and `anthropic-ratelimit-*` (what Claude Code reads through a gateway); for the OpenAI format `retry-after`, `x-request-id` and `x-ratelimit-*`. On plain, error and streamed replies alike. Every other upstream header stays behind the proxy.
- Docker image reads upstreams from `/data/upstreams.yaml`.
- `/api/runs` and `/api/runs/{run_id}` carry `run_label`, the `X-SealedRun-Run` label a live run was opened with (`null` otherwise); the Inspector shows it in the run list. Live-test finding: clients had no way to find their run.
- Streamed calls ask the upstream for `accept-encoding: identity`. Live-test finding: api.anthropic.com gzips SSE when allowed, and the relay passed the compressed bytes on without `content-encoding`, so the Anthropic SDK failed on `messages.stream()`; buffered calls were decoded and unaffected. The recorded stream bytes are now always plain SSE.
- README: Docker + Ollama on one host (host networking), the upstreams file is read once at start, unroutable calls leave no record. `upstreams.example.yaml` names the common untagged Ollama embedding models, which `"*:*"` does not match.
- `SPEC.md` 10.3: registered extension `sealedrun.proxy` (upstream, dialect, operation, HTTP status, latency, `truncated`, run label).

## [0.1.1] - 2026-09-21

First public release. Security hardening before publication. The project and the record format are now named
SealedRun (previously AFR).

### Security

- **Trust anchor.** A bundle signed end to end by a newly minted Principal used to verify exactly like a genuine one, and the report did not even name the Principal. `SPEC.md` 13.2 now has a trust anchor step and `TRUST.md` no longer treats the keys inside a bundle as a root of trust. `verify_bundle` / `verifyBundle` take the trusted principal ids and fail with check `trust` on anyone else; `BundleReport` carries `principal_id`, the exporter `agent_id` and `principal_trusted`. The recorder has `SEALEDRUN_TRUSTED_PRINCIPALS`; the Inspector shows the principal, has a box for trusted ids and says "integrity only, signer not authenticated" instead of "verified" when none matched. **API change:** `BundleReport` has three new required fields.
- Verifiers (Python and TypeScript) reject every Delegation whose `principal_id` is a DID: 0.1 has no DID resolver, so such an identifier was never bound to the signing keys. `SPEC.md` and `TRUST.md` say so.
- Bundle verification checks every delegation in the bundle and requires its `principal_id` to equal the manifest `principal_id`; the principal countersignature is checked against the exporter's delegation in both implementations.
- Bundle readers enforce decompression limits (64 MiB per entry, 512 MiB total, 10 000 entries) and report malformed archives with a fixed message instead of exception text.
- Anchors: `receipt.digest` is now required and must equal `anchored_hash`, and an `anchors/<record_id>.json` file must be the receipt of that anchor record, in both verifiers. Until now neither implementation looked at a receipt at all. The witness proof itself is still not verified offline: run reports carry `anchors_witness_verified` (0 in 0.1), the Inspector says so, and `TRUST.md` states the limitation.
- Schemas bound every `uniqueItems` array with `maxItems` (`delegations` and `runs` 1024, `data_labels` 64), `manifest.json` is capped at 4 MiB, and the Python verifier stops at the first schema error: a few-kilobyte upload could previously block the recorder for minutes in a quadratic uniqueness check.
- `ed25519` public keys must be canonical points of prime order, and `R` must be canonical and not the identity, in both verifiers. Previously a key holder could publish a torsion-shifted key, or sign with a mixed-order `R`, and get bundles that `@sealedrun/core` accepted and the Python verifier rejected.
- `es256` signatures are low-S only: the Python signer normalises `s` and both verifiers reject high-S. Previously about half of the `aat-compat-1` objects signed in Python were rejected by `@sealedrun/core`.
- `@sealedrun/core` validates the structure of manifests, delegations and records before use.
- Recorder listens on `127.0.0.1` by default; compose publishes the port to localhost only. Optional `SEALEDRUN_API_TOKEN` protects every API route except `/api/health` (Bearer).
- Recorder refuses state-changing requests whose `Sec-Fetch-Site` is not `same-origin`/`same-site`; without that header a valid bearer token is required. `TrustedHostMiddleware` limits the accepted Host names (`SEALEDRUN_ALLOWED_HOSTS`). The token is accepted as Bearer only and no `WWW-Authenticate: Basic` challenge is sent, so a browser holds no credential to replay; the Inspector asks for the token and sends it itself.
- Payload downloads are served as attachments with `nosniff`, a sandbox CSP and a media type allow-list.
- No default PostgreSQL password. Docker base images and GitHub Actions are pinned by digest; Dependabot keeps them current; workflow token is read-only by default.

### Changed

- Inspector redesigned: Tailwind CSS 4, self-hosted IBM Plex, a verdict block that separates "verified" from "intact, signer not confirmed", a welcome state that explains what to do with a "Try the example bundle" link, the run shown as a linked chain of steps, a proper token form, phone layout and keyboard focus.
- Renamed everything from AFR to SealedRun: packages `sealedrun`, `sealedrun-recorder`, `@sealedrun/core`, env prefix `SEALEDRUN_`, field `spec_version`, extension namespace `sealedrun.*`, signing domains `sealedrun/*/v1`. Vectors and examples regenerated.
- List endpoints are paginated (`limit`, `offset`); the bundle archive column is loaded only on download.
- JSON Schemas ship inside the `sealedrun` wheel.
- Public Python API carries PEP 257 docstrings and exported TypeScript symbols carry TSDoc; both are enforced by the linters (ruff `D`, `eslint-plugin-jsdoc`, `eslint-plugin-tsdoc`).

### Fixed

- The `sealedrun` wheel could not be built from its own sdist: the schema directory was a forced include that only exists in the repository. A build hook now handles both cases.

### Added

- `SECURITY.md`, `CODE_OF_CONDUCT.md`, `.github/dependabot.yml`.
- Release workflow: a `v*` tag builds the packages, installs them into a clean environment to verify the example bundle, and publishes to PyPI and npm through trusted publishing (OIDC, no stored tokens) behind a manually approved environment.

## [0.1.0] - 2026-09-17

Stage 0: specification, reference implementations, inspector, Docker image.

### Added

- Monorepo skeleton: Python workspace (`sealedrun`, `sealedrun-recorder`), pnpm workspace (`@sealedrun/core`, `@sealedrun/web`), GitHub Actions CI with GHCR image publishing.
- Licensing: Apache-2.0 for code and schemas, CC-BY-4.0 for the specification text, CLA.
- `SPEC.md`: SealedRun 0.1 draft (entities, RFC 8785 canonicalization, hash chain, hybrid Ed25519 + ML-DSA-65 signatures, delegation, tombstones, anchors, bundle format, mappings to SEP-3004, IETF AAT, OTel GenAI, EU AI Act Art. 12/19/26).
- `TRUST.md`: threat model and claims a bundle does and does not support.
- JSON Schema (draft 2020-12) in `spec/schema/`: `common.json`, `record.json`, `delegation.json`, `bundle.json`, `extensions/sealedrun.json`; `sealedrun.schema` loader with tests.
- Python reference library `sealedrun`: RFC 8785 canonicalization, SHA-256/384 hash chain, hybrid key sets (Ed25519 + ML-DSA-65, ES256 + ML-DSA-65, Ed25519 + ML-DSA-87), domain-separated signing, delegations, `RunWriter`, run verifier with exact failure location, bundle writer/reader/verifier.
- Test vectors in `spec/vectors/` (keys, RFC 8785 set, delegation, valid run, nine negative chains, four bundles) generated by `sealedrun.vectors`; worked examples in `spec/examples/`.
- TypeScript library `@sealedrun/core`: independent canonicalization, hashing, hybrid signature verification, run and bundle verification; passes all `spec/vectors/` (27 tests).
- `sealedrun-recorder` service (FastAPI + SQLAlchemy, SQLite by default, PostgreSQL via `SEALEDRUN_DATABASE_URL`): bundle upload with verification and import, verify-only endpoint, runs/records/payload API, serves the web UI when built.
- Web inspector (`apps/web`, Next.js static export): drag-and-drop bundle verification in the browser, step feed with target, location, labels, policy decision and payload preview, browsing of runs stored in the recorder.
- Docker: multi-stage `Dockerfile` (Node builds the UI, uv builds the Python env, slim runtime as non-root user with healthcheck, about 230 MB), `docker-compose.yml` with SQLite default and a `postgres` profile, `.env.example`.
