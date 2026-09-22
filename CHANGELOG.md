# Changelog

All notable changes are documented here. The format follows Keep a Changelog; the project
follows Semantic Versioning once 1.0.0 is reached.

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
