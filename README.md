# SealedRun

A tamper-evident, signed record of every step an AI agent takes. Every step an agent takes — model call, MCP tool
call, memory access, policy decision, human approval — becomes a signed record in an append-only
hash chain. Records are exported as an evidence bundle that anyone can verify offline, without
trusting the operator.

Status: early development, stage 0 (specification, reference implementation, inspector). The
proxy that records live agent traffic arrives in stage 1.

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
| `ee/`                    | Commercial features (not yet present)                                                        | Commercial |

## Cryptography

- Canonicalization: JSON Canonicalization Scheme (RFC 8785).
- Hash chain: SHA-256 by default, SHA-384 allowed (`hash_alg`).
- Signatures: hybrid, every record carries both an Ed25519 and an ML-DSA-65 (FIPS 204) signature.
  Verifiers require both to be valid.

## Run with Docker

```bash
docker compose up -d                      # SQLite in the sealedrun-data volume, UI and API on :8080
docker compose --profile postgres up -d   # with PostgreSQL; set SEALEDRUN_DATABASE_URL, see .env.example
```

Open http://localhost:8080, drop a bundle (for example `spec/examples/bundle.zip`) and the browser
verifies it. "Store in recorder" keeps it on the server.

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
Contributions require the [CLA](CLA.md). The `ee/` directory, when it appears, is licensed
separately.
