# SealedRun Record Specification

Version 0.1.0-draft · 2026-09-17 · License: CC-BY-4.0

The SealedRun Record is a format for a tamper-evident, signed, append-only record of what an AI agent did: which
model it called, which tool it invoked, what data left the host, where it went, and why a policy
allowed it. Records are exported as an evidence bundle that a third party verifies offline.

The key words MUST, MUST NOT, SHOULD, MAY are to be interpreted as described in RFC 2119.

## 1. Goals and non-goals

Goals:

- Any two implementations produce byte-identical canonical forms, hashes and verifiable signatures.
- A verifier needs only the bundle and public keys; no network, no trust in the operator.
- Both planes of an agent are in one chain: model calls (OpenAI-compatible or native APIs) and
  tool calls (MCP or in-process), correlated by run and sequence.
- Records carry data labels and policy decisions so a reader can answer "did labelled data leave
  the host, and under which rule".
- Privacy by construction: the chain stores hashes; bodies are stored separately and can be
  deleted with a provable tombstone.
- Signatures survive the post-quantum transition without a format change.

Non-goals:

- Proving that the agent's reasoning was correct or that the model told the truth.
- Replacing observability tooling. SealedRun maps to OpenTelemetry GenAI conventions (section 10) but
  does not carry metrics.
- Access control or secret management for the keys themselves.

## 2. Entities

| Entity     | Description                                                                                                |
| ---------- | ---------------------------------------------------------------------------------------------------------- |
| Principal  | The accountable party (company, person). Holds a long-lived key pair set. Identified by `principal_id`.    |
| Agent      | One deployed agent instance with its own key pair set, authorised by a Delegation signed by the Principal. |
| Delegation | A signed statement "Principal P authorises Agent A with these public keys, scope and validity window".     |
| Run        | One task or session of an Agent. A Run is a chain of Records with contiguous `seq` starting at 0.          |
| Record     | One step. Signed, chained to the previous Record of the same Run.                                          |
| Payload    | The body of a request or response. Stored outside the chain, referenced by hash. Optional, deletable.      |
| Anchor     | An external, operator-independent witness of a chain head (Sigstore Rekor entry, RFC 3161 token, SCITT).   |
| Bundle     | A portable archive: Records, Delegations, optional Payloads, Anchors, a signed Manifest.                   |

## 3. Encoding and canonicalization

- Records, Delegations and Manifests are JSON objects (RFC 8259) restricted to I-JSON (RFC 7493).
- Canonical form is the JSON Canonicalization Scheme, RFC 8785 (JCS). Every hash and signature in
  SealedRun is computed over JCS bytes.
- Binary values (hashes, keys, signatures) are encoded as base64url without padding (RFC 4648 §5),
  except `hash` and `prev_hash`, which are lowercase hex for readability in logs and diffs.
- Timestamps are RFC 3339 in UTC with millisecond precision, `Z` suffix, e.g. `2026-09-16T12:00:00.000Z`.
- Identifiers `record_id` and `run_id` are UUIDs (RFC 9562), lowercase. UUIDv7 is RECOMMENDED.
- Integers MUST be within the I-JSON safe range (|n| ≤ 2^53 − 1). Floats MUST NOT appear in the
  protected part of a record.

## 4. Cryptographic algorithms

### 4.1 Hash

`hash_alg` is a per-record field. Registered values:

| `hash_alg` | Algorithm | Output | Status                         |
| ---------- | --------- | ------ | ------------------------------ |
| `sha-256`  | SHA-256   | 32 B   | Default, MUST be supported     |
| `sha-384`  | SHA-384   | 48 B   | SHOULD be supported (CNSA 2.0) |

All records in one Run MUST use the same `hash_alg`.

### 4.2 Signatures

SealedRun uses a hybrid signature: every signed object carries two signatures produced with independent
key pairs, one classical and one post-quantum. A verifier MUST reject the object unless both
signatures verify. Rationale: ML-DSA is the EU (ENISA) and US (NIST FIPS 204, CNSA 2.0)
recommendation for the post-quantum transition, and a hybrid protects against an implementation
or cryptanalytic failure in either scheme during that transition.

| `sig_alg`   | Algorithm             | Public key               | Signature  | Reference            |
| ----------- | --------------------- | ------------------------ | ---------- | -------------------- |
| `ed25519`   | Ed25519 (pure)        | 32 B                     | 64 B       | RFC 8032             |
| `ml-dsa-65` | ML-DSA-65             | 1952 B                   | 3309 B     | FIPS 204             |
| `es256`     | ECDSA P-256 / SHA-256 | 65 B (uncompressed SEC1) | 64 B (r‖s) | FIPS 186-5, RFC 7515 |
| `ml-dsa-87` | ML-DSA-87             | 2592 B                   | 4627 B     | FIPS 204             |

Profiles:

- `sealedrun-hybrid-1` (default, MUST): `ed25519` + `ml-dsa-65`.
- `aat-compat-1` (MAY): `es256` + `ml-dsa-65`, for interoperability with implementations of
  draft-sharif-agent-audit-trail.
- `sealedrun-hybrid-2` (MAY): `ed25519` + `ml-dsa-87`.

An `ed25519` public key MUST be the canonical encoding of a point of prime order: not the
identity, no small-order component, `y` below the field prime. In a signature, `R` MUST be
canonically encoded and MUST NOT be the identity. A verifier MUST reject a key or signature that
breaks these rules before checking the equation. RFC 8032 permits both the cofactored and the
cofactorless verification equation, and libraries differ; the two agree on every input that
passes these checks, so all conforming verifiers return the same answer.

`es256` signatures MUST be low-S: `s` is at most half the order of the P-256 group. A signer that
obtains a high-S value replaces `s` with `n - s`; a verifier MUST reject a high-S signature. This
gives every signature exactly one valid encoding. JWS (RFC 7515) does not require low-S, so a
signature taken from another `es256` implementation may need this normalisation before it is
placed in a SealedRun object; normalising does not need the private key.

ML-DSA signatures use the pure (non pre-hash) variant with an empty context string. The
deterministic signing variant SHOULD be used so test vectors are reproducible; verifiers accept
both variants because verification does not depend on the choice.

### 4.3 Key set and key identifiers

A key set is a JSON object mapping `sig_alg` to a base64url public key:

```json
{ "ed25519": "…", "ml-dsa-65": "…" }
```

The key identifier `kid` of a key set is `base64url(SHA-256(JCS(keyset)))`. `agent_id` is the
`kid` of the Agent's key set; `principal_id` is the `kid` of the Principal's key set. The `did:…`
form of `principal_id` is reserved: version 0.1 defines no DID resolution, so a verifier MUST reject
a Delegation whose `principal_id` starts with `did:`. Rotation creates a new key set and therefore a
new `kid`; a new Delegation binds it.

### 4.4 Signing input

Signatures are never computed over raw JSON. The signing input is:

```
sig_input = domain || 0x00 || hash_bytes
```

where `hash_bytes` is the raw digest of the object (section 5.3, 6.2, 8.3) and `domain` is the
ASCII string identifying the object type:

| Object     | `domain`                  |
| ---------- | ------------------------- |
| Record     | `sealedrun/record/v1`     |
| Delegation | `sealedrun/delegation/v1` |
| Manifest   | `sealedrun/manifest/v1`   |

Domain separation prevents a signature on one object type from being replayed as another.

The `signatures` object maps each `sig_alg` of the signer's key set to a base64url signature:

```json
{ "ed25519": "…", "ml-dsa-65": "…" }
```

## 5. Record

### 5.1 Fields

| Field              | Type        | Req | Description                                                                       |
| ------------------ | ----------- | --- | --------------------------------------------------------------------------------- |
| `spec_version`     | string      | M   | `"0.1"`                                                                           |
| `record_id`        | uuid        | M   | Unique id of the record                                                           |
| `run_id`           | uuid        | M   | Run this record belongs to                                                        |
| `seq`              | integer ≥ 0 | M   | Position in the Run. Contiguous, starts at 0                                      |
| `occurred_at`      | timestamp   | M   | Set by the recorder's clock, never by the caller                                  |
| `principal_id`     | string      | M   | `kid` or DID of the Principal                                                     |
| `agent_id`         | string      | M   | `kid` of the signing Agent                                                        |
| `kind`             | enum        | M   | See 5.2                                                                           |
| `actor`            | object      | M   | `{ "type": "agent" \| "human" \| "system", "id": string }` who initiated the step |
| `target`           | object      | M   | Where the data went or came from. See 5.4                                         |
| `payload`          | object      | O   | Hash references to request/response bodies. See 5.5                               |
| `data_labels`      | string[]    | M   | Labels attached to data in this step (may be empty). See 5.6                      |
| `policy`           | object      | O   | The decision that allowed or altered the step. See 5.7                            |
| `outcome`          | enum        | M   | `success` \| `error` \| `blocked` \| `pending` \| `timeout`                       |
| `parent_record_id` | uuid        | O   | Causal parent (e.g. the `llm_call` that requested a `tool_call`)                  |
| `extensions`       | object      | O   | Type-keyed extension map. Keys are extension names, values are objects. See 9     |
| `hash_alg`         | enum        | M   | Section 4.1                                                                       |
| `prev_hash`        | hex         | M   | `hash` of record `seq − 1`; for `seq = 0` a string of zeros of the digest length  |
| `hash`             | hex         | M   | Digest of the protected record. See 5.3                                           |
| `signatures`       | object      | M   | Agent signatures over `hash`. See 4.4                                             |

The **protected record** is the object with every field except `hash` and `signatures`.
Implementations MUST NOT add top-level fields; new data goes into `extensions`.

### 5.2 Kinds

| `kind`            | Meaning                                                                                          |
| ----------------- | ------------------------------------------------------------------------------------------------ |
| `run_start`       | First record of a Run (`seq = 0`). MUST carry `extensions["sealedrun.delegation"]` (section 6.4) |
| `run_end`         | Last record of a Run. After it no record with this `run_id` is valid                             |
| `llm_call`        | A request to a model and its response                                                            |
| `tool_call`       | A tool invocation (MCP `tools/call`, function call) and its result                               |
| `memory_read`     | Data read from an agent memory store                                                             |
| `memory_write`    | Data written to an agent memory store                                                            |
| `policy_decision` | A standalone policy evaluation (when not embedded in the step it governs)                        |
| `human_approval`  | A human granted or denied an action. `actor.type = "human"`                                      |
| `tombstone`       | A payload was deleted. `extensions["sealedrun.tombstone"]` names the record and the reason       |
| `anchor`          | An external witness receipt for a chain head. See 8                                              |
| `note`            | Free-form operator annotation                                                                    |

### 5.3 Hash and chain

```
hash = HEX( H( JCS(protected_record) ) )
```

where `H` is the algorithm named by `hash_alg`. Because `prev_hash` is inside the protected
record, each hash commits to the entire history of the Run. A Run is valid when for every record
`r` with `seq > 0`: `r.prev_hash == records[seq − 1].hash`, and for `seq = 0` `prev_hash` is the
all-zero string.

### 5.4 Target

```json
{
  "type": "model" | "tool" | "memory" | "human" | "witness" | "none",
  "name": "gpt-4.1" | "filesystem/read_file" | "…",
  "endpoint": "https://api.openai.com/v1/chat/completions",
  "location": "local" | "cloud" | "unknown",
  "provider": "openai" | "ollama" | "mcp:filesystem" | "…"
}
```

`name` is required. `endpoint` SHOULD be the resolved upstream after routing, not the address the
agent called. `location` is the recorder's classification of where the data physically went.

### 5.5 Payload

```json
{
  "request_hash": "b64url(H(request_bytes))",
  "request_size": 1234,
  "request_media_type": "application/json",
  "response_hash": "…",
  "response_size": 567,
  "response_media_type": "application/json",
  "storage": "inline" | "bundle" | "external" | "deleted" | "none",
  "encryption": { "alg": "aes-256-gcm", "kid": "…" }
}
```

Hashes are computed over the exact bytes sent or received, before any redaction, using the Run's
`hash_alg`. A payload object with `storage: "none"` still carries the hashes; only the bodies are
absent. `deleted` means a tombstone exists for this record.

### 5.6 Data labels

Labels are lowercase strings. Reserved labels: `pii`, `phi`, `pci`, `secret`, `credential`,
`nda`, `internal`, `public`, `source_code`, `financial`, `legal`, `medical`. Implementations MAY
add namespaced labels (`acme:customer-tier-1`). The origin of a label is recorded in
`extensions["sealedrun.labels"]` when known:

```json
{
  "sealedrun.labels": {
    "pii": { "source": "classifier", "confidence": 0.93, "model": "sealedrun-sens-v1" }
  }
}
```

### 5.7 Policy

```json
{
  "rule_id": "eu-strict/no-pii-to-cloud",
  "decision": "allow" | "block" | "redirect" | "require_approval" | "allow_with_note",
  "reason": "target.location=cloud and labels contain pii",
  "redirected_to": { "type": "model", "name": "qwen2.5:14b", "location": "local" }
}
```

A `block` decision MUST be accompanied by `outcome = "blocked"` and a payload that hashes the
request that was not sent. A `redirect` MUST record the final target in `target` and the original
in `policy.original_target`.

## 6. Delegation

### 6.1 Fields

| Field            | Type      | Req | Description                                         |
| ---------------- | --------- | --- | --------------------------------------------------- |
| `spec_version`   | string    | M   | `"0.1"`                                             |
| `delegation_id`  | uuid      | M   |                                                     |
| `principal_id`   | string    | M   | `kid` or DID of the Principal                       |
| `principal_keys` | keyset    | M   | Public keys of the Principal (section 4.3)          |
| `agent_id`       | string    | M   | `kid` of `agent_keys`                               |
| `agent_keys`     | keyset    | M   | Public keys of the Agent                            |
| `agent_name`     | string    | O   | Human-readable name                                 |
| `scope`          | object    | O   | Free-form limits (allowed targets, labels, budgets) |
| `not_before`     | timestamp | M   |                                                     |
| `not_after`      | timestamp | M   |                                                     |
| `hash_alg`       | enum      | M   |                                                     |
| `hash`           | hex       | M   | Digest of the protected delegation                  |
| `signatures`     | object    | M   | Principal signatures over `hash`                    |

### 6.2 Hash

`hash = HEX(H(JCS(protected_delegation)))`, protected = all fields except `hash` and `signatures`.

### 6.3 Validation

A record is authorised when: its `agent_id` equals the delegation's `agent_id`; `principal_id`
matches; `occurred_at` is within `[not_before, not_after]`; the delegation's signatures verify
against `principal_keys`; and `kid(principal_keys) == principal_id` or the DID resolves to those
keys. Self-delegation (`principal_keys == agent_keys`) is valid and marks a single-party setup.

### 6.4 Binding to a Run

The `run_start` record carries `extensions["sealedrun.delegation"] = { "delegation_id": "…", "hash": "…" }`.
The delegation object itself is shipped in the bundle. A verifier MUST fail a Run whose
`run_start` references a delegation that is absent or whose hash differs.

## 7. Payload storage and deletion

- Bodies live outside the chain, keyed by their hash: `payloads/<hash_alg>/<hash>`.
- Bodies MAY be encrypted at rest with a key the operator controls; the chain hashes are over
  plaintext, so a verifier holding the key can still check them.
- Deletion (GDPR Art. 17, retention policy) removes the body and appends a `tombstone` record:

```json
{
  "sealedrun.tombstone": {
    "record_id": "…",
    "fields": ["request", "response"],
    "reason": "retention-90d",
    "legal_basis": "GDPR Art. 17"
  }
}
```

The original record and its hashes stay; the bundle proves that data existed, what its digest
was, and when it was removed.

## 8. Anchors

An anchor publishes a chain head to a system the operator does not control, so that a full
rewrite of the chain is detectable.

### 8.1 Anchor record

`kind = "anchor"`, `target.type = "witness"`, and:

```json
{
  "sealedrun.anchor": {
    "type": "rekor" | "rfc3161" | "scitt" | "other",
    "anchored_hash": "<hash of record seq N>",
    "anchored_seq": N,
    "receipt": { "digest": "<the digest given to the witness>", "…": "witness-specific proof" },
    "witness": "https://rekor.sigstore.dev"
  }
}
```

The anchor record itself is chained after `seq N`. `receipt.digest` is REQUIRED: it is the digest
that was submitted to the witness, in the same hex form as `anchored_hash`; every other member of
`receipt` is witness-specific. A verifier MUST check that `anchored_hash` equals the hash of the
record at `anchored_seq` and that `receipt.digest` equals `anchored_hash`, and fails with check
`anchor` otherwise. When a bundle carries `anchors/<record_id>.json`, that file MUST be the
`receipt` of the anchor record with that `record_id`.

These checks bind the receipt to the chain; they do not authenticate the witness. 0.1 defines no
offline verification of the witness-specific proof, so a verifier MUST report how many anchors
had their proof verified (always zero for a 0.1 verifier) and a relying party re-checks the
receipt against the witness.

### 8.2 Cadence

Recorders SHOULD anchor at least every 10 minutes while a Run is active, and always at `run_end`.

### 8.3 Manifest signatures

The Manifest hash is `HEX(H(JCS(protected_manifest)))`; it is signed by the exporting Agent and
MAY additionally be signed by the Principal.

## 9. Extensions

`extensions` is a map from extension name to object. Names are reverse-DNS or `sealedrun.*` for this
specification. Unknown extensions MUST be preserved in canonical form and MUST NOT cause
verification failure. Registered:

| Name                   | Section | Purpose                          |
| ---------------------- | ------- | -------------------------------- |
| `sealedrun.delegation` | 6.4     | Bind a Run to a Delegation       |
| `sealedrun.tombstone`  | 7       | Record a payload deletion        |
| `sealedrun.anchor`     | 8       | External witness receipt         |
| `sealedrun.labels`     | 5.6     | Provenance of data labels        |
| `sealedrun.llm`        | 10.1    | Model call details               |
| `sealedrun.mcp`        | 10.2    | MCP tool call details            |
| `sealedrun.proxy`      | 10.3    | Recorder proxy call details      |
| `sealedrun.otel`       | 11      | OpenTelemetry trace and span ids |

### 9.1 Compatibility with MCP SEP-3004 and IETF AAT

SealedRun field names follow draft-sharif-agent-audit-trail where semantics coincide (`record_id`,
`prev_hash`, `outcome`, tombstones) and the SEP-3004 model of a protected core with a type-keyed
`extensions` map. An SealedRun record can be projected to an AAT record by mapping `run_id → session_id`,
`kind → action_type`, `target.name → action_detail`, and to a SEP-3004 audit record by mapping
`record_id → event_id`, `occurred_at → occurred_at`, `outcome → outcome`. SealedRun-specific fields
(`data_labels`, `policy`, `target.location`, hybrid signatures) are carried as extensions in those
formats. Reverse projection is lossy and produces records marked `extensions["sealedrun.imported"]`.

## 10. Plane-specific extensions

### 10.1 `sealedrun.llm`

```json
{
  "model": "gpt-4.1",
  "provider": "openai",
  "stream": true,
  "input_tokens": 812,
  "output_tokens": 233,
  "finish_reason": "tool_calls",
  "tool_calls_requested": ["filesystem/read_file"],
  "temperature": 0
}
```

### 10.2 `sealedrun.mcp`

```json
{ "server": "filesystem", "transport": "stdio" | "http", "method": "tools/call", "tool": "read_file",
  "request_id": "…", "is_error": false }
```

### 10.3 `sealedrun.proxy`

Written by a recorder that sits between the agent and the provider. All fields are optional.
`status` is the HTTP status returned to the agent and `latency_ms` the time spent upstream.
`truncated` is set when a streamed response ended before the upstream finished it (client
disconnect, upstream break or size cap); the record then holds the bytes delivered so far and its
outcome is `error`. On a `run_start` record, `run_label` is the label the agent chose for the run.

```json
{ "upstream": "openai", "dialect": "openai" | "anthropic" | "ollama" | "gemini", "operation": "chat",
  "status": 200, "latency_ms": 412.5, "truncated": true, "run_label": "nightly-report" }
```

## 11. Mapping to OpenTelemetry GenAI semantic conventions

The OTel GenAI conventions are in Development status (semantic-conventions-genai, schema
gen-ai/1.42.0). The mapping is informative and tracks that repository:

| SealedRun                            | OTel                                                      |
| ------------------------------------ | --------------------------------------------------------- |
| Run                                  | `invoke_agent` span; `run_id` in `gen_ai.conversation.id` |
| `llm_call`                           | `chat` span; `sealedrun.llm.model → gen_ai.request.model` |
| `tool_call`                          | `execute_tool` span; `target.name → gen_ai.tool.name`     |
| `memory_read` / `memory_write`       | `retrieval` / memory operation span                       |
| `sealedrun.otel.trace_id`, `span_id` | trace and span ids of the originating span                |
| `payload.*_hash`                     | span attributes `sealedrun.payload.request_hash` etc.     |

## 12. EU AI Act mapping

Article 12 requires high-risk AI systems to allow automatic recording of events over the system's
lifetime; Articles 19 and 26 require providers and deployers to keep those logs for at least six
months. SealedRun supports this as follows:

| Requirement (Art. 12(2)–(3))                               | SealedRun element                              |
| ---------------------------------------------------------- | ---------------------------------------------- |
| Period of each use (start and end)                         | `run_start.occurred_at`, `run_end.occurred_at` |
| Reference database against which input data was checked    | `memory_read` records, `target.name`           |
| Input data for which the search led to a match             | `payload.request_hash`, retained body          |
| Identification of natural persons involved in verification | `human_approval` records, `actor.id`           |
| Traceability, post-market monitoring                       | Signed chain, anchors, bundle export           |
| Retention (Art. 19, 26)                                    | Bundle export and tombstone-based retention    |

## 13. Bundle

A bundle is a ZIP archive:

```
manifest.json
delegations/<delegation_id>.json
runs/<run_id>.jsonl          one Record per line, ascending seq
payloads/<hash_alg>/<hash>   optional bodies
anchors/<record_id>.json     optional raw witness receipts
```

### 13.1 Manifest

| Field          | Type      | Description                                                                            |
| -------------- | --------- | -------------------------------------------------------------------------------------- |
| `spec_version` | string    | `"0.1"`                                                                                |
| `bundle_id`    | uuid      |                                                                                        |
| `created_at`   | timestamp |                                                                                        |
| `exporter`     | object    | `{ "agent_id": "…", "software": "sealedrun-recorder/0.1.0" }`                          |
| `principal_id` | string    |                                                                                        |
| `delegations`  | string[]  | Delegation ids included                                                                |
| `runs`         | object[]  | `{ run_id, hash_alg, record_count, first_hash, last_hash, complete }`                  |
| `files`        | object    | Map of every file path in the archive (except `manifest.json`) to its base64url digest |
| `hash_alg`     | enum      | Algorithm for `hash` and `files`                                                       |
| `hash`         | hex       |                                                                                        |
| `signatures`   | object    | Exporter's Agent signatures; MAY include `principal_signatures`                        |

Bounds, enforced by the schemas so that a reader can reject an oversized document before doing
any other work: `delegations` and `runs` hold at most 1024 items each, a Record's `data_labels`
at most 64, and `manifest.json` is at most 4 MiB. Readers MUST check these before any hash or
signature work and SHOULD stop at the first schema error on untrusted input.

`complete` is true when the run contains a `run_end` record. A bundle MAY contain a slice of a
run; then `first_hash` is the `prev_hash` of the first included record so the slice can be joined
to an earlier bundle.

### 13.2 Verification procedure

A bundle carries its own public keys, so steps 1 and 3 to 6 only show that the bundle is
internally consistent: anyone can mint a Principal, delegate to an Agent and produce a bundle that
passes them. Who signed it is settled by step 2 alone. The verifier obtains the identifiers of the
Principals it trusts out of band (a contract, a registry, the Principal's website) and never from
the bundle.

1. Read `manifest.json`; verify its signatures against the exporter's key set found in a
   delegation in the bundle; verify `files` digests. For each delegation: verify hash and
   Principal signatures; check that `principal_id` and `agent_id` are the `kid` of the key sets
   and that `principal_id` equals the manifest `principal_id`.
2. Trust anchor: if the verifier was given a set of trusted Principals, the manifest
   `principal_id` MUST be in it, otherwise fail with check `trust`. If it was given none, it
   continues, and the report MUST state that the Principal was not authenticated.
3. For each run: check `seq` contiguity, `prev_hash` linkage, `hash` recomputation, agent
   signatures, delegation validity at `occurred_at`, `run_start` binding, absence of records after
   `run_end`.
4. For each record with a payload present: recompute body digests.
5. For each anchor record: check `anchored_hash` against the run; optionally re-query the witness.
6. Report: `ok`, or the first failing run, seq and check. The report MUST carry the manifest
   `principal_id`, the exporter `agent_id` and whether the Principal was matched against a trust
   anchor. A user interface MUST NOT present a bundle as verified without qualification when the
   Principal was not authenticated.

## 14. Test vectors

`spec/vectors/` contains deterministic inputs and expected outputs so that independent
implementations can prove conformance:

- `keys.json`: public seeds for a Principal, an Agent and an attacker, the derived public keys and
  `kid` values, and the seed derivation rule. Test keys only, never for production.
- `jcs/*.json` with `*.expected`: the RFC 8785 reference canonicalization set.
- `signatures/ed25519.json`: Ed25519 edge cases (`mixed-order-key`, `mixed-order-r`, `identity-r`,
  `small-order-key`) on which cofactored and cofactorless verifiers disagree; each entry states
  whether a verifier MUST accept.
- `delegations/valid.json`, `aat-compat-1.json`, `aat-compat-1-high-s.json` with `expected.json`:
  signed delegations and their expected hashes. The last one carries a high-S `es256` signature
  and MUST be rejected.
- `records/valid-run.jsonl` with `expected.json`: a complete nine-record run covering every
  record kind, with the expected `prev_hash` and `hash` per seq.
- `chains/*.jsonl` with `expected.json`: negative runs (`tampered-field`,
  `resigned-by-other-key`, `resigned-with-agent-key`, `gap-in-seq`, `reordered`,
  `broken-prev-hash`, `record-after-run-end`, `expired-delegation`, `bad-anchor`,
  `receipt-digest-mismatch`,
  `malformed-anchor-extension`) and the check
  name and seq at which a verifier MUST fail.
- `bundle/unknown-principal.zip`: consistent and correctly signed end to end, but by the
  `attacker` Principal. `expected.json` lists `trusted_principals`; a verifier given that set MUST
  fail with check `trust`, and without it MUST report the Principal as not authenticated.
- `bundle/swapped-anchor-receipt.zip`: the `anchors/` file is not the receipt of its anchor
  record; check `anchor`.
- `bundle/valid.zip`, `tampered-payload.zip`, `tampered-record.zip`, `poisoned-payload-name.zip`,
  `overlapping-entries.zip`, `too-many-delegations.zip`, `no-payloads.zip` with `expected.json`.

Hashes are reproducible byte-for-byte. Signatures are verifiable but not necessarily
reproducible: ML-DSA implementations may use the hedged (randomised) signing variant of
FIPS 204, and ECDSA is randomised unless RFC 6979 is used. Conformance therefore means: an
implementation reproduces every hash, verifies every positive signature, rejects every negative
case at the stated check and seq, and its own signatures verify under the reference
implementation. The vectors are generated by `python -m sealedrun.vectors spec` from the reference
implementation.

## 15. Versioning

`spec_version` uses `MAJOR.MINOR`. Minor versions add fields only inside `extensions` and new enum
values; verifiers ignore unknown extensions and treat unknown `kind` values as opaque but still
verify hash and signature. Major versions may change the protected record layout.

## References

- RFC 8785 JSON Canonicalization Scheme; RFC 7493 I-JSON; RFC 8032 Ed25519; RFC 3339; RFC 9562 UUID; RFC 3161 TSP
- NIST FIPS 204 Module-Lattice-Based Digital Signature Standard (ML-DSA); FIPS 186-5; NSA CNSA 2.0
- ENISA post-quantum recommendations (ML-DSA-65 for general use); EU Coordinated Implementation Roadmap for PQC (milestones 2026, 2030, 2035)
- MCP SEP-3004 Tamper-Evident Audit Record Contract (open PR, github.com/modelcontextprotocol/modelcontextprotocol/pull/3004)
- IETF draft-sharif-agent-audit-trail-04 (2026-09-15)
- OpenTelemetry semantic-conventions-genai (schema gen-ai/1.42.0, Development status)
- Regulation (EU) 2024/1689 (AI Act) Articles 12, 19, 26
- Sigstore Rekor; IETF SCITT architecture
