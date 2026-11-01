# What an SealedRun bundle proves, and what it does not

License: CC-BY-4.0. Companion to `SPEC.md`.

## Parties

- **Operator**: runs the recorder and holds the Agent keys. Usually the same organisation as the
  Principal.
- **Principal**: the accountable party whose keys sign delegations.
- **Verifier**: auditor, insurer, counterparty, regulator. Has the bundle and, from a source other
  than the bundle, the `principal_id` of each Principal it trusts. Does not trust the operator.
- **Witness**: an external log (Sigstore Rekor, RFC 3161 timestamp authority, SCITT) the operator
  does not control.

## What a valid bundle proves

| Claim                                                                                                                                                             | Mechanism                                                                                      |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| These records were produced in this order and none was inserted, removed or reordered later                                                                       | Hash chain over JCS bytes with `seq` and `prev_hash`                                           |
| Each record was signed by the key set identified by `agent_id`                                                                                                    | Hybrid Ed25519 + ML-DSA-65 signatures over the record hash                                     |
| That agent was authorised by the Principal for the time window of the run                                                                                         | Delegation signed by Principal keys, bound in `run_start`                                      |
| The request and response bodies, if present, are the ones the agent saw                                                                                           | Payload digests inside the signed record                                                       |
| A body that is now missing existed with this digest and was removed at this time for this reason                                                                  | `tombstone` record                                                                             |
| The chain head existed no later than the witness time, when the witness is in the verifier's trust list (SPEC 8.4); otherwise once re-checked against the witness | `anchor` record with a witness receipt (RFC 3161 token or Rekor inclusion proof)               |
| A labelled item went to this endpoint under this policy rule                                                                                                      | `data_labels`, `target`, `policy` inside the signed record                                     |
| Every step stayed within the targets, locations, labels and record budget the Principal allowed, or the verifier names the steps that did not                     | Delegation `scope` checked record by record (SPEC 6.5); findings `scope.*`                     |
| Every step whose policy required a human's approval was preceded by a `human_approval` for the same request that said `granted`, or the verifier names the step   | `human_approval` bound to the step by `payload.request_hash` (SPEC 6.6); findings `approval.*` |
| The reply the proxied call recorded is the reply the upstream returned; a self-reported step names what the changed system returned (commit, file digest, tx id)  | `sealedrun.receipt` (SPEC 10.9), `proxy` receipts bound to `payload.response_hash`             |
| The bundle files were not altered after export                                                                                                                    | Manifest `files` digests and exporter signature                                                |

Every row above is relative to the Principal named in the bundle. The keys inside a bundle are
not a root of trust: anyone can create a Principal and produce a bundle that is consistent end to
end. A bundle says who signed it only after the verifier has compared its `principal_id` with an
identifier obtained out of band (`SPEC.md` 13.2, step 2). Without that comparison a verifier has
shown integrity, not origin, and its report says so.

## What it does not prove

- **That the agent did nothing else.** Only steps that passed through the recorder or SDK are
  recorded. A tool that calls the network directly, a model reached without the proxy, or an SDK
  that was bypassed leaves no record. Completeness depends on deployment: the recorder must be
  the only egress for the agent (network policy, no direct credentials in the agent).
- **That a self-reported step happened as described.** A step posted through the SDK is the
  agent's own account, and so is a `self_reported` receipt attached to it: the agent marks its
  own homework. The record proves what the agent claimed and when, signed and chained, not that
  the claim is true. A `proxy` receipt is different in one respect: the recorder, not the agent,
  read the upstream's reply and wrote its digest, so the agent could not have invented that
  reply. Neither kind replaces the target system's own log; a receipt gives the auditor the
  `ref`, `digest` and `issuer` to look it up with. A receipt signed by the target itself is
  reserved for a later version.
- **That an out-of-scope step was harmful, or an in-scope one harmless.** A scope finding says
  the Principal did not allow that target, location or label. Whether the step mattered is for
  the reader; the verifier only makes sure the step is named rather than buried.
- **That the human who approved understood what they approved, or was the right person.** The
  verifier shows that a `human_approval` for the same request bytes preceded the step and what it
  said; `actor.id` names the person as the operator's identity system named them. Whether that
  person was entitled to decide is a question for the operator's access records.
- **That the model output is true or the reasoning was sound.** SealedRun records what was sent and
  received, not whether it was correct.
- **That the labels are correct.** A label is the output of a classifier, a regex, or a source
  annotation. The record proves which label was attached and by what, not that the data really is
  PII.
- **That the operator's clock is right.** `occurred_at` is the recorder's clock. Only anchors
  give an externally attested upper bound on time.
- **Anything about steps before a key compromise was detected.** See "Key compromise".

## Attacks and how they are handled

| Attack                                                                                                               | Detected by                                                          | Notes                                                                                                                                                            |
| -------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Edit a field in a stored record                                                                                      | Hash recomputation fails                                             |                                                                                                                                                                  |
| Delete a record from the middle of a run                                                                             | `seq` gap or `prev_hash` mismatch                                    |                                                                                                                                                                  |
| Truncate the tail of a run                                                                                           | Missing `run_end`; last anchored hash absent from the run            | Only detectable with anchors or a later bundle that continues the run                                                                                            |
| Insert a back-dated record                                                                                           | `prev_hash` linkage fails for every later record                     |                                                                                                                                                                  |
| Replace a payload body                                                                                               | Payload digest mismatch                                              |                                                                                                                                                                  |
| Forge a record with a different key                                                                                  | Signature verification fails; `agent_id` not in any delegation       |                                                                                                                                                                  |
| Operator re-signs the whole run with the real Agent key                                                              | Anchored hashes no longer appear in the run                          | This is why anchors are part of the MVP, not an option                                                                                                           |
| Operator rewrites the run **and** all anchors                                                                        | Witness log entries cannot be removed by the operator                | Verifiers check the witness proof offline for witnesses in their trust list (`anchors_witness_verified`); the relying party may also query the witness           |
| Replay a Delegation or Manifest signature as a Record signature                                                      | Domain separation in the signing input                               |                                                                                                                                                                  |
| Present an old, valid bundle as current                                                                              | `created_at`, `complete` flag, anchor times                          | Verifier compares against the latest anchor known to them                                                                                                        |
| Mint a new Principal and sign a whole bundle with it                                                                 | `principal_id` is not in the verifier's trusted set: check `trust`   | Verifier must hold the trusted `principal_id` out of band; else the report says "not authenticated"                                                              |
| Claim a DID as `principal_id` while signing with unrelated keys                                                      | Verifier rejects every `did:` principal                              | No DID resolver in 0.1; `principal_id` must equal the key set `kid`                                                                                              |
| Record steps under an expired or future delegation                                                                   | `occurred_at` outside `[not_before, not_after]`                      |                                                                                                                                                                  |
| Agent touches a system the Principal did not allow                                                                   | Finding `scope.target` / `scope.location` / `scope.label` with seq   | Reported, not hidden; `strict_scope` turns it into a failure. Needs a delegation with a scope (recorder: `SEALEDRUN_SCOPE`)                                      |
| Agent runs a step that required approval without asking, after a denial, or on a request other than the one approved | Finding `approval.missing` / `approval.denied_but_executed` with seq | Reported, not hidden; `strict_approval` turns it into a failure. The approval record's own `payload.request_hash` is the link, so swapping the request breaks it |
| Agent fabricates a "proxy" receipt on a step it reported itself                                                      | Check `receipt`: no `sealedrun.proxy` on the record                  | The recorder also refuses such a posted step                                                                                                                     |
| Operator swaps the recorded reply but keeps the receipt                                                              | Check `receipt`: digest differs from `payload.response_hash`         | Both sit in the same signed record, so the swap also breaks `hash`                                                                                               |
| Quantum adversary forges Ed25519 signatures                                                                          | ML-DSA-65 signature still required                                   | Hybrid profile                                                                                                                                                   |
| Implementation bug in the ML-DSA library                                                                             | Ed25519 signature still required                                     | Hybrid profile                                                                                                                                                   |
| Verifier and operator disagree on canonical bytes                                                                    | RFC 8785 and the test vectors                                        | Conformance is byte-for-byte                                                                                                                                     |

## Key compromise

If an attacker obtains the Agent private keys, they can produce valid records from that moment.
They cannot alter records that were already anchored. Response: the Principal issues a new
Delegation to a new key set and sets `not_after` of the compromised delegation to the last
trusted anchor time; verifiers treat records after that time under the old keys as untrusted.
Loss of the Principal keys invalidates the ability to issue new delegations; existing bundles
remain verifiable.

## Deployment requirements for strong claims

1. The recorder is the only path from the agent to models and tools. Enforce with network policy;
   do not give the agent upstream credentials.
2. Anchoring is enabled and the verifier has independent access to the witness.
3. Agent keys are stored in a volume the agent process cannot read (or in an HSM/KMS in managed
   deployments); the Principal keys are offline.
4. Payload bodies that matter for evidence are retained or their deletion is tombstoned with a
   stated legal basis.
5. The delegation carries a `scope` that states what the agent may touch (`SEALEDRUN_SCOPE` on
   the recorder), so that "the agent stayed within its mandate" is a verifier result and not a
   reading exercise.
6. Steps that change a system outside the recorder's view carry a receipt (`receipt_for` /
   `receiptFor`), so that the auditor can check them against that system's log.

## Privacy

The chain never contains bodies, only digests. Bodies can be encrypted with an operator key or
deleted. A bundle shared with a verifier can therefore be complete for integrity purposes while
containing no personal data; the verifier sees sizes, labels, endpoints and hashes.
