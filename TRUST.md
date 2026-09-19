# What an SealedRun bundle proves, and what it does not

License: CC-BY-4.0. Companion to `SPEC.md`.

## Parties

- **Operator**: runs the recorder and holds the Agent keys. Usually the same organisation as the
  Principal.
- **Principal**: the accountable party whose keys sign delegations.
- **Verifier**: auditor, insurer, counterparty, regulator. Has the bundle and public keys.
  Does not trust the operator.
- **Witness**: an external log (Sigstore Rekor, RFC 3161 timestamp authority, SCITT) the operator
  does not control.

## What a valid bundle proves

| Claim                                                                                            | Mechanism                                                  |
| ------------------------------------------------------------------------------------------------ | ---------------------------------------------------------- |
| These records were produced in this order and none was inserted, removed or reordered later      | Hash chain over JCS bytes with `seq` and `prev_hash`       |
| Each record was signed by the key set identified by `agent_id`                                   | Hybrid Ed25519 + ML-DSA-65 signatures over the record hash |
| That agent was authorised by the Principal for the time window of the run                        | Delegation signed by Principal keys, bound in `run_start`  |
| The request and response bodies, if present, are the ones the agent saw                          | Payload digests inside the signed record                   |
| A body that is now missing existed with this digest and was removed at this time for this reason | `tombstone` record                                         |
| The chain head existed no later than the witness time                                            | `anchor` record with a witness receipt                     |
| A labelled item went to this endpoint under this policy rule                                     | `data_labels`, `target`, `policy` inside the signed record |
| The bundle files were not altered after export                                                   | Manifest `files` digests and exporter signature            |

## What it does not prove

- **That the agent did nothing else.** Only steps that passed through the recorder or SDK are
  recorded. A tool that calls the network directly, a model reached without the proxy, or an SDK
  that was bypassed leaves no record. Completeness depends on deployment: the recorder must be
  the only egress for the agent (network policy, no direct credentials in the agent).
- **That the model output is true or the reasoning was sound.** SealedRun records what was sent and
  received, not whether it was correct.
- **That the labels are correct.** A label is the output of a classifier, a regex, or a source
  annotation. The record proves which label was attached and by what, not that the data really is
  PII.
- **That the operator's clock is right.** `occurred_at` is the recorder's clock. Only anchors
  give an externally attested upper bound on time.
- **Anything about steps before a key compromise was detected.** See "Key compromise".

## Attacks and how they are handled

| Attack                                                          | Detected by                                                    | Notes                                                                 |
| --------------------------------------------------------------- | -------------------------------------------------------------- | --------------------------------------------------------------------- |
| Edit a field in a stored record                                 | Hash recomputation fails                                       |                                                                       |
| Delete a record from the middle of a run                        | `seq` gap or `prev_hash` mismatch                              |                                                                       |
| Truncate the tail of a run                                      | Missing `run_end`; last anchored hash absent from the run      | Only detectable with anchors or a later bundle that continues the run |
| Insert a back-dated record                                      | `prev_hash` linkage fails for every later record               |                                                                       |
| Replace a payload body                                          | Payload digest mismatch                                        |                                                                       |
| Forge a record with a different key                             | Signature verification fails; `agent_id` not in any delegation |                                                                       |
| Operator re-signs the whole run with the real Agent key         | Anchored hashes no longer appear in the run                    | This is why anchors are part of the MVP, not an option                |
| Operator rewrites the run **and** all anchors                   | Witness log entries cannot be removed by the operator          | Verifier must query the witness or hold a copy of the receipts        |
| Replay a Delegation or Manifest signature as a Record signature | Domain separation in the signing input                         |                                                                       |
| Present an old, valid bundle as current                         | `created_at`, `complete` flag, anchor times                    | Verifier compares against the latest anchor known to them             |
| Record steps under an expired or future delegation              | `occurred_at` outside `[not_before, not_after]`                |                                                                       |
| Quantum adversary forges Ed25519 signatures                     | ML-DSA-65 signature still required                             | Hybrid profile                                                        |
| Implementation bug in the ML-DSA library                        | Ed25519 signature still required                               | Hybrid profile                                                        |
| Verifier and operator disagree on canonical bytes               | RFC 8785 and the test vectors                                  | Conformance is byte-for-byte                                          |

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

## Privacy

The chain never contains bodies, only digests. Bodies can be encrypted with an operator key or
deleted. A bundle shared with a verifier can therefore be complete for integrity purposes while
containing no personal data; the verifier sees sizes, labels, endpoints and hashes.
