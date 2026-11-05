# AIUC-1 evidence from a SealedRun bundle

Read against AIUC-1 as published at [standard.aiuc-1.com](https://standard.aiuc-1.com/), Q4 2026
release (15 October 2026). The standard is revised every quarter; check the control text before
you hand this page to an auditor.

AIUC-1 certifies an agent, and the organisation that runs it provides the evidence. SealedRun is
not certified and does not make an agent compliant. It produces artifacts that an organisation can
submit for the controls below. Every row covers only steps that went through the recorder
(proxies, `sealedrun-mcp-wrap`, SDKs, OTLP ingest); [TRUST.md](../TRUST.md) states what a bundle
proves and what it does not.

## Controls

"Level" is the level of the control, then the group its evidence item sits in on the control page.

| Control                       | Level             | What to hand the auditor                                                                                                                                                                                  | Not covered                                                                         |
| ----------------------------- | ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| E015.1 Logging implementation | Mandatory, should | The bundle (`run.zip`): one signed record per model call, tool call, A2A call, memory read and approval, with payload digests, target, time and outcome                                                   | Bodies are optional; a bundle without them proves digests, not content              |
| E015.2 Agent logging          | Mandatory, may    | Tool call records, `human_approval` records, parent links between runs, the delegation with its `scope` and validity window                                                                               | Reasoning traces; `agent_software` is self-reported                                 |
| E015.3 Log storage            | Mandatory, should | Archived bundles; `tombstone` records for deleted bodies (digest, time, reason)                                                                                                                           | Retention schedule, access control and PII masking are the operator's               |
| E015.4 Log integrity          | Mandatory, may    | Verifier output: hash chain, hybrid signatures, RFC 3161 anchors, first failing record if anything changed                                                                                                | Tampering is detected, not prevented; the tail after the last anchor is unwitnessed |
| D003.1 Tool authorization     | Mandatory, should | Delegation `scope`, `upstreams.yaml`, `scope.*` findings                                                                                                                                                  | Parameter validation, per-user access rules                                         |
| D003.2 Rate limits            | Mandatory, should | `scope.max_records` finding                                                                                                                                                                               | Per-tool quotas, time windows, circuit breakers                                     |
| D003.3 Tool call log          | Mandatory, should | `sealedrun.mcp` in each `tool_call` record: server, tool, method, request id, protocol version, the server's self-reported name and version, time; parameters as a digest; scope violations listed by seq | MCP has no version per tool; alerts are the recipe below                            |
| D003.4 Human approval         | Mandatory, should | `human_approval` records and `approval.*` findings: the approved request bytes equal the executed ones                                                                                                    | Whether the approver was entitled; what counts as sensitive is the operator's rule  |
| C008.1 Behaviour trace        | Optional, should  | Signed trace per run; the seq at which the system prompt changed; labels sent to cloud targets                                                                                                            | Risk categories, sampling, dashboards                                               |
| C008.3 Security tooling       | Optional, may     | Records are JSON; the recipe below ships them to a SIEM                                                                                                                                                   | No built-in forwarder                                                               |

Nothing in SealedRun addresses D003.5 (periodic log review); that is a process.

## Produce the evidence

```sh
curl -s -X POST -H "Authorization: Bearer $SEALEDRUN_API_TOKEN" \
  "http://127.0.0.1:8080/api/runs/<run_id>/export?end=true" -o run.zip
python -m sealedrun run.zip <principal_id>
```

The verifier exits 0 when the bundle verifies and 1 when it does not. Findings (`scope.*`,
`approval.*`) are listed and do not change the exit code unless you ask.

## Alerts on scope and approval violations

Run the verifier on a schedule with the strict flags and let your scheduler raise the alert:

```sh
python -m sealedrun --strict-scope --strict-approval run.zip <principal_id> || notify-oncall
```

A non-zero exit means a record was outside the delegation, a required approval was missing, or
the bundle was altered. The first line of the output names the run, the seq and the check.
SealedRun sends nothing by itself: the recorder has no outbound alert channel, and the alert
comes from a verification anyone can repeat.

## Records in a SIEM

A bundle holds one JSON-lines file per run (`runs/<run_id>.jsonl`, one record per line), and
`GET /api/runs/{id}/records` returns the same records over HTTP. Point the log shipper you already
run (Vector, Fluent Bit, the Splunk or Datadog agent) at either. Records carry digests, not
bodies, so shipping the records alone sends no prompt or reply text; leave `payloads/` out.

The copy in the SIEM is a search index, not evidence: it can be edited there. Keep the bundle,
and verify the bundle when the question is whether a record is genuine.

## Verifier report in Vanta

A Vanta customer can upload evidence to their own account from a private integration, with no
SealedRun service in between. Create a private Build Integrations app in Vanta's Developer
Console, request a token with the `client_credentials` grant, and upload the bundle or the
verifier output to the document that tracks the control with
`POST /v1/documents/{documentId}/uploads`, then submit it. See Vanta's
[private integration quickstart](https://developer.vanta.com/docs/quickstart/build-private-integration)
and [document upload guide](https://developer.vanta.com/docs/guides/upload-a-document) for the
scopes your app needs; we have not run this against a Vanta account.
