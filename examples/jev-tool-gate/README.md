# A shell tool gated by a decision model, recorded by SealedRun

Before the agent runs a shell command, Jev (TypeSafe's decision model, served by OpenRouter)
answers two typed questions about it: does it touch production data, and how severe is it.
The decision call goes through the recorder's proxy, the program applies its thresholds and
reports the verdict with `record_gate`, then runs the command or refuses it. One run holds the
whole chain: question, probabilities, threshold, verdict, and the tool call that ran or did not.

Needs: Python 3.12+, `uv`, the recorder, and an OpenRouter key (one call costs well under a
tenth of a cent).

```bash
# 1. recorder on :8080 with this folder's upstreams file
export SEALEDRUN_API_TOKEN=change-me OPENROUTER_API_KEY=sk-or-...
SEALEDRUN_UPSTREAMS_FILE=./upstreams.yaml uv run --project ../.. sealedrun-recorder

# 2. the gate (another shell)
uv sync
export SEALEDRUN_TOKEN=change-me
uv run gate.py "rm -rf /var/lib/postgres" prod-db-1      # block
uv run gate.py "ls /tmp" ci-box                          # approve, runs the command

# 3. export without payload bodies and verify: the verdict is still in the records
curl -s -H "Authorization: Bearer change-me" http://127.0.0.1:8080/api/runs | jq -r '.[0].run_id'
curl -s -X POST -H "Authorization: Bearer change-me" \
  "http://127.0.0.1:8080/api/runs/<run_id>/export?payloads=omit&end=true" -o run.zip
PRINCIPAL=$(curl -s -H "Authorization: Bearer change-me" http://127.0.0.1:8080/api/identity | jq -r .principal_id)
uv run --project ../.. python -m sealedrun run.zip $PRINCIPAL   # or drop run.zip on http://127.0.0.1:8080
```

In the Inspector the decision call shows a bar per answer with the threshold drawn on it and a
link to the gate step; the gate step links back.

What the run proves: that this model, at that time, given exactly that state, returned those
probabilities, and that this program compared them against those thresholds and did what it
says. What it does not prove: that the model was right. A threshold is a policy choice; keep
it with the model version it was tuned for (a rebased model shifts the calibration).

Tests run without a model or a recorder: `uv run pytest`.
