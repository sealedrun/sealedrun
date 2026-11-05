# Langfuse trace and SealedRun record of the same model call

Langfuse shows what the agent did so you can debug it. A trace in Langfuse can be edited by
whoever runs the database, so it is not evidence. This example keeps both: the call is traced in
Langfuse and sealed in a SealedRun run, and the Langfuse trace id is the run label, so each side
leads to the other.

How it is wired: the agent uses Langfuse's OpenAI client (`from langfuse.openai import OpenAI`)
and points it at the recorder's LLM proxy. Langfuse gets the trace from the client; the recorder
signs the request and the reply that actually went over the wire. The trace id travels in the
`X-SealedRun-Run` header.

Needs: Python 3.12+, `uv`, the recorder, a Langfuse project (cloud or self-hosted, Langfuse v4 for
the Python SDK v5), and Ollama with `qwen3:8b` (or an OpenAI key).

```bash
# 1. recorder on :8080 with this folder's upstreams file
export SEALEDRUN_API_TOKEN=change-me OPENAI_API_KEY=sk-...   # OPENAI_API_KEY only for gpt-*
SEALEDRUN_UPSTREAMS_FILE=./upstreams.yaml uv run --project ../.. sealedrun-recorder

# 2. the agent (another shell)
uv sync
export SEALEDRUN_TOKEN=change-me
export LANGFUSE_PUBLIC_KEY=pk-lf-... LANGFUSE_SECRET_KEY=sk-lf-...
export LANGFUSE_BASE_URL=https://cloud.langfuse.com   # or your own host
uv run agent.py                                       # MODEL=gpt-4.1-mini uv run agent.py for OpenAI

# 3. export the run named by the trace id and verify it
TRACE=<trace id the agent printed>
RUN=$(curl -s -H "Authorization: Bearer change-me" "http://127.0.0.1:8080/api/runs?q=$TRACE" | jq -r '.[0].run_id')
curl -s -X POST -H "Authorization: Bearer change-me" \
  "http://127.0.0.1:8080/api/runs/$RUN/export?end=true" -o run.zip
PRINCIPAL=$(curl -s -H "Authorization: Bearer change-me" http://127.0.0.1:8080/api/identity | jq -r .principal_id)
uv run --project ../.. python -m sealedrun run.zip $PRINCIPAL
```

In Langfuse the trace holds a `sealedrun-example` span with `sealedrun_run` in its metadata and
the model call under it. In the recorder the run's `run_start` record carries the trace id as
`run_label`, followed by one `llm_call` record with the digests of the request and the reply.

The two copies answer different questions. Langfuse: what happened, how long it took, what it
cost. The bundle: can a third party check that this is what was sent and received, and that
nobody changed it since. Only calls made through the proxy are sealed; a call the agent makes
around it appears in Langfuse and not in the run.

Tests: `uv run pytest` (no model, recorder or Langfuse needed).
