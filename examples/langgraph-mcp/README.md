# LangGraph agent with a filesystem MCP tool, recorded by SealedRun

One question, one tool, one signed run: the agent asks a model what a file is about, the
model calls the filesystem MCP server, the answer comes back. The model calls go through the
recorder's LLM proxy and the MCP server runs under `sealedrun-mcp-wrap`, so the run holds both.

Needs: Python 3.12+, `uv`, Node (for `npx`), the recorder, and Ollama with `qwen3:8b` (or an
OpenAI key).

```bash
# 1. recorder on :8080 with this folder's upstreams file
export SEALEDRUN_API_TOKEN=change-me OPENAI_API_KEY=sk-...   # OPENAI_API_KEY only for openai:*
SEALEDRUN_UPSTREAMS_FILE=./upstreams.yaml uv run --project ../.. sealedrun-recorder

# 2. the agent (another shell)
uv sync
export SEALEDRUN_TOKEN=change-me
uv run agent.py                       # MODEL=openai:gpt-4.1-mini uv run agent.py for OpenAI

# 3. export and verify
curl -s -H "Authorization: Bearer change-me" http://127.0.0.1:8080/api/runs | jq -r '.[0].run_id'
curl -s -X POST -H "Authorization: Bearer change-me" \
  "http://127.0.0.1:8080/api/runs/<run_id>/export?end=true" -o run.zip
PRINCIPAL=$(curl -s -H "Authorization: Bearer change-me" http://127.0.0.1:8080/api/identity | jq -r .principal_id)
uv run --project ../.. python -m sealedrun run.zip $PRINCIPAL   # or drop run.zip on http://127.0.0.1:8080
```

The run shows `llm_call` records for the model and `tool_call` records (`transport: stdio`) for
`tools/list` and `read_file`, chained and signed by the recorder. Coding agents on Ollama send
long prompts; if the model ignores the tool, raise the context (`OLLAMA_CONTEXT_LENGTH=16384`).
