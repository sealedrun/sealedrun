"""Trace a model call in Langfuse and seal the same call in a SealedRun run.

Langfuse's OpenAI client records the call as a trace. The client is pointed at the recorder's
LLM proxy, so the request that reaches the model is also one signed record. The Langfuse trace
id is sent as the run label (`X-SealedRun-Run`): from a trace you find the sealed run by that
id, and from a run you find the trace.
"""

from __future__ import annotations

import os

from langfuse import get_client
from langfuse.openai import OpenAI

RECORDER = os.environ.get("SEALEDRUN_URL", "http://127.0.0.1:8080")
TOKEN = os.environ.get("SEALEDRUN_TOKEN", "")
MODEL = os.environ.get("MODEL", "qwen3:8b")
QUESTION = "In one sentence: why does an auditor want a signed record of a model call?"


def ask(question: str) -> tuple[str, str]:
    """Ask the model through the recorder; return its answer and the Langfuse trace id."""
    langfuse = get_client()
    with langfuse.start_as_current_observation(as_type="span", name="sealedrun-example") as span:
        trace_id = langfuse.get_current_trace_id()
        if trace_id is None:
            raise RuntimeError("Langfuse is not configured: set LANGFUSE_PUBLIC_KEY and the rest")
        client = OpenAI(
            base_url=f"{RECORDER}/v1",
            api_key=TOKEN,
            default_headers={"X-SealedRun-Run": trace_id},
        )
        reply = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": question}],
        )
        answer = reply.choices[0].message.content or ""
        span.update(input=question, output=answer, metadata={"sealedrun_run": trace_id})
    langfuse.flush()
    return answer, trace_id


def main() -> None:
    """Run the example and print where to find the call in both systems."""
    answer, trace_id = ask(QUESTION)
    print(answer.strip())
    print(f"Langfuse trace: {trace_id}")
    print(f"SealedRun run:  {RECORDER}/api/runs?q={trace_id}")


if __name__ == "__main__":
    main()
