"""SystemOne wire format: decision models that answer typed questions about a state.

Spoken by TypeSafe (Jev), OpenRouter (`/api/alpha/decisions` and `/api/v1/systemone`) and
Microsoft Foundry (`/providers/microsoft/v1/systemone`, Decision-1). The request carries
`model`, `state` and a map of `questions` (noul, choice or score, each with `criteria`); the
reply carries the same map of `answers` with probabilities, plus `id`, `model` and `usage`.
The recorder accepts all three public paths and forwards to `<upstream url>/systemone`, so an
OpenRouter upstream keeps its `/api/v1` base URL. Calls never stream.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, Request, Response

from sealedrun_recorder.proxy.core import (
    Dialect,
    Operation,
    forward,
    integer,
    mapping,
    require_proxy_token,
)
from sealedrun_recorder.proxy.openai import _is_probability, _probability, normalise_type


def _error_body(status: int, message: str) -> bytes:
    return json.dumps({"error": {"message": message, "type": "sealedrun_proxy_error"}}).encode()


def decisions_usage(reply: dict[str, Any]) -> dict[str, Any]:
    """Read the model snapshot and token counts from a SystemOne reply.

    `usage.cost` has no `sealedrun.llm` field and stays in the stored payload only.
    """
    llm: dict[str, Any] = {}
    model = reply.get("model")
    if isinstance(model, str) and model:
        llm["model"] = model
    usage = mapping(reply.get("usage"))
    for field in ("input_tokens", "output_tokens"):
        value = integer(usage.get(field))
        if value is not None:
            llm[field] = value
    return llm


def decision_from_systemone(call: dict[str, Any], reply: dict[str, Any]) -> dict[str, Any]:
    """Build `sealedrun.decision` (SPEC 10.7) from a SystemOne reply, map-shaped answers.

    `noul` becomes `predicate` with the probability as value. A `score` answer's `legend`
    (index -> label) renames the probability keys; without one the index strings stay. An
    answer marked `refused` or of type `refusal` keeps the question's type from the request.
    """
    questions = mapping(call.get("questions"))
    answers = []
    for name, raw in mapping(reply.get("answers")).items():
        raw = mapping(raw)
        kind = raw.get("type")
        if not isinstance(name, str) or not name or not isinstance(kind, str):
            continue
        answer: dict[str, Any] = {"name": name}
        if kind == "refusal" or raw.get("refused") is True:
            asked = mapping(questions.get(name)).get("type")
            answer["type"] = normalise_type(asked if isinstance(asked, str) else kind)
            if answer["type"] == "refusal":
                answer["type"] = "predicate"
            answer["refused"] = True
            answers.append(answer)
            continue
        answer["type"] = normalise_type(kind)
        if kind == "noul":
            answer.update(_probability("value", raw.get("noul")))
        elif kind == "choice":
            if isinstance(raw.get("choice"), str):
                answer["value"] = raw["choice"]
            answer.update(_probabilities(raw, {}))
        elif kind == "score":
            score = raw.get("score")
            if isinstance(score, int | float) and not isinstance(score, bool):
                answer["value"] = score
            legend = {k: v for k, v in mapping(raw.get("legend")).items() if isinstance(v, str)}
            answer.update(_probabilities(raw, legend))
        else:
            continue
        answer.update(_probability("confidence", raw.get("confidence")))
        answers.append(answer)
    return {"sealedrun.decision": {"answers": answers}} if answers else {}


def _probabilities(raw: dict[str, Any], legend: dict[str, str]) -> dict[str, Any]:
    probabilities = {
        legend.get(key, key): value
        for key, value in mapping(raw.get("probabilities")).items()
        if _is_probability(value)
    }
    return {"probabilities": probabilities} if probabilities else {}


SYSTEMONE = Dialect(
    "systemone",
    _error_body,
    reply_passthrough=("retry-after", "x-request-id"),
    reply_prefixes=("x-ratelimit-",),
)
DECISIONS = Operation(
    SYSTEMONE, "decisions", "/systemone", decisions_usage, extract=decision_from_systemone
)

router = APIRouter(dependencies=[Depends(require_proxy_token)])


@router.post("/api/alpha/decisions")
@router.post("/api/v1/systemone")
@router.post("/providers/microsoft/v1/systemone")
async def decisions(request: Request) -> Response:
    """Forward a decision call on any of the three public paths and record it."""
    return await forward(request, DECISIONS)
