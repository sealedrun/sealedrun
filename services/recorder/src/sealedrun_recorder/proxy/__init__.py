"""LLM proxy: every supported wire format, recorded into live runs."""

from typing import Any

from fastapi import APIRouter, Depends, Request

from sealedrun_recorder.proxy import anthropic, gemini, ollama, openai
from sealedrun_recorder.proxy.core import RunGrouper, require_proxy_token

router = APIRouter()
router.include_router(openai.router)
router.include_router(anthropic.router)
router.include_router(ollama.router)
router.include_router(gemini.router)


@router.get("/v1/models", dependencies=[Depends(require_proxy_token)])
async def models(request: Request) -> dict[str, Any]:
    """List models in the shape of the asking SDK.

    OpenAI and Anthropic share this path; the Anthropic SDKs always send `anthropic-version`.
    """
    if "anthropic-version" in request.headers:
        return await anthropic.list_models(request)
    return await openai.list_models(request)


__all__ = ["RunGrouper", "router"]
