"""System instructions of a model request, per wire format (SPEC 10.1 `system_prompt_hash`).

Each reader returns the bytes a verifier's `system_prompt_hash` commits to: the system (and
developer) instructions of the request, in order, joined by a newline, UTF-8. A request without
such instructions yields None and the record carries no hash, so that "no system prompt" and
"empty system prompt" stay distinguishable.
"""

from __future__ import annotations

from typing import Any

SYSTEM_ROLES = frozenset({"system", "developer"})


def _texts(parts: Any) -> list[str]:
    """Flatten a string, or a list of strings and `{"text": …}` blocks, into its texts."""
    if isinstance(parts, str):
        return [parts]
    out: list[str] = []
    if isinstance(parts, list):
        for part in parts:
            if isinstance(part, str):
                out.append(part)
            elif isinstance(part, dict) and isinstance(part.get("text"), str):
                out.append(part["text"])
    return out


def _joined(texts: list[str]) -> bytes | None:
    return "\n".join(texts).encode() if texts else None


def _from_messages(messages: Any) -> list[str]:
    texts: list[str] = []
    if isinstance(messages, list):
        for message in messages:
            if isinstance(message, dict) and message.get("role") in SYSTEM_ROLES:
                texts.extend(_texts(message.get("content")))
    return texts


def openai_chat(call: dict[str, Any]) -> bytes | None:
    """`messages[].role in (system, developer)` of a Chat Completions request."""
    return _joined(_from_messages(call.get("messages")))


def openai_responses(call: dict[str, Any]) -> bytes | None:
    """`instructions`, then system or developer items of `input`, of a Responses request."""
    texts = _texts(call.get("instructions"))
    texts.extend(_from_messages(call.get("input")))
    return _joined(texts)


def anthropic_messages(call: dict[str, Any]) -> bytes | None:
    """Top-level `system` (a string or text blocks) of a Messages request."""
    return _joined(_texts(call.get("system")))


def ollama_chat(call: dict[str, Any]) -> bytes | None:
    """`messages[].role == system` of an Ollama chat request."""
    return _joined(_from_messages(call.get("messages")))


def ollama_generate(call: dict[str, Any]) -> bytes | None:
    """Top-level `system` of an Ollama generate request."""
    return _joined(_texts(call.get("system")))


def gemini_generate(call: dict[str, Any]) -> bytes | None:
    """`systemInstruction.parts[].text` (or `system_instruction`) of a generateContent request."""
    instruction = call.get("systemInstruction", call.get("system_instruction"))
    if isinstance(instruction, str):
        return _joined([instruction])
    if isinstance(instruction, dict):
        return _joined(_texts(instruction.get("parts")))
    return None
