"""System instructions readers per wire format (SPEC 10.1 `system_prompt_hash`)."""

from __future__ import annotations

from sealedrun_recorder.proxy import prompt


def test_openai_chat_joins_system_and_developer_messages_in_order() -> None:
    call = {
        "messages": [
            {"role": "system", "content": "Be brief."},
            {"role": "user", "content": "hi"},
            {"role": "developer", "content": [{"type": "text", "text": "Use JSON."}]},
        ]
    }
    assert prompt.openai_chat(call) == b"Be brief.\nUse JSON."
    assert prompt.openai_chat({"messages": [{"role": "user", "content": "hi"}]}) is None
    assert prompt.openai_chat({}) is None


def test_openai_responses_reads_instructions_then_system_items() -> None:
    call = {
        "instructions": "Be brief.",
        "input": [
            {"role": "developer", "content": "Use JSON."},
            {"role": "user", "content": "hi"},
        ],
    }
    assert prompt.openai_responses(call) == b"Be brief.\nUse JSON."
    assert prompt.openai_responses({"input": "hi"}) is None


def test_anthropic_system_string_or_blocks() -> None:
    assert prompt.anthropic_messages({"system": "Be brief."}) == b"Be brief."
    blocks = [{"type": "text", "text": "Be brief."}, {"type": "text", "text": "Use JSON."}]
    assert prompt.anthropic_messages({"system": blocks}) == b"Be brief.\nUse JSON."
    assert prompt.anthropic_messages({"messages": []}) is None


def test_ollama_chat_and_generate() -> None:
    call = {
        "messages": [{"role": "system", "content": "Be brief."}, {"role": "user", "content": "x"}]
    }
    assert prompt.ollama_chat(call) == b"Be brief."
    assert prompt.ollama_generate({"system": "Be brief.", "prompt": "x"}) == b"Be brief."
    assert prompt.ollama_generate({"prompt": "x"}) is None


def test_gemini_system_instruction_parts() -> None:
    call = {"systemInstruction": {"parts": [{"text": "Be brief."}, {"text": "Use JSON."}]}}
    assert prompt.gemini_generate(call) == b"Be brief.\nUse JSON."
    assert prompt.gemini_generate({"system_instruction": {"parts": [{"text": "x"}]}}) == b"x"
    assert prompt.gemini_generate({"contents": []}) is None


def test_empty_system_prompt_differs_from_none() -> None:
    assert prompt.openai_chat({"messages": [{"role": "system", "content": ""}]}) == b""
