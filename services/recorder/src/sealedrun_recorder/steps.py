"""Self-reported steps: records an agent or a wrapper posts to `/api/steps`.

A step arrives as JSON, is checked against the record schema pieces it fills (kind, target,
outcome, policy, extensions) before anything is sealed, and is then appended to a live run like
a proxied call. Payload bodies come as text or base64 and are stored like proxy payloads.
"""

from __future__ import annotations

import base64
import binascii
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from sealedrun.schema import validate_extensions, validator

SELF_REPORTED_KINDS = frozenset(
    {
        "llm_call",
        "tool_call",
        "memory_read",
        "memory_write",
        "policy_decision",
        "human_approval",
        "note",
    }
)
OUTCOMES = frozenset({"success", "error", "blocked", "pending", "timeout"})


class StepError(ValueError):
    """The posted step cannot become a record; the message says why."""


class Step(BaseModel):
    """One self-reported step as posted; `request`/`response` are the payload bodies.

    `occurred_at` is not accepted: SPEC 5.1 has the recorder's clock set it.
    """

    model_config = ConfigDict(extra="forbid")

    kind: str
    target: dict[str, Any]
    actor: dict[str, str] | None = None
    outcome: str = "success"
    data_labels: list[str] = Field(default_factory=list)
    policy: dict[str, Any] | None = None
    parent_record_id: str | None = None
    extensions: dict[str, Any] = Field(default_factory=dict)
    request: str | None = None
    response: str | None = None
    request_base64: str | None = None
    response_base64: str | None = None
    request_media_type: str | None = None
    response_media_type: str | None = None

    def tools_list(self) -> dict[str, Any] | None:
        """Return server, transport, cursor and result of a `tools/list` step, else None.

        A step counts as a listing when its `sealedrun.mcp` extension says so and its response
        holds a JSON-RPC result; the cursor comes from the request's params.
        """
        mcp = self.extensions.get("sealedrun.mcp")
        if not isinstance(mcp, dict) or mcp.get("method") != "tools/list":
            return None
        try:
            request = json.loads(self.request or "null")
            response = json.loads(self.response or "null")
        except ValueError:
            return None
        if not isinstance(response, dict) or "result" not in response:
            return None
        params = request.get("params") if isinstance(request, dict) else None
        cursor = params.get("cursor") if isinstance(params, dict) else None
        return {
            "server": str(mcp.get("server")),
            "transport": str(mcp.get("transport")),
            "cursor": cursor if isinstance(cursor, str) else None,
            "result": response["result"],
        }

    def fields(self) -> dict[str, Any]:
        """Return the keyword arguments for `LiveRuns.append` after every check passed."""
        fields: dict[str, Any] = {
            "check": True,
            "target": self.target,
            "outcome": self.outcome,
            "data_labels": self.data_labels,
            "request": _body(self.request, self.request_base64),
            "response": _body(self.response, self.response_base64),
            "request_media_type": self.request_media_type,
            "response_media_type": self.response_media_type,
        }
        if self.actor is not None:
            fields["actor"] = self.actor
        if self.policy is not None:
            fields["policy"] = self.policy
        if self.parent_record_id is not None:
            fields["parent_record_id"] = self.parent_record_id
        if self.extensions:
            fields["extensions"] = self.extensions
        return fields


def parse_step(body: bytes) -> Step:
    """Parse and check a posted step; raises StepError with the first problem found."""
    try:
        data = json.loads(body)
    except ValueError as error:
        raise StepError("body must be JSON") from error
    if not isinstance(data, dict):
        raise StepError("body must be a JSON object")
    try:
        step = Step.model_validate(data)
    except ValidationError as error:
        first = error.errors()[0]
        where = "/".join(str(p) for p in first["loc"]) or "$"
        raise StepError(f"{where}: {first['msg']}") from error
    if step.kind not in SELF_REPORTED_KINDS:
        raise StepError(f"kind must be one of {', '.join(sorted(SELF_REPORTED_KINDS))}")
    if step.outcome not in OUTCOMES:
        raise StepError(f"outcome must be one of {', '.join(sorted(OUTCOMES))}")
    for name, value in (("target", step.target), ("policy", step.policy)):
        if value is None:
            continue
        errors = _validate_def(name, value)
        if errors:
            raise StepError(f"{name}/{errors[0]}")
    if not all(isinstance(label, str) and label for label in step.data_labels):
        raise StepError("data_labels must be non-empty strings")
    errors = validate_extensions(step.extensions, first_only=True)
    if errors:
        raise StepError(errors[0])
    if step.request is not None and step.request_base64 is not None:
        raise StepError("request and request_base64 are exclusive")
    if step.response is not None and step.response_base64 is not None:
        raise StepError("response and response_base64 are exclusive")
    for side, encoded in (("request", step.request_base64), ("response", step.response_base64)):
        if encoded is not None:
            try:
                base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError) as error:
                raise StepError(f"{side}_base64 is not valid base64") from error
    return step


def _validate_def(name: str, value: Any) -> list[str]:
    record = validator("record.json")
    schema = record.schema
    assert isinstance(schema, dict)
    sub = record.evolve(
        schema={"$id": schema["$id"], "$ref": f"#/$defs/{name}", "$defs": schema["$defs"]}
    )
    return sorted(
        f"{'/'.join(str(p) for p in e.absolute_path) or '$'}: {e.message[:200]}"
        for e in sub.iter_errors(value)
    )


def _body(text: str | None, encoded: str | None) -> bytes | None:
    if text is not None:
        return text.encode()
    if encoded is not None:
        return base64.b64decode(encoded, validate=True)
    return None
