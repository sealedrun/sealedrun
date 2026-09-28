"""Report steps from your own code to a running recorder.

`Recorder` posts self-reported steps to `POST /api/steps`; the recorder validates and signs each
one onto the live run named by the run label (the same label the proxies use), so in-process
actions such as SQL, files or shell commands sit in one chain with the proxied model calls.
Only the standard library is used, so the package stays dependency-free.

    recorder = Recorder("http://127.0.0.1:8080", token="...", run="nightly")
    with recorder.step("tool_call", name="db.query", provider="postgres") as step:
        step.request = sql
        step.response = rows
    @recorder.tool("fetch_page")
    def fetch_page(url: str) -> str: ...

A step whose body raises records outcome `error` and re-raises. Unlike the MCP wrapper, a
recorder that refuses or cannot be reached raises `RecorderError`: the caller asked for the
record, so silence would be a lie.
"""

from __future__ import annotations

import functools
import inspect
import json
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, ParamSpec, TypeVar

from sealedrun.errors import SealedRunError

DEFAULT_TIMEOUT = 5.0
JSON = "application/json"
TARGET_TYPES = {
    "llm_call": "model",
    "tool_call": "tool",
    "memory_read": "memory",
    "memory_write": "memory",
    "human_approval": "human",
    "policy_decision": "none",
    "note": "none",
}

P = ParamSpec("P")
R = TypeVar("R")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: the bearer token must not travel to a host we did not name."""

    def redirect_request(
        self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect())


class RecorderError(SealedRunError):
    """The recorder refused the step or could not be reached; `status` is the HTTP code or 0."""

    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


def post_step(
    url: str,
    step: dict[str, Any],
    *,
    token: str | None = None,
    run: str | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """POST one step to `url` and return the recorder's answer; raises RecorderError."""
    headers = {"Content-Type": JSON}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if run:
        headers["X-SealedRun-Run"] = run
    request = urllib.request.Request(  # noqa: S310
        f"{url.rstrip('/')}/api/steps",
        data=json.dumps(step).encode(),
        headers=headers,
        method="POST",
    )
    try:
        with _OPENER.open(request, timeout=timeout) as reply:
            answer: dict[str, Any] = json.loads(reply.read() or b"{}")
            return answer
    except urllib.error.HTTPError as error:
        if 300 <= error.code < 400:
            raise RecorderError(
                f"recorder at {public_url(url)} redirected ({error.code}); not followed",
                error.code,
            ) from error
        detail = error.read(300).decode(errors="replace")
        raise RecorderError(f"recorder answered {error.code}: {detail}", error.code) from error
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise RecorderError(f"recorder unreachable at {public_url(url)}: {error}") from error


def public_url(url: str) -> str:
    """Return `url` without userinfo, safe for messages."""
    scheme, _, rest = url.partition("://")
    return f"{scheme}://{rest.rpartition('@')[2]}"


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, default=repr)
    except (TypeError, ValueError):
        return repr(value)


@dataclass
class Step:
    """One step being reported; set `request`, `response`, `outcome` inside the `with` block."""

    kind: str
    target: dict[str, Any]
    request: Any = None
    response: Any = None
    outcome: str = "success"
    data_labels: list[str] = field(default_factory=list)
    extensions: dict[str, Any] = field(default_factory=dict)
    actor: dict[str, str] | None = None
    record: dict[str, Any] | None = None

    def body(self) -> dict[str, Any]:
        """Return the JSON body posted to `/api/steps`."""
        body: dict[str, Any] = {
            "kind": self.kind,
            "target": self.target,
            "outcome": self.outcome,
            "data_labels": self.data_labels,
            "extensions": self.extensions,
        }
        if self.actor is not None:
            body["actor"] = self.actor
        for side, value in (("request", self.request), ("response", self.response)):
            text = _text(value)
            if text is not None:
                body[side] = text
                body[f"{side}_media_type"] = (
                    "text/plain" if isinstance(value, str | bytes) else JSON
                )
        return body


class Recorder:
    """Post steps to one recorder under one run label."""

    def __init__(
        self,
        url: str,
        *,
        token: str | None = None,
        run: str | None = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        if not url.startswith(("http://", "https://")):
            raise ValueError("url must start with http:// or https://")
        self.url = url.rstrip("/")
        self.token = token
        self.run = run
        self.timeout = timeout

    def record(
        self,
        kind: str,
        name: str,
        *,
        request: Any = None,
        response: Any = None,
        outcome: str = "success",
        provider: str | None = None,
        location: str = "local",
        endpoint: str | None = None,
        target_type: str | None = None,
        data_labels: list[str] | None = None,
        extensions: dict[str, Any] | None = None,
        actor: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Post one finished step and return the signed record."""
        step = Step(
            kind,
            self._target(kind, name, provider, location, endpoint, target_type),
            request=request,
            response=response,
            outcome=outcome,
            data_labels=list(data_labels or []),
            extensions=dict(extensions or {}),
            actor=actor,
        )
        return self.post(step)

    def step(
        self,
        kind: str,
        name: str,
        *,
        provider: str | None = None,
        location: str = "local",
        endpoint: str | None = None,
        target_type: str | None = None,
        data_labels: list[str] | None = None,
        extensions: dict[str, Any] | None = None,
    ) -> _StepContext:
        """Return a context manager that posts the step when the block ends.

        An exception in the block sets outcome `error`, puts the exception's name and text
        in the response, posts the step and re-raises.
        """
        step = Step(
            kind,
            self._target(kind, name, provider, location, endpoint, target_type),
            data_labels=list(data_labels or []),
            extensions=dict(extensions or {}),
        )
        return _StepContext(self, step)

    def tool(
        self,
        name: str | None = None,
        *,
        provider: str | None = None,
        location: str = "local",
        data_labels: list[str] | None = None,
    ) -> Callable[[Callable[P, R]], Callable[P, R]]:
        """Decorate a sync or async function so each call is a `tool_call` record.

        The record's request is the call's arguments as JSON, the response its return value.
        """

        def decorate(function: Callable[P, R]) -> Callable[P, R]:
            tool_name = name or function.__name__

            if inspect.iscoroutinefunction(function):

                @functools.wraps(function)
                async def run_async(*args: P.args, **kwargs: P.kwargs) -> Any:
                    with self.step(
                        "tool_call",
                        tool_name,
                        provider=provider,
                        location=location,
                        data_labels=data_labels,
                    ) as step:
                        step.request = _arguments(function, args, kwargs)
                        result = await function(*args, **kwargs)
                        step.response = result
                    return result

                return run_async  # type: ignore[return-value]

            @functools.wraps(function)
            def run_sync(*args: P.args, **kwargs: P.kwargs) -> R:
                with self.step(
                    "tool_call",
                    tool_name,
                    provider=provider,
                    location=location,
                    data_labels=data_labels,
                ) as step:
                    step.request = _arguments(function, args, kwargs)
                    result = function(*args, **kwargs)
                    step.response = result
                return result

            return run_sync

        return decorate

    def post(self, step: Step) -> dict[str, Any]:
        """Post a prepared `Step`; stores and returns the signed record."""
        step.record = post_step(
            self.url, step.body(), token=self.token, run=self.run, timeout=self.timeout
        )
        return step.record

    @staticmethod
    def _target(
        kind: str,
        name: str,
        provider: str | None,
        location: str,
        endpoint: str | None,
        target_type: str | None,
    ) -> dict[str, Any]:
        target: dict[str, Any] = {
            "type": target_type or TARGET_TYPES.get(kind, "tool"),
            "name": name,
            "location": location,
        }
        if provider:
            target["provider"] = provider
        if endpoint:
            target["endpoint"] = endpoint
        return target


class _StepContext:
    def __init__(self, recorder: Recorder, step: Step) -> None:
        self._recorder = recorder
        self._step = step

    def __enter__(self) -> Step:
        return self._step

    def __exit__(self, exc_type: Any, exc: BaseException | None, _tb: Any) -> None:
        if exc is not None:
            self._step.outcome = "error"
            if self._step.response is None:
                self._step.response = f"{type(exc).__name__}: {exc}"
        self._recorder.post(self._step)


def _arguments(function: Callable[..., Any], args: Any, kwargs: Any) -> dict[str, Any]:
    try:
        bound = inspect.signature(function).bind_partial(*args, **kwargs)
        return dict(bound.arguments)
    except (TypeError, ValueError):
        return {"args": list(args), "kwargs": dict(kwargs)}
