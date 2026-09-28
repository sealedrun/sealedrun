"""Size caps shared by everything that reads a body: requests, upstream replies, witnesses.

A body is read chunk by chunk and dropped as soon as it passes the cap, so a client that omits
`Content-Length` (chunked transfer) or an upstream that answers with a huge or compressed body
cannot make the recorder hold more than the cap in memory. Deeply nested JSON is refused too:
Python's parser recurses once per level and would otherwise fail with RecursionError.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
from fastapi import Request


class BodyTooLargeError(Exception):
    """The body passed the cap; the message says which body."""


async def read_body(request: Request, limit: int) -> bytes:
    """Read the request body up to `limit` bytes; raises BodyTooLargeError past it.

    A `Content-Length` above the cap is refused before any byte is read. The body is cached on
    the request, so a later `request.body()` sees the same bytes.
    """
    declared = request.headers.get("content-length", "")
    if declared.isdigit() and int(declared) > limit:
        raise BodyTooLargeError("request body exceeds size limit")
    if hasattr(request, "_body"):
        body: bytes = request._body
        if len(body) > limit:
            raise BodyTooLargeError("request body exceeds size limit")
        return body
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise BodyTooLargeError("request body exceeds size limit")
        chunks.append(chunk)
    body = b"".join(chunks)
    request._body = body
    return body


async def read_reply(reply: httpx.Response, limit: int) -> bytes:
    """Read a streamed upstream reply up to `limit` bytes and close it; BodyTooLargeError past it.

    Chunks arrive decoded, so a compressed reply is capped by its real size, not its wire size.
    """
    chunks: list[bytes] = []
    size = 0
    try:
        async for chunk in reply.aiter_bytes():
            size += len(chunk)
            if size > limit:
                raise BodyTooLargeError("upstream reply exceeds size limit")
            chunks.append(chunk)
    finally:
        await reply.aclose()
    return b"".join(chunks)


def parse_json(body: bytes | str) -> Any:
    """Parse JSON; raises ValueError for malformed text and for nesting too deep to parse."""
    try:
        return json.loads(body)
    except RecursionError as error:
        raise ValueError("JSON nesting too deep") from error
