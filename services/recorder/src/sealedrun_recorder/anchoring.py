"""Periodic anchoring of live runs at an RFC 3161 authority (SPEC 8).

One `Anchoring` per app: `loop` wakes every interval and anchors each open run whose head moved
since its last anchor; `anchor_run` does the same for one run on demand, before an export or
`run_end`. Each cycle writes one anchor record per configured witness: the time-stamp authority
(with its fallback) and, when set, the Rekor log, both over the same head. A witness that fails
never blocks a run: the failure is logged and the next cycle tries again. The anchor records go
through `LiveRuns.append`, so they are signed and chained like any other record.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any
from urllib.parse import urlsplit

import httpx
from sealedrun.anchors import rekor, rfc3161
from sealedrun.anchors.rekor import RekorError
from sealedrun.anchors.rfc3161 import AnchorError

from sealedrun_recorder.live import LiveRunError, LiveRuns
from sealedrun_recorder.settings import Settings

log = logging.getLogger("sealedrun.anchoring")

PEM_MARK = "-----BEGIN CERTIFICATE-----"


class Anchoring:
    """Time-stamps chain heads at the configured authorities and writes the anchor records."""

    def __init__(self, live: LiveRuns, http: httpx.AsyncClient, settings: Settings):
        self._live = live
        self._http = http
        self._urls = [u for u in (settings.anchor_tsa_url, settings.anchor_tsa_fallback_url) if u]
        self._rekor = settings.anchor_rekor_url.rstrip("/")
        self._interval = settings.anchor_interval_seconds
        self._timeout = settings.anchor_timeout_seconds
        self._chains: dict[str, list[str]] = {}
        self._busy: dict[str, asyncio.Lock] = {}

    @property
    def enabled(self) -> bool:
        """True when at least one witness URL is configured."""
        return bool(self._urls or self._rekor)

    async def loop(self) -> None:
        """Anchor every open run whose head moved, every `anchor_interval_seconds`."""
        while True:
            await asyncio.sleep(self._interval)
            for run_id in self._live.open_runs():
                await self.anchor_run(run_id)

    async def anchor_run(self, run_id: str) -> list[dict[str, Any]]:
        """Anchor the head of `run_id` unless it is already anchored or anchoring is off.

        Returns the anchor records written, in order (authority first, then the log); empty
        when nothing was written: anchoring off, run not open, the last record already an
        anchor, or every witness failed (logged).
        """
        if not self.enabled:
            return []
        async with self._busy.setdefault(run_id, asyncio.Lock()):
            try:
                seq, head, kind = self._live.head(run_id)
            except LiveRunError:
                return []
            if kind == "anchor":
                return []
            written = []
            if self._urls:
                receipt, url = await self._timestamp_any(run_id, head)
                if receipt is not None:
                    written.append(self._write(run_id, "rfc3161", url, seq, head, receipt))
            if self._rekor:
                receipt = await self._publish(run_id, head)
                if receipt is not None:
                    written.append(self._write(run_id, "rekor", self._rekor, seq, head, receipt))
            return [record for record in written if record is not None]

    def _write(
        self, run_id: str, type_: str, url: str, seq: int, head: str, receipt: dict[str, Any]
    ) -> dict[str, Any] | None:
        try:
            return self._live.append(
                run_id,
                "anchor",
                target={"type": "witness", "name": urlsplit(url).hostname or url, "endpoint": url},
                extensions={
                    "sealedrun.anchor": {
                        "type": type_,
                        "anchored_hash": head,
                        "anchored_seq": seq,
                        "receipt": receipt,
                        "witness": url,
                    }
                },
            )
        except LiveRunError as error:
            log.warning("anchor run=%s not written: %s", run_id, error)
            return None

    async def _timestamp_any(self, run_id: str, head: str) -> tuple[dict[str, Any] | None, str]:
        """Try the authority twice, then the fallback twice; None when all failed."""
        for url in self._urls:
            for attempt in (1, 2):
                try:
                    return await self._timestamp(url, head), url
                except (AnchorError, httpx.HTTPError) as error:
                    log.warning("anchor run=%s tsa=%s try=%d: %s", run_id, url, attempt, error)
        log.error("anchor run=%s: every authority failed, head %s not anchored", run_id, head)
        return None, ""

    async def _publish(self, run_id: str, head: str) -> dict[str, Any] | None:
        """Publish the head to the Rekor log as a `hashedrekord`; None when it failed."""
        key = self._live.identity.anchor_key
        public_key = self._live.identity.anchor_public_key
        signature = rekor.sign_head(key, head)
        try:
            reply = await self._http.post(
                self._rekor + rekor.ENTRIES_PATH,
                json=rekor.entry_for(head, signature, public_key),
                headers={"accept": "application/json"},
                timeout=self._timeout,
            )
            if reply.status_code not in (200, 201):
                raise RekorError(f"log answered {reply.status_code}")
            return rekor.receipt_from(reply.json(), self._rekor, head, signature, public_key)
        except (RekorError, httpx.HTTPError, ValueError) as error:
            log.warning("anchor run=%s rekor=%s: %s", run_id, self._rekor, error)
            return None

    async def _timestamp(self, url: str, head: str) -> dict[str, Any]:
        req = rfc3161.request(head)
        reply = await self._http.post(
            url,
            content=req.body,
            headers={"content-type": rfc3161.MEDIA_TYPE, "accept": "application/timestamp-reply"},
            timeout=self._timeout,
        )
        if reply.status_code != 200:
            raise AnchorError(f"authority answered {reply.status_code}")
        return rfc3161.receipt_from(req, reply.content, await self._chain(url))

    async def _chain(self, url: str) -> list[str]:
        """Return the chain an authority publishes at `<url>/certchain`, or none.

        Sigstore's authority returns a leaf-only token and publishes the chain there; DigiCert
        embeds the full chain in the token and has no such endpoint. Fetched once per URL.
        """
        cached = self._chains.get(url)
        if cached is not None:
            return cached
        chain: list[str] = []
        try:
            reply = await self._http.get(f"{url}/certchain", timeout=self._timeout)
            if reply.status_code == 200 and PEM_MARK in reply.text:
                chain = [
                    PEM_MARK + "\n" + part.strip() + "\n"
                    for part in reply.text.split(PEM_MARK)[1:]
                    if part.strip()
                ]
        except httpx.HTTPError as error:
            log.warning("anchor tsa=%s certchain not fetched: %s", url, error)
            return []
        self._chains[url] = chain
        return chain
