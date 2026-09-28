"""Data labels a client attaches to a proxied call through the `X-SealedRun-Labels` header.

The header carries a comma-separated list of SPEC 5.6 labels (`nda, pii`, or namespaced
`acme:tier-1`). They land in the record's `data_labels` with the source `header` in
`sealedrun.labels`, so a label a caller asserted is never confused with one a classifier found.
The header never reaches an upstream: no dialect lists it among the headers that pass through.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import Request

LABELS_HEADER = "x-sealedrun-labels"
LABEL = re.compile(r"^[a-z0-9_-]+(:[a-z0-9_-]+)?$")
MAX_LABELS = 64


class LabelsError(ValueError):
    """The labels header cannot be used; the message says why."""


def header_labels(request: Request) -> list[str]:
    """Return the sorted, deduplicated labels of the request's header; empty when absent.

    Raises LabelsError for an empty item, a label outside the SPEC 5.6 pattern or more than
    64 labels.
    """
    raw = request.headers.get(LABELS_HEADER)
    if raw is None:
        return []
    labels: set[str] = set()
    for item in raw.split(","):
        label = item.strip()
        if not LABEL.match(label):
            raise LabelsError(f"{LABELS_HEADER}: label {label!r} must match {LABEL.pattern}")
        labels.add(label)
    if len(labels) > MAX_LABELS:
        raise LabelsError(f"{LABELS_HEADER}: at most {MAX_LABELS} labels")
    return sorted(labels)


def label_fields(labels: list[str], extensions: dict[str, Any]) -> dict[str, Any]:
    """Return the record fields for `labels`: `data_labels` and their provenance in `extensions`.

    The `sealedrun.labels` extension is added to `extensions` only when there are labels, so an
    unlabelled call keeps its record unchanged.
    """
    if not labels:
        return {"extensions": extensions}
    provenance = {label: {"source": "header"} for label in labels}
    return {
        "data_labels": labels,
        "extensions": {**extensions, "sealedrun.labels": provenance},
    }
