"""JSON Schema validation of records, delegations, bundles and extensions.

Schemas come from the copy packaged with the wheel, or from `spec/schema` in a source checkout.
`MAX_MESSAGE` caps each reported message: jsonschema messages embed the failing instance, which
on untrusted input is attacker-sized.
"""

from __future__ import annotations

import json
from functools import cache
from itertools import islice
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

SCHEMA_BASE = "https://sealedrun.com/schema/0.1/"
MAX_MESSAGE = 200
_PACKAGED = Path(__file__).resolve().parent / "_schema"
SCHEMA_DIR = (
    _PACKAGED
    if _PACKAGED.is_dir()
    else Path(__file__).resolve().parents[3].parent / "spec" / "schema"
)
SCHEMA_FILES = (
    "common.json",
    "record.json",
    "delegation.json",
    "bundle.json",
    "extensions/sealedrun.json",
)


@cache
def registry() -> Registry:
    """Load every schema file once and register it under its `SCHEMA_BASE` URL."""
    resources = []
    for name in SCHEMA_FILES:
        document = json.loads((SCHEMA_DIR / name).read_text())
        resources.append((SCHEMA_BASE + name, Resource.from_contents(document, DRAFT202012)))
    return Registry().with_resources(resources)


@cache
def validator(name: str) -> Draft202012Validator:
    """Return the cached Draft 2020-12 validator for a schema file such as `record.json`."""
    resource = registry().get_or_retrieve(SCHEMA_BASE + name).value
    return Draft202012Validator(resource.contents, registry=registry())


def validate(name: str, instance: Any, *, first_only: bool = False) -> list[str]:
    """Return sorted `path: message` strings for each schema violation; empty when valid.

    `first_only` is for untrusted input: a document that has already failed must not keep paying
    for further checks (uniqueItems is quadratic on items that cannot be sorted).
    """
    errors = validator(name).iter_errors(instance)
    return sorted(
        f"{'/'.join(str(p) for p in e.absolute_path) or '$'}: {e.message[:MAX_MESSAGE]}"
        for e in (islice(errors, 1) if first_only else errors)
    )


def validate_extensions(extensions: dict[str, Any], *, first_only: bool = False) -> list[str]:
    """Validate each known `sealedrun.*` extension against its definition; skip unknown keys.

    Unknown extensions are allowed by SPEC 9, so they are not errors. `first_only` has the same
    purpose as in `validate`.
    """
    ext_validator = validator("extensions/sealedrun.json")
    schema = ext_validator.schema
    assert isinstance(schema, dict)
    defs = schema["$defs"]
    errors: list[str] = []
    for key, value in extensions.items():
        if key not in defs:
            continue
        sub = ext_validator.evolve(
            schema={**defs[key], "$id": SCHEMA_BASE + "extensions/sealedrun.json"}
        )
        found = sub.iter_errors(value)
        errors.extend(
            f"extensions/{key}/{'/'.join(str(p) for p in e.absolute_path)}: "
            f"{e.message[:MAX_MESSAGE]}"
            for e in (islice(found, 1) if first_only else found)
        )
        if first_only and errors:
            break
    return sorted(errors)
