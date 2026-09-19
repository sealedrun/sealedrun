from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

SCHEMA_BASE = "https://sealedrun.com/schema/0.1/"
SCHEMA_DIR = Path(__file__).resolve().parents[3].parent / "spec" / "schema"
SCHEMA_FILES = (
    "common.json",
    "record.json",
    "delegation.json",
    "bundle.json",
    "extensions/sealedrun.json",
)


@cache
def registry() -> Registry:
    resources = []
    for name in SCHEMA_FILES:
        document = json.loads((SCHEMA_DIR / name).read_text())
        resources.append((SCHEMA_BASE + name, Resource.from_contents(document, DRAFT202012)))
    return Registry().with_resources(resources)


@cache
def validator(name: str) -> Draft202012Validator:
    resource = registry().get_or_retrieve(SCHEMA_BASE + name).value
    return Draft202012Validator(resource.contents, registry=registry())


def validate(name: str, instance: Any) -> list[str]:
    errors = validator(name).iter_errors(instance)
    return sorted(
        f"{'/'.join(str(p) for p in e.absolute_path) or '$'}: {e.message}" for e in errors
    )


def validate_extensions(extensions: dict[str, Any]) -> list[str]:
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
        errors.extend(
            f"extensions/{key}/{'/'.join(str(p) for p in e.absolute_path)}: {e.message}"
            for e in sub.iter_errors(value)
        )
    return sorted(errors)
