"""Hatchling build hook that ships the JSON Schemas from ``spec/schema`` inside the package."""

from pathlib import Path
from typing import Any

from hatchling.builders.hooks.plugin.interface import BuildHookInterface

_DESTINATIONS = {"wheel": "sealedrun/_schema", "sdist": "src/sealedrun/_schema"}


class SchemaBuildHook(BuildHookInterface[Any]):
    """Copy ``spec/schema`` into the artifact when building from the repository.

    A wheel built from an sdist has no ``spec`` directory next to it; there the schemas are
    already in ``src/sealedrun/_schema`` and are picked up as ordinary package data.
    """

    PLUGIN_NAME = "custom"

    def initialize(self, version: str, build_data: dict[str, Any]) -> None:
        """Register the schema directory as a forced include if the repository copy exists."""
        source = Path(self.root, "..", "..", "spec", "schema").resolve()
        if source.is_dir():
            build_data["force_include"][str(source)] = _DESTINATIONS[self.target_name]
