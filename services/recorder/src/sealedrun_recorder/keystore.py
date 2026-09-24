"""Recorder identity: principal and agent keys on disk, and the delegation between them."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sealedrun import PrivateKeySet, covers, create_delegation, verify_delegation
from sealedrun.hashing import b64url_decode, b64url_encode

KEY_DIR = "keys"
PRINCIPAL_FILE = "principal.json"
AGENT_FILE = "agent.json"
DELEGATION_FILE = "delegation.json"


@dataclass(frozen=True)
class Identity:
    """The keys the recorder signs with and the delegation that binds them."""

    principal: PrivateKeySet
    agent: PrivateKeySet
    delegation: dict[str, Any]

    @property
    def principal_id(self) -> str:
        """Key id of the principal."""
        return self.principal.public.kid

    @property
    def agent_id(self) -> str:
        """Key id of the agent."""
        return self.agent.public.kid


def load_identity(data_dir: Path, *, agent_name: str = "sealedrun-recorder") -> Identity:
    """Load the keys under `data_dir/keys`, generating whatever is missing.

    Seeds are written with mode 0600 into a 0700 directory and never leave the file system.
    The delegation is reissued when its file is missing, fails verification, was issued for
    other keys, or no longer covers the current time.
    """
    key_dir = data_dir / KEY_DIR
    key_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(key_dir, 0o700)
    principal = _load_or_create_keys(key_dir / PRINCIPAL_FILE)
    agent = _load_or_create_keys(key_dir / AGENT_FILE)
    delegation_path = key_dir / DELEGATION_FILE
    delegation = _read_json(delegation_path)
    if not _delegation_usable(delegation, principal, agent):
        delegation = create_delegation(principal, agent.public, agent_name=agent_name)
        _write_private(delegation_path, json.dumps(delegation, indent=2).encode())
    assert delegation is not None
    return Identity(principal, agent, delegation)


def _load_or_create_keys(path: Path) -> PrivateKeySet:
    stored = _read_json(path)
    if stored is not None:
        return PrivateKeySet.from_seeds({alg: b64url_decode(seed) for alg, seed in stored.items()})
    keys = PrivateKeySet.generate()
    seeds = {alg: b64url_encode(seed) for alg, seed in keys.seeds().items()}
    _write_private(path, json.dumps(seeds, indent=2).encode())
    return keys


def _delegation_usable(
    delegation: dict[str, Any] | None, principal: PrivateKeySet, agent: PrivateKeySet
) -> bool:
    if delegation is None:
        return False
    try:
        if verify_delegation(delegation) is not None:
            return False
    except (KeyError, ValueError, TypeError):
        return False
    return (
        delegation["principal_id"] == principal.public.kid
        and delegation["agent_id"] == agent.public.kid
        and covers(delegation, datetime.now(UTC))
    )


def _read_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        value = json.loads(path.read_bytes())
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def _write_private(path: Path, content: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
