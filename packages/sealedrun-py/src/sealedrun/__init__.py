"""Tamper-evident, hybrid-signed hash-chain records of AI agent steps.

Reference implementation of SPEC.md: writing runs, delegations, bundles and their verification.
"""

from sealedrun.bundle import Bundle, BundleReport, read_bundle, verify_bundle, write_bundle
from sealedrun.canonical import canonicalize
from sealedrun.client import Recorder, RecorderError, receipt_for
from sealedrun.delegation import covers, create_delegation, verify_delegation
from sealedrun.errors import SealedRunError, VerificationError
from sealedrun.hashing import b64url_decode, b64url_encode, object_hash, payload_digest, zero_hash
from sealedrun.keys import PROFILES, KeySet, PrivateKeySet
from sealedrun.records import RunWriter, payload_ref
from sealedrun.scope import Finding, Scope, scope_within
from sealedrun.verify import RunReport, check_parent_links, parent_of, verify_run

__version__ = "0.7.0"

__all__ = [
    "PROFILES",
    "Bundle",
    "BundleReport",
    "Finding",
    "KeySet",
    "PrivateKeySet",
    "Recorder",
    "RecorderError",
    "RunReport",
    "RunWriter",
    "Scope",
    "SealedRunError",
    "VerificationError",
    "b64url_decode",
    "b64url_encode",
    "canonicalize",
    "check_parent_links",
    "covers",
    "create_delegation",
    "object_hash",
    "parent_of",
    "payload_digest",
    "payload_ref",
    "read_bundle",
    "receipt_for",
    "scope_within",
    "verify_bundle",
    "verify_delegation",
    "verify_run",
    "write_bundle",
    "zero_hash",
]
