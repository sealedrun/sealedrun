"""Tamper-evident, hybrid-signed hash-chain records of AI agent steps.

Reference implementation of SPEC.md: writing runs, delegations, bundles and their verification.
"""

from sealedrun.approval import Approvals
from sealedrun.bundle import Bundle, BundleReport, read_bundle, verify_bundle, write_bundle
from sealedrun.canonical import canonicalize
from sealedrun.client import Recorder, RecorderError, receipt_for
from sealedrun.delegation import covers, create_delegation, verify_delegation
from sealedrun.errors import SealedRunError, VerificationError
from sealedrun.hashing import b64url_decode, b64url_encode, object_hash, payload_digest, zero_hash
from sealedrun.keys import PROFILES, KeySet, PrivateKeySet
from sealedrun.records import RunWriter, payload_ref
from sealedrun.report import evidence_report, failure_report, file_sha256, render_report
from sealedrun.scope import Finding, Scope, scope_within
from sealedrun.verify import (
    ApprovalAnchor,
    RunReport,
    check_parent_links,
    parent_of,
    verify_run,
)

__version__ = "0.10.0"

__all__ = [
    "PROFILES",
    "ApprovalAnchor",
    "Approvals",
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
    "evidence_report",
    "failure_report",
    "file_sha256",
    "object_hash",
    "parent_of",
    "payload_digest",
    "payload_ref",
    "read_bundle",
    "receipt_for",
    "render_report",
    "scope_within",
    "verify_bundle",
    "verify_delegation",
    "verify_run",
    "write_bundle",
    "zero_hash",
]
