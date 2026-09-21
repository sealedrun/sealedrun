"""Generator of the conformance test vectors and examples under `spec/` (SPEC 14).

Keys, ids and timestamps are fixed, so the output is byte-for-byte reproducible. Run as
`python -m sealedrun.vectors [spec_dir]`.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import shutil
import struct
import sys
import zipfile
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sealedrun.bundle import MANIFEST, write_bundle
from sealedrun.delegation import create_delegation
from sealedrun.hashing import b64url_decode, b64url_encode, payload_digest
from sealedrun.keys import (
    _ED_L,
    _ED_P,
    P256_ORDER,
    PROFILES,
    PrivateKeySet,
    _ed_add,
    _ed_decode,
    _ed_encode,
    _ed_mul,
)
from sealedrun.records import RunWriter, payload_ref
from sealedrun.signing import (
    DOMAIN_DELEGATION,
    DOMAIN_MANIFEST,
    DOMAIN_RECORD,
    countersign,
    seal,
)

START = datetime(2026, 9, 16, 12, 0, tzinfo=UTC)
UUID_PREFIX = "0192b3c4-5d6e-7f80-9a1b-"
DELEGATION_ID = UUID_PREFIX + "0000000000d0"
RUN_ID = UUID_PREFIX + "0000000000a0"
BUNDLE_ID = UUID_PREFIX + "0000000000b0"
SEED_DERIVATION = (
    "seed = utf8('<name>:<sig_alg>') right-padded with 0x00 to 32 bytes; "
    "ed25519 seed per RFC 8032; ml-dsa seed per FIPS 204 xi; "
    "es256 scalar = SHA-256('sealedrun/es256/seed' || seed) mod (n-1) + 1"
)

PAYLOADS = {
    "chat_request": (
        b'{"model":"gpt-4.1","messages":[{"role":"user",'
        b'"content":"Summarise the attached contract for Jane Doe."}]}'
    ),
    "chat_response": (
        b'{"choices":[{"message":{"role":"assistant",'
        b'"tool_calls":[{"function":{"name":"read_file"}}]}}]}'
    ),
    "tool_request": b'{"name":"read_file","arguments":{"path":"/contracts/acme-nda.pdf"}}',
    "tool_response": b'{"content":[{"type":"text","text":"NON-DISCLOSURE AGREEMENT ..."}]}',
    "local_request": (
        b'{"model":"qwen2.5:14b","messages":[{"role":"user","content":"Classify sensitivity."}]}'
    ),
    "local_response": b'{"choices":[{"message":{"role":"assistant","content":"nda, pii"}}]}',
}


def seeds_for(prefix: str, profile: str) -> dict[str, bytes]:
    """Derive the public test seeds of a named party, as described by `SEED_DERIVATION`."""
    return {alg: f"{prefix}:{alg}".encode().ljust(32, b"\0") for alg in PROFILES[profile]}


def keys_for(prefix: str, profile: str = "sealedrun-hybrid-1") -> PrivateKeySet:
    """Build the deterministic test keys of a named party. Never use them outside tests."""
    return PrivateKeySet.from_seeds(seeds_for(prefix, profile))


class Clock:
    """Deterministic clock: each call returns a time one second after the previous one."""

    def __init__(self) -> None:
        self.current = START

    def __call__(self) -> datetime:
        """Advance by one second and return the new time; the first call gives START + 1 s."""
        self.current += timedelta(seconds=1)
        return self.current


class Ids:
    """Deterministic id factory: UUID-shaped strings with a counter in the last group."""

    def __init__(self) -> None:
        self.n = 0

    def __call__(self) -> str:
        """Return the next id, counting from 1."""
        self.n += 1
        return f"{UUID_PREFIX}{self.n:012x}"


def build_delegation(principal: PrivateKeySet, agent: PrivateKeySet) -> dict[str, Any]:
    """Create the fixed 31-day delegation around START that all vectors share."""
    return create_delegation(
        principal,
        agent.public,
        not_before=START - timedelta(days=1),
        not_after=START + timedelta(days=30),
        agent_name="contract-summariser",
        scope={
            "allowed_locations": ["local", "cloud"],
            "max_labels_to_cloud": ["public", "internal"],
        },
        delegation_id=DELEGATION_ID,
    )


def build_run(agent: PrivateKeySet, delegation: dict[str, Any]) -> RunWriter:
    """Write the reference run: model and tool calls, a human approval, an anchor and a tombstone.

    The policy decisions cover allow, redirect, block and require_approval.
    """
    alg = delegation["hash_alg"]
    writer = RunWriter(agent, delegation, run_id=RUN_ID, clock=Clock(), id_factory=Ids())
    writer.start(
        extensions={
            "sealedrun.otel": {
                "trace_id": "0af7651916cd43dd8448eb211c80319c",
                "span_id": "b7ad6b7169203331",
            }
        }
    )
    llm = writer.append(
        "llm_call",
        target={
            "type": "model",
            "name": "gpt-4.1",
            "endpoint": "https://api.openai.com/v1/chat/completions",
            "location": "cloud",
            "provider": "openai",
        },
        payload=payload_ref(
            alg,
            PAYLOADS["chat_request"],
            PAYLOADS["chat_response"],
            request_media_type="application/json",
            response_media_type="application/json",
        ),
        data_labels=["pii"],
        policy={
            "rule_id": "default/allow",
            "decision": "allow",
            "reason": "no rule matched labels [pii] for cloud target",
        },
        extensions={
            "sealedrun.llm": {
                "model": "gpt-4.1",
                "provider": "openai",
                "stream": False,
                "input_tokens": 41,
                "output_tokens": 12,
                "finish_reason": "tool_calls",
                "tool_calls_requested": ["read_file"],
            },
            "sealedrun.labels": {"pii": {"source": "regex", "confidence": 1}},
        },
    )
    tool = writer.append(
        "tool_call",
        target={
            "type": "tool",
            "name": "filesystem/read_file",
            "location": "local",
            "provider": "mcp:filesystem",
        },
        payload=payload_ref(alg, PAYLOADS["tool_request"], PAYLOADS["tool_response"]),
        data_labels=["nda", "legal"],
        parent_record_id=llm["record_id"],
        extensions={
            "sealedrun.mcp": {
                "server": "filesystem",
                "transport": "stdio",
                "method": "tools/call",
                "tool": "read_file",
                "request_id": 7,
                "is_error": False,
            },
            "sealedrun.labels": {
                "nda": {"source": "classifier", "confidence": 0.97, "model": "sealedrun-sens-v1"},
                "legal": {"source": "classifier", "confidence": 0.91, "model": "sealedrun-sens-v1"},
            },
        },
    )
    writer.append(
        "llm_call",
        target={
            "type": "model",
            "name": "qwen2.5:14b",
            "endpoint": "http://ollama:11434/v1/chat/completions",
            "location": "local",
            "provider": "ollama",
        },
        payload=payload_ref(alg, PAYLOADS["local_request"], PAYLOADS["local_response"]),
        data_labels=["nda", "legal", "pii"],
        policy={
            "rule_id": "eu-strict/no-nda-to-cloud",
            "decision": "redirect",
            "reason": "labels [nda] may not leave the host",
            "original_target": {
                "type": "model",
                "name": "gpt-4.1",
                "endpoint": "https://api.openai.com/v1/chat/completions",
                "location": "cloud",
                "provider": "openai",
            },
            "redirected_to": {"type": "model", "name": "qwen2.5:14b", "location": "local"},
        },
        parent_record_id=tool["record_id"],
        extensions={
            "sealedrun.llm": {
                "model": "qwen2.5:14b",
                "provider": "ollama",
                "stream": True,
                "input_tokens": 512,
                "output_tokens": 6,
                "finish_reason": "stop",
            }
        },
    )
    writer.append(
        "llm_call",
        target={
            "type": "model",
            "name": "gpt-4.1",
            "endpoint": "https://api.openai.com/v1/chat/completions",
            "location": "cloud",
            "provider": "openai",
        },
        payload=payload_ref(alg, PAYLOADS["tool_response"], storage="none"),
        data_labels=["nda"],
        policy={
            "rule_id": "eu-strict/no-nda-to-cloud",
            "decision": "block",
            "reason": "labels [nda] may not leave the host and no local fallback configured",
        },
        outcome="blocked",
    )
    writer.append(
        "human_approval",
        actor={"type": "human", "id": "jane.doe@example.com"},
        target={"type": "human", "name": "approval:send-summary"},
        data_labels=["nda"],
        policy={
            "rule_id": "eu-strict/require-approval",
            "decision": "require_approval",
            "reason": "external delivery of nda-labelled content",
        },
    )
    writer.append(
        "anchor",
        target={"type": "witness", "name": "rekor", "endpoint": "https://rekor.sigstore.dev"},
        extensions={
            "sealedrun.anchor": {
                "type": "rekor",
                "anchored_hash": writer.head,
                "anchored_seq": writer.seq - 1,
                "receipt": {
                    "digest": writer.head,
                    "log_index": 123456789,
                    "integrated_time": 1789646406,
                    "uuid": "24296fb24b8ad77a" + "0" * 48,
                },
                "witness": "https://rekor.sigstore.dev",
            }
        },
    )
    writer.append(
        "tombstone",
        target={"type": "none", "name": f"record:{llm['record_id']}"},
        extensions={
            "sealedrun.tombstone": {
                "record_id": llm["record_id"],
                "fields": ["request"],
                "reason": "retention-90d",
                "legal_basis": "GDPR Art. 17",
            }
        },
    )
    writer.end()
    return writer


def negative_chains(
    run: RunWriter, agent: PrivateKeySet, principal: PrivateKeySet, delegation: dict[str, Any]
) -> dict[str, tuple[list[dict[str, Any]], dict[str, Any]]]:
    """Build invalid variants of the reference run with the failure a verifier must report.

    Maps a case name to its records and the expected `check` and `seq`. An outcome with a
    `delegation` key replaces the shared delegation for that case.
    """
    base = run.records
    cases: dict[str, tuple[list[dict[str, Any]], dict[str, Any]]] = {}

    edited = copy.deepcopy(base)
    edited[1]["data_labels"] = []
    cases["tampered-field"] = (edited, {"check": "hash", "seq": 1})

    resigned = copy.deepcopy(base)
    resigned[1]["data_labels"] = []
    resigned[1] = seal(resigned[1], DOMAIN_RECORD, keys_for("attacker"))
    cases["resigned-by-other-key"] = (resigned, {"check": "signature", "seq": 1})

    resigned_real = copy.deepcopy(base)
    resigned_real[1]["data_labels"] = []
    resigned_real[1] = seal(resigned_real[1], DOMAIN_RECORD, agent)
    cases["resigned-with-agent-key"] = (resigned_real, {"check": "chain", "seq": 2})

    gap = copy.deepcopy(base)
    del gap[3]
    cases["gap-in-seq"] = (gap, {"check": "seq", "seq": 3})

    swapped = copy.deepcopy(base)
    swapped[2], swapped[3] = swapped[3], swapped[2]
    cases["reordered"] = (swapped, {"check": "seq", "seq": 2})

    broken = copy.deepcopy(base)
    broken[4]["prev_hash"] = "f" * len(broken[4]["prev_hash"])
    cases["broken-prev-hash"] = (broken, {"check": "chain", "seq": 4})

    late = RunWriter(agent, delegation, run_id=RUN_ID, clock=Clock(), id_factory=Ids())
    late.records = list(base)
    late.append("note", target={"type": "none", "name": "after-end"})
    cases["record-after-run-end"] = (late.records, {"check": "run_end", "seq": len(base)})

    expired = seal(
        {**delegation, "not_after": "2026-09-16T12:00:03.000Z"}, DOMAIN_DELEGATION, principal
    )
    exp_run = build_run(agent, expired).records
    cases["expired-delegation"] = (
        exp_run,
        {"check": "delegation", "seq": 3, "delegation": expired},
    )

    anchored = RunWriter(agent, delegation, run_id=RUN_ID, clock=Clock(), id_factory=Ids())
    anchored.records = list(base[:3])
    anchored.append(
        "anchor",
        target={"type": "witness", "name": "rekor"},
        extensions={
            "sealedrun.anchor": {
                "type": "rekor",
                "anchored_hash": "e" * 64,
                "anchored_seq": 2,
                "receipt": {"digest": "e" * 64},
                "witness": "https://rekor.sigstore.dev",
            }
        },
    )
    cases["bad-anchor"] = (anchored.records, {"check": "anchor", "seq": 3})

    malformed = RunWriter(agent, delegation, run_id=RUN_ID, clock=Clock(), id_factory=Ids())
    malformed.records = list(base[:3])
    malformed.append(
        "anchor",
        target={"type": "witness", "name": "rekor"},
        extensions={
            "sealedrun.anchor": {
                "type": "rekor",
                "receipt": {"digest": "e" * 64},
                "witness": "https://rekor.sigstore.dev",
            }
        },
    )
    mismatched = RunWriter(agent, delegation, run_id=RUN_ID, clock=Clock(), id_factory=Ids())
    mismatched.records = list(base[:3])
    mismatched.append(
        "anchor",
        target={"type": "witness", "name": "rekor"},
        extensions={
            "sealedrun.anchor": {
                "type": "rekor",
                "anchored_hash": base[2]["hash"],
                "anchored_seq": 2,
                "receipt": {"digest": "e" * 64},
                "witness": "https://rekor.sigstore.dev",
            }
        },
    )
    cases["receipt-digest-mismatch"] = (mismatched.records, {"check": "anchor", "seq": 3})

    cases["malformed-anchor-extension"] = (
        malformed.records,
        {"check": "schema", "seq": 3},
    )

    return cases


def jsonl(records: list[dict[str, Any]]) -> str:
    """Serialize records as JSON Lines with compact separators and sorted keys."""
    return "".join(json.dumps(r, separators=(",", ":"), sort_keys=True) + "\n" for r in records)


def dump(path: Path, value: Any) -> None:
    """Write `value` as indented JSON with sorted keys, creating parent directories."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def payload_map(alg: str) -> dict[str, bytes]:
    """Key the sample payload bodies by their digest, the form `write_bundle` expects."""
    return {payload_digest(alg, body): body for body in PAYLOADS.values()}


def bundle_bytes(
    agent: PrivateKeySet,
    principal: PrivateKeySet,
    delegation: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    with_payloads: bool = True,
    receipt_override: dict[str, Any] | None = None,
) -> bytes:
    """Export one run as a bundle with fixed id and creation time and return the zip bytes.

    `receipt_override` replaces every anchor receipt file, to build a bundle whose receipt
    differs from its anchor record.
    """
    anchors = {
        r["record_id"]: receipt_override or r["extensions"]["sealedrun.anchor"]["receipt"]
        for r in records
        if r["kind"] == "anchor"
    }
    out = io.BytesIO()
    write_bundle(
        out,
        exporter=agent,
        software="sealedrun-vectors/0.1.0",
        delegations=[delegation],
        runs=[records],
        payloads=payload_map(delegation["hash_alg"]) if with_payloads else {},
        principal=principal,
        anchors=anchors,
        bundle_id=BUNDLE_ID,
        created_at="2026-09-16T13:00:00.000Z",
    )
    return out.getvalue()


def poison_payload_name(data: bytes, exporter: PrivateKeySet, principal: PrivateKeySet) -> bytes:
    """Rename a payload entry to a digest it does not have, then re-seal the manifest."""
    with zipfile.ZipFile(io.BytesIO(data)) as src:
        entries = {name: src.read(name) for name in src.namelist()}
    manifest = json.loads(entries.pop(MANIFEST))
    victim = next(n for n in entries if n.startswith("payloads/"))
    alg = manifest["hash_alg"]
    poison = b"poisoned body, not the content this name claims"
    entries[victim.rsplit("/", 1)[0] + "/" + payload_digest(alg, entries[victim])] = poison

    for key in ("signatures", "principal_signatures", "hash"):
        manifest.pop(key, None)
    manifest["files"] = {n: payload_digest(alg, c) for n, c in entries.items()}
    manifest = countersign(seal(manifest, DOMAIN_MANIFEST, exporter), DOMAIN_MANIFEST, principal)

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        dst.writestr(MANIFEST, json.dumps(manifest, indent=2, sort_keys=True))
        for name, content in sorted(entries.items()):
            dst.writestr(name, content)
    return out.getvalue()


def overlapping_entries_zip(copies: int = 3, body_size: int = 4096) -> bytes:
    """Central-directory entries all point at one local entry and understate its size.

    The compressed size is what a stored entry actually copies; the uncompressed size of 1 is
    the understatement.
    """
    body = b"A" * body_size
    crc = zlib.crc32(body) & 0xFFFFFFFF
    name = b"payloads/sha-256/overlap"
    compressed_size = body_size
    understated_size = 1
    out = bytearray()
    out += (
        struct.pack(
            "<IHHHHHIIIHH", 0x04034B50, 20, 0, 0, 0, 0, crc, body_size, body_size, len(name), 0
        )
        + name
        + body
    )
    central = bytearray()
    for i in range(copies):
        entry = name + b"%03d" % i
        central += (
            struct.pack(
                "<IHHHHHHIIIHHHHHII",
                0x02014B50,
                20,
                20,
                0,
                0,
                0,
                0,
                crc,
                compressed_size,
                understated_size,
                len(entry),
                0,
                0,
                0,
                0,
                0,
                0,
            )
            + entry
        )
    cd_off = len(out)
    out += central
    out += struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, copies, copies, len(central), cd_off, 0)
    return bytes(out)


def high_s(doc: dict[str, Any]) -> dict[str, Any]:
    """Replace the es256 signature `s` with `n - s`.

    The result still satisfies the ECDSA equation but breaks the SPEC 4.2 low-S rule, so a
    verifier must reject it.
    """
    signature = b64url_decode(doc["signatures"]["es256"])
    s = P256_ORDER - int.from_bytes(signature[32:], "big")
    flipped = b64url_encode(signature[:32] + s.to_bytes(32, "big"))
    return {**doc, "signatures": {**doc["signatures"], "es256": flipped}}


ED_TORSION = bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05")


def ed25519_edge_cases() -> list[dict[str, Any]]:
    """Signatures a cofactored verifier accepts and a cofactorless one rejects, or the reverse."""
    base = _ed_decode((4 * pow(5, -1, _ED_P) % _ED_P).to_bytes(32, "little"))
    torsion = _ed_decode(ED_TORSION)
    assert base is not None and torsion is not None
    message = b"sealedrun ed25519 edge cases"
    expanded = hashlib.sha512(b"edge".ljust(32, b"\0")).digest()
    a = (int.from_bytes(expanded[:32], "little") & ((1 << 254) - 8)) | (1 << 254)
    key = _ed_mul(a, base)

    def h(*parts: bytes) -> int:
        return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")

    def case(
        name: str, ok: bool, shift_key: bool = False, r_kind: str = "honest"
    ) -> dict[str, Any]:
        public = _ed_encode(_ed_add(key, torsion) if shift_key else key)
        for counter in range(256):
            r = 0 if r_kind == "identity" else h(expanded[32:], message, bytes([counter])) % _ED_L
            point = _ed_mul(r, base)
            encoded_r = _ed_encode(_ed_add(point, torsion) if r_kind == "mixed" else point)
            k = h(encoded_r, public, message) % _ED_L
            if k % 8 or r_kind == "identity":
                break
        signature = encoded_r + ((r + k * a) % _ED_L).to_bytes(32, "little")
        return {
            "name": name,
            "ok": ok,
            "public_key": public.hex(),
            "message": message.hex(),
            "signature": signature.hex(),
        }

    small = {**case("small-order-key", False), "public_key": ED_TORSION.hex()}
    return [
        case("honest", True),
        case("mixed-order-key", False, shift_key=True),
        case("mixed-order-r", False, r_kind="mixed"),
        case("identity-r", False, r_kind="identity"),
        small,
    ]


def too_many_delegations(data: bytes, count: int = 1025) -> bytes:
    """List more delegation ids in the manifest than the bundle schema allows."""
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        manifest = json.loads(zf.read("manifest.json"))
    manifest["delegations"] = [f"00000000-0000-4000-8000-{i:012x}" for i in range(count)]
    return rewrite_zip(data, "manifest.json", json.dumps(manifest, sort_keys=True).encode())


def rewrite_zip(data: bytes, path: str, content: bytes) -> bytes:
    """Copy a zip archive, replacing the content of the entry at `path`."""
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as src, zipfile.ZipFile(out, "w") as dst:
        for name in src.namelist():
            dst.writestr(name, content if name == path else src.read(name))
    return out.getvalue()


def generate(spec_dir: Path) -> None:
    """Regenerate `vectors/` and `examples/` under `spec_dir`, deleting the previous output.

    `unknown-principal.zip` is consistent and correctly signed end to end, but by a Principal the
    verifier never heard of, so it fails only the trust check.
    """
    vectors = spec_dir / "vectors"
    examples = spec_dir / "examples"
    for sub in ("keys.json", "signatures", "delegations", "records", "chains", "bundle"):
        target = vectors / sub
        if target.is_dir():
            shutil.rmtree(target)
        elif target.exists():
            target.unlink()
    if examples.exists():
        shutil.rmtree(examples)

    principal = keys_for("principal")
    agent = keys_for("agent")
    delegation = build_delegation(principal, agent)
    run = build_run(agent, delegation)

    dump(
        vectors / "keys.json",
        {
            "warning": "Test keys derived from public seeds. Never use in production.",
            "principal": {
                "profile": "sealedrun-hybrid-1",
                "seeds": {
                    a: s.hex() for a, s in seeds_for("principal", "sealedrun-hybrid-1").items()
                },
                "public": principal.public.to_json(),
                "kid": principal.public.kid,
            },
            "agent": {
                "profile": "sealedrun-hybrid-1",
                "seeds": {a: s.hex() for a, s in seeds_for("agent", "sealedrun-hybrid-1").items()},
                "public": agent.public.to_json(),
                "kid": agent.public.kid,
            },
            "attacker": {
                "profile": "sealedrun-hybrid-1",
                "seeds": {
                    a: s.hex() for a, s in seeds_for("attacker", "sealedrun-hybrid-1").items()
                },
                "public": keys_for("attacker").public.to_json(),
                "kid": keys_for("attacker").public.kid,
            },
            "seed_derivation": SEED_DERIVATION,
            "other_profiles": {
                profile: {
                    name: keys_for(name, profile).public.to_json()
                    for name in ("principal", "agent")
                }
                for profile in PROFILES
                if profile != "sealedrun-hybrid-1"
            },
        },
    )
    dump(vectors / "signatures" / "ed25519.json", ed25519_edge_cases())
    dump(vectors / "delegations" / "valid.json", delegation)
    aat = build_delegation(keys_for("principal", "aat-compat-1"), keys_for("agent", "aat-compat-1"))
    dump(vectors / "delegations" / "aat-compat-1.json", aat)
    dump(vectors / "delegations" / "aat-compat-1-high-s.json", high_s(aat))
    dump(
        vectors / "delegations" / "expected.json",
        {
            name: {
                "ok": ok,
                "hash": doc["hash"],
                "agent_id": doc["agent_id"],
                "principal_id": doc["principal_id"],
            }
            for name, doc, ok in (
                ("valid.json", delegation, True),
                ("aat-compat-1.json", aat, True),
                ("aat-compat-1-high-s.json", aat, False),
            )
        },
    )

    (vectors / "records").mkdir(parents=True)
    (vectors / "records" / "valid-run.jsonl").write_text(jsonl(run.records))
    dump(
        vectors / "records" / "expected.json",
        {
            "valid-run.jsonl": [
                {"seq": r["seq"], "kind": r["kind"], "prev_hash": r["prev_hash"], "hash": r["hash"]}
                for r in run.records
            ]
        },
    )

    chains = vectors / "chains"
    chains.mkdir(parents=True)
    expected: dict[str, Any] = {}
    for name, (records, outcome) in negative_chains(run, agent, principal, delegation).items():
        (chains / f"{name}.jsonl").write_text(jsonl(records))
        entry = dict(outcome)
        if "delegation" in entry:
            dump(chains / f"{name}.delegation.json", entry.pop("delegation"))
            entry["delegation"] = f"{name}.delegation.json"
        expected[f"{name}.jsonl"] = entry
    dump(chains / "expected.json", expected)

    bundle_dir = vectors / "bundle"
    bundle_dir.mkdir(parents=True)
    valid = bundle_bytes(agent, principal, delegation, run.records)
    (bundle_dir / "valid.zip").write_bytes(valid)
    with zipfile.ZipFile(io.BytesIO(valid)) as zf:
        payload_path = next(n for n in zf.namelist() if n.startswith("payloads/"))
        payload = bytearray(zf.read(payload_path))
        run_path = next(n for n in zf.namelist() if n.startswith("runs/"))
        run_text = zf.read(run_path).decode()
    payload[0] ^= 0x01
    (bundle_dir / "tampered-payload.zip").write_bytes(
        rewrite_zip(valid, payload_path, bytes(payload))
    )
    (bundle_dir / "tampered-record.zip").write_bytes(
        rewrite_zip(
            valid, run_path, run_text.replace('"outcome":"blocked"', '"outcome":"success"').encode()
        )
    )
    (bundle_dir / "poisoned-payload-name.zip").write_bytes(
        poison_payload_name(valid, agent, principal)
    )
    (bundle_dir / "overlapping-entries.zip").write_bytes(overlapping_entries_zip())
    (bundle_dir / "too-many-delegations.zip").write_bytes(too_many_delegations(valid))
    (bundle_dir / "swapped-anchor-receipt.zip").write_bytes(
        bundle_bytes(
            agent, principal, delegation, run.records, receipt_override={"digest": "e" * 64}
        )
    )
    forger, forger_agent = keys_for("attacker"), keys_for("attacker-agent")
    forged_delegation = build_delegation(forger, forger_agent)
    (bundle_dir / "unknown-principal.zip").write_bytes(
        bundle_bytes(
            forger_agent,
            forger,
            forged_delegation,
            build_run(forger_agent, forged_delegation).records,
        )
    )
    trusted = [principal.public.kid]
    (bundle_dir / "no-payloads.zip").write_bytes(
        bundle_bytes(agent, principal, delegation, run.records, with_payloads=False)
    )
    dump(
        bundle_dir / "expected.json",
        {
            "valid.zip": {
                "ok": True,
                "runs": 1,
                "records": len(run.records),
                "complete": True,
                "trusted_principals": trusted,
            },
            "unknown-principal.zip": {
                "ok": False,
                "check": "trust",
                "trusted_principals": trusted,
            },
            "tampered-payload.zip": {"ok": False, "check": "bundle"},
            "tampered-record.zip": {"ok": False, "check": "bundle"},
            "poisoned-payload-name.zip": {"ok": False, "check": "bundle"},
            "overlapping-entries.zip": {"ok": False, "check": "bundle"},
            "too-many-delegations.zip": {"ok": False, "check": "schema"},
            "swapped-anchor-receipt.zip": {"ok": False, "check": "anchor"},
            "no-payloads.zip": {"ok": False, "check": "payload", "seq": 1},
        },
    )

    examples.mkdir(parents=True)
    for record in run.records:
        dump(examples / f"record-{record['seq']:02d}-{record['kind']}.json", record)
    dump(examples / "delegation.json", delegation)
    with zipfile.ZipFile(io.BytesIO(valid)) as zf:
        dump(examples / "bundle-manifest.json", json.loads(zf.read("manifest.json")))
    (examples / "bundle.zip").write_bytes(valid)


def main() -> None:
    """Generate into the directory given as the first argument, `spec` by default."""
    generate(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("spec"))


if __name__ == "__main__":
    main()
