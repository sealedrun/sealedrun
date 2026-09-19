from __future__ import annotations

import copy
import io
import json
import shutil
import sys
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sealedrun.bundle import write_bundle
from sealedrun.delegation import create_delegation
from sealedrun.hashing import payload_digest
from sealedrun.keys import PROFILES, PrivateKeySet
from sealedrun.records import RunWriter, payload_ref
from sealedrun.signing import DOMAIN_DELEGATION, DOMAIN_RECORD, seal

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
    return {alg: f"{prefix}:{alg}".encode().ljust(32, b"\0") for alg in PROFILES[profile]}


def keys_for(prefix: str, profile: str = "sealedrun-hybrid-1") -> PrivateKeySet:
    return PrivateKeySet.from_seeds(seeds_for(prefix, profile))


class Clock:
    def __init__(self) -> None:
        self.current = START

    def __call__(self) -> datetime:
        self.current += timedelta(seconds=1)
        return self.current


class Ids:
    def __init__(self) -> None:
        self.n = 0

    def __call__(self) -> str:
        self.n += 1
        return f"{UUID_PREFIX}{self.n:012x}"


def build_delegation(principal: PrivateKeySet, agent: PrivateKeySet) -> dict[str, Any]:
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
                "receipt": {},
                "witness": "https://rekor.sigstore.dev",
            }
        },
    )
    cases["bad-anchor"] = (anchored.records, {"check": "anchor", "seq": 3})

    return cases


def jsonl(records: list[dict[str, Any]]) -> str:
    return "".join(json.dumps(r, separators=(",", ":"), sort_keys=True) + "\n" for r in records)


def dump(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def payload_map(alg: str) -> dict[str, bytes]:
    return {payload_digest(alg, body): body for body in PAYLOADS.values()}


def bundle_bytes(
    agent: PrivateKeySet,
    principal: PrivateKeySet,
    delegation: dict[str, Any],
    records: list[dict[str, Any]],
    *,
    with_payloads: bool = True,
) -> bytes:
    out = io.BytesIO()
    write_bundle(
        out,
        exporter=agent,
        software="sealedrun-vectors/0.1.0",
        delegations=[delegation],
        runs=[records],
        payloads=payload_map(delegation["hash_alg"]) if with_payloads else {},
        principal=principal,
        bundle_id=BUNDLE_ID,
        created_at="2026-09-16T13:00:00.000Z",
    )
    return out.getvalue()


def rewrite_zip(data: bytes, path: str, content: bytes) -> bytes:
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(data)) as src, zipfile.ZipFile(out, "w") as dst:
        for name in src.namelist():
            dst.writestr(name, content if name == path else src.read(name))
    return out.getvalue()


def generate(spec_dir: Path) -> None:
    vectors = spec_dir / "vectors"
    examples = spec_dir / "examples"
    for sub in ("keys.json", "delegations", "records", "chains", "bundle"):
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
    dump(vectors / "delegations" / "valid.json", delegation)
    dump(
        vectors / "delegations" / "expected.json",
        {
            "valid.json": {
                "hash": delegation["hash"],
                "agent_id": delegation["agent_id"],
                "principal_id": delegation["principal_id"],
            }
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
    (bundle_dir / "no-payloads.zip").write_bytes(
        bundle_bytes(agent, principal, delegation, run.records, with_payloads=False)
    )
    dump(
        bundle_dir / "expected.json",
        {
            "valid.zip": {"ok": True, "runs": 1, "records": len(run.records), "complete": True},
            "tampered-payload.zip": {"ok": False, "check": "bundle"},
            "tampered-record.zip": {"ok": False, "check": "bundle"},
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
    generate(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("spec"))


if __name__ == "__main__":
    main()
