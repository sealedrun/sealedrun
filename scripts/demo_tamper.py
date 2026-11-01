"""Change one field of one record inside an evidence bundle, the way an insider would.

    python scripts/demo_tamper.py <bundle.zip> <out.zip> --seq 5 --field target.name --value x

The archive is rewritten with the edited record line and nothing else touched. The bundle then
fails verification: the manifest digest of the runs file no longer matches, and if that were
patched too, the record hash and the anchored chain head would not. The script exists for the
demo recording and for anyone who wants to see the verifier refuse an edit with their own eyes.
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path


def set_path(record: dict, path: str, value: str) -> str:
    """Set `path` (dot-separated) in `record` to `value`; return the previous value as text."""
    keys = path.split(".")
    node = record
    for key in keys[:-1]:
        node = node.setdefault(key, {})
    previous = node.get(keys[-1])
    node[keys[-1]] = value
    return json.dumps(previous)


def main(argv: list[str]) -> int:
    """Rewrite the bundle with one field changed; print what changed."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("bundle", type=Path)
    parser.add_argument("out", type=Path)
    parser.add_argument("--seq", type=int, required=True)
    parser.add_argument("--field", default="target.name")
    parser.add_argument("--value", required=True)
    args = parser.parse_args(argv)

    with (
        zipfile.ZipFile(args.bundle) as src,
        zipfile.ZipFile(args.out, "w", zipfile.ZIP_DEFLATED) as dst,
    ):
        for info in src.infolist():
            data = src.read(info)
            if info.filename.startswith("runs/") and info.filename.endswith(".jsonl"):
                lines = data.decode().splitlines()
                for index, line in enumerate(lines):
                    record = json.loads(line)
                    if record["seq"] == args.seq:
                        previous = set_path(record, args.field, args.value)
                        lines[index] = json.dumps(record, separators=(",", ":"), sort_keys=True)
                        changed = json.dumps(args.value)
                        print(f"seq {args.seq} {args.field}: {previous} -> {changed}")
                data = ("\n".join(lines) + "\n").encode()
            dst.writestr(info, data)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
