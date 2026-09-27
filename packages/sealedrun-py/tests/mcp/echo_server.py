"""A stdio server for the wrapper tests: answers requests by method name, one line each.

`tools/call` echoes the arguments; argument `sleep` delays the reply, `chatter` writes a
non-JSON line to stdout first, `crash` exits without answering. `initialize` answers like a
legacy server; `server/discover` like a modern one. Environment `IGNORE_EOF=1` keeps the
process alive after stdin closes and `EXIT_CODE` sets the code it exits with on EOF.
"""

import json
import os
import signal
import sys
import time

sys.stderr.write("echo server started\n")
sys.stderr.flush()
if os.environ.get("IGNORE_SIGTERM"):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)


def reply(message: dict) -> None:
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


for raw in sys.stdin:
    try:
        request = json.loads(raw)
    except ValueError:
        continue
    if "method" not in request or "id" not in request:
        continue
    method, params, rid = request["method"], request.get("params") or {}, request["id"]
    if method == "initialize":
        reply({"jsonrpc": "2.0", "id": rid, "result": {"protocolVersion": "2025-11-25"}})
    elif method == "server/discover":
        reply({"jsonrpc": "2.0", "id": rid, "result": {"supportedVersions": ["2026-07-28"]}})
    elif method == "tools/call":
        arguments = params.get("arguments") or {}
        if "sleep" in arguments:
            time.sleep(float(arguments["sleep"]))
        if arguments.get("chatter"):
            sys.stdout.write("not json at all\n")
            sys.stdout.flush()
        if arguments.get("crash"):
            os._exit(9)
        if arguments.get("fail"):
            reply({"jsonrpc": "2.0", "id": rid, "error": {"code": -32602, "message": "bad"}})
            continue
        result = {"content": [{"type": "text", "text": json.dumps(arguments)}]}
        if arguments.get("is_error"):
            result["isError"] = True
        if arguments.get("input_required"):
            result = {"resultType": "input_required", "inputRequests": []}
        reply({"jsonrpc": "2.0", "id": rid, "result": result})
    elif method == "tools/list":
        reply({"jsonrpc": "2.0", "id": rid, "result": {"tools": [{"name": "add"}]}})
    else:
        reply({"jsonrpc": "2.0", "id": rid, "result": {"echo": method}})

if os.environ.get("IGNORE_EOF"):
    while True:
        time.sleep(1)
sys.exit(int(os.environ.get("EXIT_CODE", "0")))
