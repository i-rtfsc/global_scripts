#!/usr/bin/env python3
"""Self-test for the gs_plugin SDK + the demo-py example plugin.

Spawns ``examples/demo-py/plugin.py`` as a subprocess and drives it over
stdio with framed JSON-RPC requests, then asserts on the responses:

  1. ``describe`` returns commands ``greet`` and ``paint``.
  2. ``complete`` with ``source="colors"`` returns the 3 colors.
  3. ``invoke`` of ``greet`` returns ``exit_code == 0``.

Run::

    python3 sdk/python/selftest.py
"""

from __future__ import annotations

import io
import os
import subprocess
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.abspath(os.path.join(_HERE, "..", ".."))

sys.path.insert(0, _HERE)  # so we can import gs_plugin.framing
from gs_plugin.framing import read_message, write_message  # noqa: E402

DEMO_PLUGIN = os.path.join(_REPO_ROOT, "examples", "demo-py", "plugin.py")


def _frame(obj) -> bytes:
    buf = io.BytesIO()
    write_message(buf, obj)
    return buf.getvalue()


def main() -> int:
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "describe",
            "params": {"protocol": 1, "locale": "en", "plugin": "demo"},
        },
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "complete",
            "params": {
                "command": "paint",
                "arg": "color",
                "source": "colors",
                "current": "",
                "args": {},
                "cwd": _REPO_ROOT,
                "locale": "en",
            },
        },
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "invoke",
            "params": {
                "command": "greet",
                "args": {"name": "world"},
                "cwd": _REPO_ROOT,
                "env": {},
                "context": {"locale": "en", "tty": False},
                "capabilities": {"exec": ["echo"]},
            },
        },
    ]

    payload = b"".join(_frame(r) for r in requests)

    proc = subprocess.Popen(
        [sys.executable, DEMO_PLUGIN],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    out, err = proc.communicate(payload, timeout=30)

    if err:
        sys.stderr.write("[plugin stderr]\n" + err.decode("utf-8", "replace") + "\n")

    stream = io.BytesIO(out)

    # Read all framed responses; collect final responses (those with "id").
    # Notifications (events, no "id") are interleaved before the invoke result.
    responses = {}
    events = []
    while True:
        msg = read_message(stream)
        if msg is None:
            break
        if "id" in msg and msg["id"] is not None:
            responses[msg["id"]] = msg
        elif msg.get("method") == "event":
            events.append(msg["params"])

    assert proc.returncode == 0, "plugin exited non-zero: {}".format(proc.returncode)

    # --- 1. describe ---
    assert 1 in responses, "no describe response"
    describe = responses[1]
    assert "result" in describe, "describe error: {}".format(describe.get("error"))
    cmd_names = {c["name"] for c in describe["result"]["commands"]}
    assert cmd_names == {"greet", "paint"}, "unexpected commands: {}".format(cmd_names)
    assert describe["result"]["name"] == "demo"
    # paint must declare a dynamic colors completion.
    paint = next(c for c in describe["result"]["commands"] if c["name"] == "paint")
    color_arg = next(a for a in paint["args"] if a["name"] == "color")
    assert color_arg["complete"] == {"kind": "dynamic", "source": "colors"}, color_arg
    print("OK  describe -> commands {}".format(sorted(cmd_names)))

    # --- 2. complete ---
    assert 2 in responses, "no complete response"
    complete = responses[2]
    assert "result" in complete, "complete error: {}".format(complete.get("error"))
    values = [v["value"] for v in complete["result"]["values"]]
    assert values == ["red", "green", "blue"], "unexpected colors: {}".format(values)
    print("OK  complete(colors) -> {}".format(values))

    # --- 3. invoke ---
    assert 3 in responses, "no invoke response"
    invoke = responses[3]
    assert "result" in invoke, "invoke error: {}".format(invoke.get("error"))
    assert invoke["result"]["exit_code"] == 0, invoke["result"]
    # Streaming events should have been emitted before the result.
    types = [e.get("type") for e in events]
    assert "progress" in types and "output" in types, "events: {}".format(types)
    print("OK  invoke(greet) -> exit_code 0, events {}".format(types))

    print("\nALL SELFTESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
