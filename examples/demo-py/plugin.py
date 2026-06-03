#!/usr/bin/env python3
"""GS 6.0 demo plugin (T2 / script tier).

Implements two commands (``greet``, ``paint``) and a dynamic ``colors``
completer, using the :mod:`gs_plugin` SDK. Run by the Rust core over stdio
with LSP-style framed JSON-RPC.
"""

from __future__ import annotations

import os
import sys

# Make the SDK importable both when run in-tree (from this repo) and when the
# SDK is installed on PYTHONPATH.
_SDK = os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python")
if os.path.isdir(_SDK):
    sys.path.insert(0, os.path.abspath(_SDK))

from gs_plugin import Plugin  # noqa: E402

plugin = Plugin(name="demo")


@plugin.command(
    name="greet",
    summary={"zh": "打招呼", "en": "Greet someone"},
    usage="gs demo greet <name>",
    examples=["gs demo greet world"],
    args=[
        {
            "name": "name",
            "type": "string",
            "required": True,
            "description": {"zh": "要问候的名字", "en": "Name to greet"},
        }
    ],
)
def greet(ctx):
    name = ctx.args.get("name") or "world"
    ctx.emit_progress(pct=50, stage="greeting", message="composing greeting")
    ctx.emit_output("stdout", "Hello, {}!\n".format(name))
    return 0


@plugin.command(
    name="paint",
    summary={"zh": "涂色", "en": "Paint with a color"},
    usage="gs demo paint --color <color>",
    examples=["gs demo paint --color red"],
    args=[
        {
            "name": "color",
            "type": "string",
            "flag": "--color",
            "description": {"zh": "颜色", "en": "Color to paint with"},
            "complete": {"kind": "dynamic", "source": "colors"},
        }
    ],
)
def paint(ctx):
    color = ctx.args.get("color") or "transparent"
    ctx.emit_output("stdout", "Painting with {}.\n".format(color))
    return 0


@plugin.completer(source="colors")
def colors(params):
    return [
        {"value": "red", "description": "warm"},
        {"value": "green", "description": "go"},
        {"value": "blue", "description": "cool"},
    ]


if __name__ == "__main__":
    raise SystemExit(plugin.run())
