# `gs_plugin` — Global Scripts 6.0 Python plugin SDK

A stdlib-only (Python 3.9+) helper for writing **T2 "script" tier** plugins
for Global Scripts 6.0. It implements the plugin wire protocol from
`tmp/phase0-plugin-protocol.md`: JSON-RPC 2.0 over stdio with LSP-style
`Content-Length` framing. The Rust core spawns your plugin process and talks
to it over stdin/stdout.

## Install / import

The package has no dependencies. Put `sdk/python` on `PYTHONPATH`, or copy
`gs_plugin/` next to your plugin. Example plugins in this repo add the SDK
path automatically:

```python
import os, sys
sys.path.insert(0, os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python")))
from gs_plugin import Plugin
```

## Writing a plugin

```python
from gs_plugin import Plugin

plugin = Plugin(name="demo")

@plugin.command(
    name="greet",
    summary={"zh": "打招呼", "en": "Greet someone"},
    usage="gs demo greet <name>",
    examples=["gs demo greet world"],
    args=[
        {"name": "name", "type": "string", "required": True,
         "description": {"zh": "名字", "en": "Name"}},
    ],
)
def greet(ctx):
    name = ctx.args.get("name", "world")
    ctx.emit_progress(pct=50, stage="greeting", message="composing")
    ctx.emit_output("stdout", f"Hello, {name}!\n")
    return 0  # exit_code

@plugin.completer(source="colors")
def colors(params):
    # Return value-objects or plain strings; both are normalized.
    return [{"value": "red", "description": "warm"}, "green", "blue"]

if __name__ == "__main__":
    raise SystemExit(plugin.run())
```

### `@plugin.command(...)`

Registers a command and its describe metadata. Arguments:

- `name` (str, required) — command name; `.`-separated for sub-commands.
- `summary` (`{"zh":..,"en":..}`, required) — one-line bilingual summary.
- `usage` (str, optional), `examples` (`list[str]`, optional).
- `args` (`list[dict]`, optional) — each dict matches the describe arg schema:
  `name`, `type` (`string|int|float|bool|enum|path|flag`), and optional
  `required`, `variadic`, `flag`, `default`, `description`, and `complete`
  (`{"kind": "none|enum|file|dir|dynamic", "values"?, "source"?, "pattern"?}`).
- `hidden` (bool, optional).

The handler receives an `InvokeContext` (`ctx`) and returns an `int` exit
code (default `0` if it returns `None`), or a `dict` merged into the result.

### `@plugin.completer(source=...)`

Registers a dynamic-completion handler `def handler(params) -> list` for a
`complete.source` id. `params` carries `command`, `arg`, `source`, `current`
(typed prefix), `args` (other parsed args), `cwd`, `locale`. Return either
value-objects `[{"value":.., "description"?:..}]` or plain strings; both are
normalized. Return `{"values": [...], "ttl": <int>}` to set a cache TTL.

### `InvokeContext` (the `ctx` passed to command handlers)

- `ctx.args`, `ctx.cwd`, `ctx.env`, `ctx.context`, `ctx.capabilities` — the
  parsed `invoke` params.
- `ctx.emit_progress(message="", pct=None, stage=None)` — emit a `progress`
  event notification.
- `ctx.emit_log(message, level="info")` — emit a `log` event.
- `ctx.emit_output(stream, chunk)` — emit an `output` event
  (`stream` is `"stdout"` or `"stderr"`); the recommended way to stream.
- `ctx.emit(params)` — emit a raw `event` notification.

All emitted events are also collected and returned in `result.events`.

### `plugin.run(stdin=..., stdout=...)`

Runs the request loop, reading framed requests from `stdin` (binary;
defaults to `sys.stdin.buffer`) and writing one framed response per request
to `stdout` (defaults to `sys.stdout.buffer`), until stdin EOF, then returns
`0`. The core spawns the process per invocation and may send 1–2 requests
(e.g. `describe` then `complete`, or `describe` then `invoke`).

## Wire protocol summary

Transport: **JSON-RPC 2.0 over stdio**, framed LSP-style — each message is
`Content-Length: <N>\r\n\r\n` followed by exactly `<N>` bytes of UTF-8 JSON.
Extra headers are accepted and ignored on read. **stderr** is a free log
channel the core does not parse.

Methods (all field names are snake_case, per the protocol doc):

| method | params | result |
|---|---|---|
| `describe` | `{protocol, locale, plugin}` | `{protocol, name, commands:[{name, summary, usage?, examples?, args:[...]}]}` |
| `complete` | `{command, arg, source, current, args, cwd, locale}` | `{values:[{value, description?}], ttl?}` |
| `invoke` | `{command, args, cwd, env, context, capabilities}` | `{exit_code, stdout?, stderr?, events?}` |

During `invoke`, the handler MAY stream JSON-RPC **notifications** (no `id`)
to stdout before the final response:

```json
{"jsonrpc":"2.0","method":"event","params":{"type":"progress","pct":42,"stage":"pulling","message":"..."}}
{"jsonrpc":"2.0","method":"event","params":{"type":"log","level":"info","message":"..."}}
{"jsonrpc":"2.0","method":"event","params":{"type":"output","stream":"stdout","chunk":"...\n"}}
```

Errors return a JSON-RPC error response:
`{"jsonrpc":"2.0","id":<id>,"error":{"code":<int>,"message":<str>}}` —
`-32601` for an unknown method/command, `-32603` for an internal error.

## Low-level framing helpers

`gs_plugin.read_message(stream) -> dict | None` (returns `None` at clean EOF)
and `gs_plugin.write_message(stream, obj)` operate on **binary** streams and
can be used directly if you want to drive the protocol yourself.

## Self-test

```sh
python3 sdk/python/selftest.py
```

Spawns `examples/demo-py/plugin.py`, sends framed `describe` + `complete`
(`source="colors"`) + `invoke` (`greet`) requests, and asserts the responses.
