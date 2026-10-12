# Plugin development

The full field/protocol reference is [docs/protocol.md](../protocol.md). This is
the hands-on tutorial.

## 1. Three kinds of plugin

| You want | Tier | Processes |
|---|---|---|
| Wrap an existing command as `gs xxx` | T1 declarative | 0 |
| Real branching / parsing logic | T2 script | 1 per call |
| That, called often | T3 resident | reused |

## 2. A T1 plugin (zero processes)

```
plugins/gitx/
└── plugin.toml
```

```toml
name    = "gitx"
version = "1.0.0"
tier    = "declarative"
category = "development"
description = { zh = "Git 快捷封装", en = "Git shortcuts" }

[groups.co]
zh = "分支操作"
en = "Branch operations"

[capabilities]
exec = ["git", "code"]

[[commands]]
name    = "co"
summary = { zh = "切换分支", en = "Checkout branch" }
usage   = "gs gitx co <branch>"
run     = "git checkout {branch}"

  [[commands.args]]
  name = "branch"
  type = "string"
  required = true
  [commands.args.complete]
  kind    = "dynamic"
  command = "git branch --format=%(refname:short)"
```

Notes:

- `run` is an **argv template**: the core splits it on whitespace and expands
  `{branch}` as a separate argument, so a branch name containing spaces stays one
  argument and there is no shell-injection surface;
- add `shell = true` for pipes/redirects/`&&` — the whole line goes to the system
  shell and placeholders are substituted with escaping;
- to change the caller's directory, use `cd = "$HOME/code/foo"` instead of `run`;
- the `exec` allowlist is enforced: the first word of `run` must be listed.

## 3. A T2 plugin

```
plugins/hello/
├── plugin.toml
└── hello.py
```

`plugin.toml`:

```toml
name    = "hello"
version = "1.0.0"
tier    = "script"
runtime = "python"
entry   = "hello.py"

[capabilities]
exec = ["echo"]
env  = ["GS_ROOT"]
```

`hello.py`:

```python
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))
from gs_plugin import Plugin  # noqa: E402

plugin = Plugin(name="hello")


@plugin.command(
    name="greet",
    summary={"zh": "打招呼", "en": "Greet"},
    usage="gs hello greet <who>",
    args=[{"name": "who", "type": "string", "required": True}],
)
def greet(ctx):
    ctx.emit_output("stdout", "hello {}\n".format(ctx.args.get("who")))
    return 0


@plugin.completer(source="colors")
def colors(params):
    return ["red", "green", "blue"]


if __name__ == "__main__":
    plugin.run()
```

Notes:

- you do not duplicate the command tree in `plugin.toml`: `describe` derives it
  from the decorators, and it is isomorphic to the inlined manifest shape;
- handlers return an `int` exit code, or a dict merged into the result
  (`stdout`/`stderr`/`env`/`exec`);
- use `ctx.emit_progress/log/output` for long tasks so output is not buffered to
  the end;
- to ask the core to run a command, return
  `{"exit_code": 0, "exec": ["git", "status"]}` — still gated by `exec`.

Switching to a resident plugin is just `tier = "rpc"`.

## 4. Completion

| Case | Form |
|---|---|
| Fixed values | `complete = { kind = "enum", values = [...] }` |
| Files / directories | `complete = { kind = "file", pattern = "*.apk" }` / `kind = "dir"` |
| T1 dynamic | `complete = { kind = "dynamic", command = "…" }` (core runs it, capability-checked) |
| T2+ dynamic | `complete = { kind = "dynamic", source = "colors" }` → `@plugin.completer(source="colors")` |

## 5. Debugging

```bash
# run straight from the checkout without touching an installed copy
export GS_ROOT=$PWD
cargo build --manifest-path rust/Cargo.toml -p gs
./rust/target/debug/gs doctor
./rust/target/debug/gs plugin info hello
./rust/target/debug/gs hello greet world
./rust/target/debug/gs __complete hello greet
```

Editing a manifest needs no restart; T2+ describe caches are keyed by mtime and
invalidate themselves.

## 6. Before committing

```bash
python3 scripts/audit_plugins.py          # manifest/metadata/groups/smoke
bash scripts/verify_gs.sh                 # end-to-end contracts
cd rust && cargo test --workspace
```

## 7. Rules

- One plugin directory = one `plugin.toml`; do not add a `plugin.json`.
- The directory name must equal the manifest `name`.
- Destructive commands offer `--dry-run` and `--yes` (mutually exclusive, exactly one).
- No emoji in output; honour `NO_COLOR`.
- Declare external programs in `exec` and environment variables in `env`.
- Name commands verb + object, group with dots (`device.logcat`), and describe
  groups in `[groups]`.

## Related

- [Plugin protocol](../protocol.md) · [Architecture](./architecture-en.md) · [CLI reference](./cli-reference-en.md)
