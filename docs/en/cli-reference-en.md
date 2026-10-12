# CLI reference

## Front-door commands

Handled natively by the Rust front door; no plugin involved.

| Command | Purpose |
|---|---|
| `gs` / `gs help` | help: front-door commands + plugins |
| `gs version` | version |
| `gs status` | plugin inventory and command totals |
| `gs doctor` | manifests / entries / plugin runtime / shell integration |
| `gs refresh` | rescan manifests (reports invalid ones) |
| `gs plugin list` | plugins and command counts |
| `gs plugin info <plugin> [group]` | one plugin's command surface (optionally one group) |
| `gs plugin enable\|disable <plugin>` | flip `enabled` in that plugin's `plugin.toml` |
| `gs plugin migrate <dir>` | convert a legacy `plugin.json` into `plugin.toml` |
| `gs init [step]` | provision this machine from `config/init.toml` |
| `gs completions [shell]` | emit completion scripts (`--install` writes them) |
| `gs shell-init <shell>` | emit the wrapper that provides `cd`/`export` effects |
| `gs __complete <words…>` | completion backend used by the scripts above |

### `gs init`

```bash
gs init --list                    # steps and their state
gs init --dry-run                 # check everything
gs init <step>                    # one step
gs init --group=<group>           # one group
gs init --only=<steps> --skip=<steps>
gs init --without=<groups>
gs init --yes <step>              # actually run it (otherwise it prints sudo lines)
```

## Plugin commands

Always

```
gs <plugin> <verb> [object] [args]
```

Groups work dotted (`device.logcat`) or space-separated (`device logcat`). A few
examples:

```bash
gs android device devices
gs android logcat clear --dry-run
gs android build build --dry-run
gs dotfiles install nvim --dry-run
gs dotfiles doctor
gs system proxy on --dry-run
gs system repo tsinghua --dry-run
gs system prompt themes
gs multirepo plan mini-aosp --backend=git
gs multirepo apply-plan plan.json --yes
gs sync status
gs identity claude show
gs vps status
gs vscode paths
gs spider classify https://www.jianshu.com/p/…
gs grep python 'def _search'
gs navigator list
gs alias sources bash
```

Use `gs plugin list` for the inventory and `gs plugin info <plugin>` per plugin.

## Conventions

- **Plan vs run** — writes require exactly one of `--dry-run` (print the plan) or
  `--yes` (do it); giving both or neither is an error.
- **JSON plans** — commands supporting `--format=json` emit a stable schema with
  `schema_version`, `mode`, `check`, … for CI.

| Exit code | Meaning |
|---|---|
| 0 | success |
| 1 | failure / check did not pass |
| 2 | usage error (arguments, flags, missing required option) |
| 127 | program to execute not found |

## Environment variables

| Variable | Effect |
|---|---|
| `GS_ROOT` | root of the plugin tree and config (set by `gs-launch`) |
| `GS_COMMAND_NAME` | command name baked into completions / shell init |
| `GS_LANGUAGE` / `GS_LANG` / `LANG` | output language (`zh` / `en`) |
| `GS_COLOR=0`, `NO_COLOR` | disable colour |
| `GS_CACHE_DIR` | describe / complete cache directory |
| `GS_PLUGIN_PATH` | extra plugin roots (`:`-separated) |
| `GS_INCLUDE_EXAMPLES=1` | also load `examples/` |
| `GS_ALLOW_EXTERNAL_PLUGINS=1` | with `GS_ROOT` set, also load user plugins |
| `GS_DAEMON_IDLE_MS` | T3 resident idle timeout (default 30000) |
| `GS_CD_FILE` / `GS_ENV_FILE` | effect files exchanged with the shell wrapper |

## Related

- [Plugin protocol](../protocol.md) · [Architecture](./architecture-en.md) · [Installation](./installation-en.md)
