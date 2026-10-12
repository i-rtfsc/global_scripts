# FAQ

## 6.0 vs 5.2

**Is the 5.2 Python implementation still here?**
No. `src/gscripts/`, `tests/`, `scripts/setup.py`, `plugin.json`/`plugin.py` and
the `router.json` dispatch path were retired from the repository (see
[ADR 005](../adr/005-retire-gs52-python-runtime.md)). They remain in git history.

**I have my own old plugin — can I still use it?**
Convert it:

```bash
gs plugin migrate /path/to/old-plugin --write
```

It reads `plugin.json` (and `commands.json`) and writes a 6.0 `plugin.toml`.

**Why is Python still needed?**
Because some plugins are T2/T3 tiers implemented in Python. The core and front
door are Rust; `gs doctor` checks that `python3` is on `PATH`. No `uv`, no `jq`.

## Day to day

**`gs` clashes with Ghostscript.**
`~/.local/bin/gs` comes first on `PATH` and shadows it. Call `/usr/bin/gs` by
absolute path, or reinstall with `--name gsp`.

**A `cd` command did not change directory.**
You need shell integration: `source <(gs shell-init bash)` (same for zsh; for fish
write to `~/.config/fish/conf.d/gs.fish`). Without it a `cd` command only prints
the target path.

**How do I turn colour off?**
`NO_COLOR=1` or `GS_COLOR=0`. Output degrades automatically when piped.

**How do I switch to English output?**
`export GS_LANGUAGE=en` (or `GS_LANG`; otherwise `LC_ALL`/`LANG` is used).

## Plugin system

**What is a plugin's source of truth?**
The `plugin.toml` in its directory: command tree, arguments, completion rules and
capabilities all live there. There is no second manifest.

**Why inline the command tree instead of writing code?**
Inlining (T1) lets the core execute and complete with zero processes, so `gs help`
and Tab never start a plugin. Use T2/T3 when you need real logic.

**T2 or T3?**
T2 for infrequent calls (one process each); T3 for frequent calls (resident
process reused, skipping interpreter cold start).

**Why is completion fast?**
Discovery only parses manifests; T1 completion is fully static; T2+ `describe` and
`complete` are batched into one process start and cached to disk.

**Can a plugin run whatever it wants?**
No. `[capabilities]` denies by default and `exec`/`env` are enforced by the core;
undeclared programs are refused.

**Why do destructive commands need `--dry-run` or `--yes`?**
Every write must pick one, to prevent accidents. `gs` never escalates privileges;
it prints the `sudo …` line instead.

## Development and verification

**How do I run the tests?**

```bash
cd rust && cargo test --workspace        # Rust unit + integration
bash scripts/verify_gs.sh                # end-to-end acceptance (build first)
python3 scripts/audit_plugins.py         # per-plugin manifest/metadata/smoke
```

**`gs doctor` says a plugin manifest is invalid.**
Fix the file and line it reports; `doctor` lists every problem at once, and
`gs refresh` rescans.

## Related

- [Plugin protocol](../protocol.md) · [Architecture](./architecture-en.md) · [Installation](./installation-en.md)
