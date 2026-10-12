# GS 6.0 migration status

## Where we are

GS 6.0 is the only runtime. Every plugin in the repository has exactly one
`plugin.toml` and one implementation.

| Item | Value |
|---|---|
| Public plugins | 13 (see `gs plugin list`) |
| Private plugins | `sgm` / `flyme`, only in `custom/userspace/` (not committed, not shipped) |
| Front door | Rust (`rust/crates/gs`) + core (`rust/crates/gs-core`) |
| 5.2 Python implementation | retired, see [ADR 005](../adr/005-retire-gs52-python-runtime.md) |

## Migrated and verified

| Plugin | Tier | How it is verified |
|---|---|---|
| `navigator` | T1 declarative | front-door E2E; `$HOME` expansion |
| `alias` | T2 | read-only inspection and source detection |
| `dotfiles` | T2 | real install/backup/restore in an isolated `$HOME` |
| `devenv` | T2 | fake brew/apt executors assert real arguments |
| `grep` | T2 | search without shell option injection |
| `spider` | T2 | URL allowlist and output boundaries |
| `multirepo` | T2 | real clone from a local bare repo + plan/apply |
| `sync` | T2 | real copy from a temp Git repo to a target tree |
| `system` | T2 | mirror/proxy dry-runs and theme enumeration |
| `vps` | T2 | 8 commands; writes require `--dry-run`/`--yes` |
| `identity` | T2 | generated fixtures; nothing private in the package |
| `android` | T2 | read-only commands on a real device; risky ones stay dry-run |
| `vscode` | T2 | fake `code` executor asserts launch arguments |

## Private plugins

The `sgm` and `flyme` **code** also stays out of the public repository and the
release package; it lives only in `custom/userspace/<name>/` (`custom/` is
git-ignored). `scripts/install_gs.sh` copies it into the local install tree, so
your own `gs` still sees it while third parties do not.

## What happened to 5.2

`src/gscripts/` (~22k lines), `tests/` (~23k lines), `scripts/setup.py`,
`scripts/audit_command_parity.py`, `pyproject.toml`, `pytest.ini`, every plugin's
`plugin.json`/`plugin.py`/`plugin.sh`/`commands.json`, and `plugins/menubar/` were
deleted from `develop`/`main`.

The code remains in git history:

```bash
git log --oneline -1 --diff-filter=D -- src/gscripts
git show <sha>:src/gscripts/cli/main.py | head
```

`gs plugin migrate <dir>` still converts a third-party `plugin.json` into
`plugin.toml`.

## Verification

```bash
cd rust && cargo test --workspace        # Rust unit + integration
bash scripts/verify_gs.sh                # end-to-end (build + stage first)
python3 scripts/audit_plugins.py         # per-plugin manifest/metadata/smoke
python3 scripts/verify_package.py --root <dir> --target <target>
```
