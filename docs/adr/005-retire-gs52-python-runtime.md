# ADR 005: Retire the GS 5.2 Python Runtime

## Status

Accepted. Supersedes [ADR 002](./002-in-place-plugin-migration.md) and
[ADR 003](./003-remove-menubar.md); makes the Python-side scope of
[ADR 001](./001-migrate-to-clean-architecture.md) historical.

## Context

GS 6.0 shipped a Rust front door and a `plugin.toml` plugin protocol, but the
repository still carried the entire GS 5.2 Python implementation next to it:

- `src/gscripts/` — ~22k lines (CLI, router, plugin loaders, parsers, menubar,
  shell-completion generator);
- `tests/` — ~23k lines of pytest, almost all of it exercising `gscripts`;
- `scripts/setup.py` — the 5.2 installer;
- `plugin.json` / `plugin.py` / `plugin.sh` / `commands.json` inside plugin
  directories — a second manifest and a second implementation per plugin;
- the `router.json` dispatch path in the Rust front door, which fell back to
  `uv run python -m gscripts.cli.main` for anything it could not resolve.

Measurements and reviews during the 6.0 migration showed the cost of keeping it:

- **Two implementations per plugin.** `plugin.toml` pointed at the new
  `<name>.py`, while the legacy `plugin.py` (roughly 2,700 lines across the
  tree) was reachable only through the dead `router.json` path.
- **Python was never removed.** 12 of 13 plugins are `tier = "rpc"`, so the hot
  path still starts an interpreter; the front door additionally needed `uv`,
  making the runtime depend on a tool nothing else used.
- **The acceptance gate depended on the thing being retired.** Command parity
  was measured against the 5.2 loader, so the legacy files could not be deleted
  without also deciding the parity audit's fate.
- **Documentation drifted.** `docs/architecture.md` and `README.md` still
  described the Python layers and the `uv`-based install.

Keeping both systems indefinitely was rejected: it doubles the surface a
contributor must understand, hides which implementation actually runs, and makes
every release bigger.

## Decision

GS 6.0 is the only runtime. The 5.2 Python implementation is retired from
`develop`:

1. **Delete the Python tree** — `src/gscripts/`, `tests/`, `scripts/setup.py`,
   `scripts/audit_command_parity.py`, `pyproject.toml`, `pytest.ini`.
2. **One implementation per plugin** — delete every plugin's `plugin.json`,
   legacy `plugin.py` / `plugin.sh`, `commands.json`, and `plugins/menubar/`.
   `plugins/android/build/plugin.sh` stays: it is a build asset sourced by the
   new implementation, not a legacy manifest.
3. **Remove the fallback path** — drop `delegate_python`, the `router.json`
   resolution (`resolve` / `load_router` / `router_index_path`) and
   `gs-core::completion`. An unknown command now fails with an explicit error
   and a hint instead of silently invoking another interpreter.
4. **Rename the escape hatch** — `GS_ALLOW_LEGACY` becomes
   `GS_ALLOW_EXTERNAL_PLUGINS` (same semantics: a `$GS_ROOT` checkout is
   isolated from the user's own plugin directory unless explicitly allowed).
5. **Keep a migration door** — `gs plugin migrate <dir>` still converts a
   third-party `plugin.json` into `plugin.toml`.

The code is not lost: it remains in git history, and
`git show <sha>:src/gscripts/...` still works. The last commit that contained it
is referenced in [migration-status](../migration-status.md).

## Consequences

- The repository carries one plugin protocol, one loader and one test strategy
  (Rust unit/integration tests plus `scripts/verify_gs.sh`).
- `uv` and `jq` are no longer dependencies of anything; T2/T3 plugins need only
  a `python3` on `PATH`, which `gs doctor` now verifies.
- Deleting ~60k lines removes the parity audit's baseline. Command parity is no
  longer measured against 5.2; correctness is measured by the front-door
  acceptance suite and the per-plugin audit instead.
- 5.2 users who still want the old behaviour must use an old tag
  (`v5.0.0` or a commit before this ADR); the `develop`/`main` lines are 6.0 only.
- Anyone with a personal 5.2-era plugin outside this repository can still
  migrate it with `gs plugin migrate`.
