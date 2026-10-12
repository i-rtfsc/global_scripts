# Contributing

## Development environment

You need exactly two things:

- **Rust** 1.75+ (via `rustup`)
- **Python 3.8+** (for T2/T3 plugins and the tools under `scripts/`)

No `uv`, no `jq`, no virtualenv.

```bash
git clone https://github.com/i-rtfsc/global_scripts.git
cd global_scripts
cargo build --manifest-path rust/Cargo.toml -p gs
```

## Layout

```
rust/crates/gs-core/   # pure logic (manifest/discovery/completion/RPC/cache/caps)
rust/crates/gs/        # the front-door binary
plugins/<name>/        # plugins (one plugin.toml each)
sdk/python/gs_plugin/  # T2/T3 plugin SDK
scripts/               # install, package, verification tooling
docs/                  # docs (spec in docs/protocol.md)
```

Behavioural contracts live in the [plugin protocol](../protocol.md) and the
[architecture](../en/architecture-en.md) doc.

## Everyday commands

```bash
# build
cargo build --manifest-path rust/Cargo.toml -p gs

# unit + integration tests
cd rust && cargo test --workspace

# formatting and lint (CI enforces these)
cargo fmt --all -- --check
cargo clippy --workspace --all-targets

# run straight from the checkout (does not touch an installed copy)
export GS_ROOT=$PWD
./rust/target/debug/gs doctor
./rust/target/debug/gs plugin list

# end-to-end acceptance (stages dist/gs and runs the full contract suite)
bash scripts/stage_release.sh
bash scripts/verify_gs.sh

# per-plugin health audit
python3 scripts/audit_plugins.py
```

## Conventions

### Rust

- Logic goes in `gs-core`; side effects (spawn, file writes, printing) go in the
  `gs` front door. Keep `gs-core` pure so it stays unit-testable.
- Front-door dispatch is `main.rs`'s `run()` → the matching module (`plugin.rs`,
  `shell.rs`, `system.rs`, `init.rs`, `dispatch.rs`).
- All presentation goes through `ui.rs`; do not hand-roll colours or tables.
- No emoji in output; honour `NO_COLOR`.

### Plugins

- One directory, one `plugin.toml`; the directory name must equal `name`.
- Destructive commands provide mutually exclusive `--dry-run` / `--yes`.
- Declare external programs in `[capabilities].exec` and env vars in `env`.
- See [plugin development](./plugin-development-en.md) for the full workflow.

## Commit conventions

Use Conventional Commit prefixes and explain *why*:

```
feat(android): add device screencap dry-run
fix(shell): keep cd effects when the wrapper is missing
refactor(core): split the front door into modules
docs(protocol): specify the completion directive
```

The repository uses a Gerrit-style `Change-Id:` trailer; add one line when
committing.

## Adding a plugin (shortest path)

```bash
mkdir plugins/myplugin
$EDITOR plugins/myplugin/plugin.toml      # see docs/protocol.md §2
# T1: write [[commands]] inline
# T2/T3: add an entry script and point `entry` at it
export GS_ROOT=$PWD
./rust/target/debug/gs doctor
./rust/target/debug/gs plugin info myplugin
python3 scripts/audit_plugins.py
```

`audit_plugins.py` checks manifests, metadata, groups and a smoke command. If your
plugin has no read-only smoke command yet, add one to the `SMOKE` table.

## Adding a front-door command

1. register it in `run()` in `rust/crates/gs/src/main.rs`;
2. implement it in the matching module (`system.rs` / `plugin.rs` / `shell.rs` /
   `init.rs`);
3. if completion should suggest it, update `SYSTEM_CMDS` in `shell.rs`;
4. run `cargo test --workspace` and `bash scripts/verify_gs.sh`.

## Documentation

- Protocol changes → [docs/protocol.md](../protocol.md) (the single spec);
- Important trade-offs → a new [ADR](../adr/);
- User-visible behaviour → [CLI reference](./cli-reference-en.md) and
  [changelog](../changelog.md).

## Related

- [Plugin protocol](../protocol.md) · [Architecture](./architecture-en.md) · [Plugin development](./plugin-development-en.md)
