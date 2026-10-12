# Installation

## Requirements

| Item | Requirement | Notes |
|---|---|---|
| Rust | 1.75+ | only to build **from source** |
| Python | 3.8+ | needed by T2/T3 plugins (`gs doctor` checks it) |
| Shell | bash / zsh / fish | PowerShell experimental |
| Platform | macOS / Linux | Windows via WSL2 |

No `jq`, no `uv`, no third-party Python packages — the plugin SDK is stdlib-only
and ships with the release archive.

## Install

### From source

```bash
git clone https://github.com/i-rtfsc/global_scripts.git
cd global_scripts

# 1. Build the release front door
cargo build --release --manifest-path rust/Cargo.toml -p gs

# 2. Produce the staging tree (dist/gs)
bash scripts/stage_release.sh

# 3. Install (defaults to ~/.local, no sudo)
bash scripts/install_gs.sh --yes
```

### From a release archive

```bash
# after unpacking the archive for your platform
bash scripts/install_gs.sh --yes
```

What the installer touches:

- the whole tree under `$PREFIX/share/global-scripts/<version>/`;
- a symlink `$PREFIX/bin/gs` → `<version>/gs-launch`;
- completion files plus `~/.config/global-scripts/shell/gs-env.{bash,zsh,fish}`,
  referenced from `~/.bashrc` / `~/.zshrc` / `~/.config/fish/config.fish`.

Options:

| Env var / flag | Effect |
|---|---|
| `GS_PREFIX=/opt/gs` | install prefix (default `~/.local`) |
| `--name gsp` | command name (default `gs`) |
| `GS_LINK_PRIVATE_ASSETS=0` | don't link private assets under `custom/userspace` |
| `GS_INCLUDE_PRIVATE=1` | package private plugins (private builds only) |

The installer never copies private keys, tokens or company config; private assets
are symlinked only.

## Shell integration

To get `cd` and `export` side effects, install the thin wrapper (it hands
`$GS_CD_FILE` / `$GS_ENV_FILE` to `gs` and `eval`s the result):

```bash
# bash
echo 'source <(gs shell-init bash)' >> ~/.bashrc
# zsh
echo 'source <(gs shell-init zsh)'  >> ~/.zshrc
# fish
gs shell-init fish > ~/.config/fish/conf.d/gs.fish
```

Completion is installed separately:

```bash
gs completions bash --install     # or zsh / fish; no argument installs all
```

## Verify

```bash
gs version
gs doctor        # manifest / entry / plugin runtime / shell integration
gs plugin list
```

The `插件运行时` row tells you whether the interpreter your T2/T3 plugins need is
on `PATH`.

### Private plugins

Private plugins such as `sgm` and `flyme` live only in `custom/userspace/<name>/`
(`custom/` is git-ignored) and never ship in the repository or the release
package. `scripts/install_gs.sh --yes` copies them into the local install tree so
your own `gs` still sees them.

## Upgrade and uninstall

```bash
bash scripts/install_gs.sh --yes     # re-running upgrades in place
bash scripts/uninstall_gs.sh --yes   # removes only gs
```

If `~/.local/bin/gs` pointed somewhere else, it is first renamed to
`gs.backup-<timestamp>`.

## Name clash with Ghostscript

Many systems ship a `gs` (Ghostscript). After install, `~/.local/bin/gs` comes
first on `PATH` and shadows it. Call `/usr/bin/gs` by absolute path, or install
with `--name gsp`.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `gs: command not found` | `~/.local/bin` is not on `PATH`, or reopen the terminal |
| `env: 'command': No such file or directory` | stale fish integration — reinstall `gs shell-init fish` |
| plugin commands cannot find an interpreter | install `python3`, then re-run `gs doctor` |
| completion does nothing | `gs completions <shell> --install`, then reopen the terminal |
| `gs <plugin>` reports an invalid plugin.toml | fix the manifest at the reported line; `gs doctor` lists every problem |

## Related

- [Quick start](./quickstart-en.md) · [Architecture](./architecture-en.md) · [Plugin protocol](../protocol.md)
