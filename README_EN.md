# Global Scripts

[中文](README.md) | [English](README_EN.md)

[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![Version](https://img.shields.io/badge/version-6.0.0--dev-brightgreen.svg)](https://github.com/i-rtfsc/global_scripts)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](./LICENSE)

> One `gs` for your dev box: command wrappers, Android tooling, dotfiles and
> machine provisioning — described by `plugin.toml`, dispatched by a Rust front door.

## What it is

Global Scripts (GS) 6.0 is a command and plugin system. You type
`gs <plugin> <command> [args]`; the Rust front door reads that plugin's
`plugin.toml` and executes it according to its declared tier:

- **T1 declarative** — the command *is* a `run` template; the core renders the
  argv itself and **spawns nothing**;
- **T2 script / T3 resident** — the plugin answers JSON-RPC over stdio; T3 keeps
  a resident process to skip interpreter cold start;
- **T4 wasm** — run a sandboxed module through wasmtime.

The command tree, arguments, completion rules and capability declarations all
live in a single `plugin.toml`. There is no second manifest and no hidden loader.

## Features

- **Single source of truth** — one `plugin.toml` per plugin; completion, help and
  validation share one model.
- **Fast completion** — discovery only parses manifests; T1 completion is fully
  static, T2+ resolves in one process and caches to disk.
- **Deny-by-default capabilities** — `exec` / `env` / `fs` / `net` must be
  declared; `exec` and `env` are enforced by the core.
- **Safe defaults** — writes require `--dry-run` or `--yes`; `gs` never escalates
  privileges, it only prints the `sudo …` line for you.
- **Scriptable** — `--format=json` plans for CI.
- **No emoji, honors `NO_COLOR`** — tables degrade cleanly when piped.

## Install

### From source

```bash
git clone https://github.com/i-rtfsc/global_scripts.git
cd global_scripts

# 1. Build the Rust front door
cargo build --release --manifest-path rust/Cargo.toml -p gs

# 2. Produce the staging tree (dist/gs)
bash scripts/stage_release.sh

# 3. Install into ~/.local (no copy, no sudo)
bash scripts/install_gs.sh --yes
```

### From a release archive

Download `gs-<target>.zip` for your platform, unpack it, then run

```bash
bash scripts/install_gs.sh --yes
```

The installer touches exactly two things: a symlink at `~/.local/bin/gs` and the
real tree under `~/.local/share/global-scripts/<version>/`. Use `GS_PREFIX=…` for
another prefix, `--name` for another command name, and
`scripts/uninstall_gs.sh --yes` to remove it.

## Requirements

- **Rust** 1.75+ (only to build from source)
- **Python 3.8+** for T2/T3 plugins (`gs doctor` checks it)
- **Shell**: bash / zsh / fish (PowerShell experimental)
- No `jq`, no `uv`, no third-party Python packages.

## Quick start

```bash
gs help                       # front-door commands
gs plugin list                # plugins and command counts
gs doctor                     # manifests / entries / plugin runtime / shell integration
gs android device devices     # run a plugin command
gs init --list                # the machine setup plan (config/init.toml)
```

Enable completion and `cd` integration (pick one, add to your rc file):

```bash
source <(gs shell-init bash)
source <(gs shell-init zsh)
gs shell-init fish > ~/.config/fish/conf.d/gs.fish
```

## Bundled plugins

| Plugin | What it does |
|---|---|
| `android` | device, logcat, dump, emulator, fs, frida, perfetto, winscope, builds |
| `dotfiles` | install / backup / restore / audit for nvim, vim, tmux, git, fish, zsh |
| `system` | mirrors, proxy, prompt themes |
| `identity` | model accounts + node switching, Git/SSH private config |
| `multirepo` | plan / apply / sync for AOSP-style manifests |
| `sync` | controlled Git worktree sync to a target tree |
| `devenv` | dev environment checks and explicit installs |
| `vscode` / `vps` / `spider` / `grep` / `navigator` / `alias` | editor, VPS, article extraction, search, navigation, alias audit |

`gs plugin info <plugin>` shows a plugin's full command surface.

## Documentation

| Doc | Contents |
|---|---|
| [Plugin protocol](./docs/protocol.md) | manifest / RPC / cache / daemon spec |
| [Architecture](./docs/en/architecture-en.md) | layers, dispatch path, trade-offs |
| [Plugin development](./docs/en/plugin-development-en.md) | write a plugin from scratch |
| [Installation](./docs/en/installation-en.md) · [Quick start](./docs/en/quickstart-en.md) | setup and first steps |
| [Docs index](./docs/en/readme-en.md) | every document |

## License

Apache-2.0, see [LICENSE](./LICENSE).
