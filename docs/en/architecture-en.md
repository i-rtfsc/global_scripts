# Architecture

How Global Scripts (GS) 6.0 is put together. For the wire/manifest contract see
[docs/protocol.md](../protocol.md).

## 1. Scope and principles

GS 6.0 is the **only runtime**. The GS 5.2 Python implementation
(`src/gscripts`, `router.json` dispatch, `plugin.json`/`commands.json`) has been
retired — see [ADR 005](../adr/005-retire-gs52-python-runtime.md).

Four principles:

1. **Single source of truth** — one `plugin.toml` per plugin defines its command
   tree, capabilities and metadata. No `plugin.json`, no decorator scanning, no
   `router.json` index.
2. **Side-effect-free core** — `gs-core` only does pure logic (parsing,
   discovery, completion, binding, capability checks, framing). It never spawns a
   process, so it is fully unit-testable.
3. **Deny by default** — a plugin must explicitly declare what it executes,
   reads/writes and which environment variables it needs.
4. **Lazy by layer** — discovery only parses `plugin.toml`; a command tree is
   resolved inline or via a single `describe`, so Tab completion and `gs help`
   never start a plugin.

## 2. Layers

```
┌──────────────────────────────────────────────────────────────┐
│ Front door  rust/crates/gs                                   │
│   main.rs      entry / bootstrap / dispatch                  │
│   dispatch.rs  T1 exec, T2/T3 invoke, cd/env effects          │
│   plugin.rs    gs plugin list|info|enable|disable|migrate    │
│   shell.rs     gs __complete / completions / shell-init      │
│   system.rs    gs status / doctor / refresh                  │
│   init.rs      gs init (step list from config/init.toml)     │
│   ui.rs        the single presentation layer (tabled + color)│
└───────────────────────────┬──────────────────────────────────┘
                            │ pure function calls
┌───────────────────────────▼──────────────────────────────────┐
│ Core  rust/crates/gs-core                                    │
│   manifest.rs  plugin.toml schema + normalized command model │
│   index.rs     lazy discovery / command index / program lookup│
│   engine.rs    positional (Tab) completion                   │
│   exec.rs      T1 argv binding + run template rendering      │
│   rpc.rs       JSON-RPC 2.0 + LSP framing + one-shot channel │
│   daemon.rs    T3 resident plugin daemon                      │
│   cache.rs     on-disk describe / complete caches            │
│   caps.rs      capability arbitration (deny by default)      │
│   migrate.rs   plugin.json → plugin.toml (migration tool)    │
│   init.rs      config/init.toml step model                   │
└───────────────────────────┬──────────────────────────────────┘
                            │ stdio / socket
┌───────────────────────────▼──────────────────────────────────┐
│ Plugins  plugins/<name>/  +  SDK  sdk/python/gs_plugin        │
│   T1 declarative: no process; core renders the argv           │
│   T2 script / T3 rpc: JSON-RPC over stdio                     │
│   T4 wasm: run the module through wasmtime                    │
└──────────────────────────────────────────────────────────────┘
```

## 3. Directory layout

```
global_scripts/
├── rust/                      # Rust front door and core
│   └── crates/{gs,gs-core}/
├── plugins/<name>/            # formal plugins (one plugin.toml each)
├── examples/                  # plugin examples (only with GS_INCLUDE_EXAMPLES=1)
├── sdk/python/gs_plugin/      # T2/T3 plugin SDK (stdlib only)
├── config/init.toml           # step list for `gs init`
├── config/gs.json             # user preferences (language / prompt_theme)
├── themes/prompt/             # prompt themes
├── custom/                    # private area (git-ignored)
├── scripts/                   # install / package / verification tooling
└── docs/                      # documentation (spec in protocol.md)
```

## 4. The path of one call

```
gs <args>
  │
  ├─ front-door command? (version/help/status/doctor/init/plugin/completions/…)
  │     → handled natively
  │
  ├─ is args[0] a plugin?
  │     → read plugins/<name>/plugin.toml
  │       ├─ T1 → exec.rs binds argv, renders run (or cd), executes under caps
  │       ├─ T2 → rpc.rs spawns once, describe/invoke
  │       ├─ T3 → daemon.rs reuses the resident process
  │       └─ T4 → wasmtime runs the module
  │
  └─ neither → a clear error (hint: gs help / gs plugin list)
```

**There is no Python fallback and no `router.json` fallback**: an unknown input
fails immediately with a next step.

### 4.1 Tiers

| tier | alias | core behaviour | when to use |
|---|---|---|---|
| `declarative` | T1 | zero processes | thin wrappers around `git`/`echo`-style commands |
| `script` | T2 | one interpreter per call | real logic, infrequent calls |
| `rpc` | T3 | resident process reused | real logic, frequent calls (saves cold start) |
| `wasm` | T4 | run via wasmtime | sandboxing or a non-Python implementation |

## 5. Key design decisions

### 5.1 One data model, isomorphic across tiers

The command tree inlined in `plugin.toml` and the tree returned by a T2+ runtime
`describe` are **exactly the same shape** (`CommandSpec`). Completion, help and
argument validation are therefore tier-agnostic: one `engine::complete` serves
every plugin.

### 5.2 The Tab hot path

Every keypress is a fresh process, so:

- discovery parses `plugin.toml` only (no plugin is started);
- T1 `enum`/`file`/`dir` completion is fully static, zero callbacks;
- T1 dynamic completion runs the manifest's `command` (capability-checked);
- T2+ `describe`/`complete` are batched into **one** process start and cached to
  disk (keyed by manifest and entry mtime, protocol version, locale).

### 5.3 Capabilities and safety

`[capabilities]` denies everything by default. `exec` and `env` are **enforced**
by the core (it controls the spawn and the child environment); `fs`/`net` are
advisory declarations echoed back to the plugin, with real sandboxing deferred to
future OS facilities.

Destructive work requires an explicit `--dry-run` or `--yes`, and `gs` itself
**never** escalates privileges — it prints the `sudo …` line for the user.

### 5.4 Resident plugins (T3)

The socket path embeds a generation hash of the plugin's content (editing a plugin
changes the path and the old daemon ages out); idle daemons exit on a timeout; a
client that vanishes mid-request poisons its daemon so replies can never leak to
the next caller; and when no daemon can start the transport degrades to one-shot.
See [protocol.md §8](../protocol.md).

### 5.5 Presentation

All output goes through one module, `gs/src/ui.rs`: `tabled` for tables,
`anstyle` for colour, `indicatif` for progress. Rules: no emoji, honour
`NO_COLOR`, adapt to width, degrade when not a TTY.

## 6. Extension points

- **Add a command** — edit the plugin's `plugin.toml` (T1) or add a
  `@plugin.command` in the plugin script (T2/T3).
- **Add a plugin** — create `plugins/<name>/plugin.toml` plus an entry script;
  see [plugin development](./plugin-development-en.md) and the
  [protocol appendix](../protocol.md).
- **Add a front-door command** — register it in `run()` in `gs/src/main.rs` and
  implement it in the matching module.
- **Add a provisioning step** — edit `config/init.toml`; `gs init` picks it up.

## 7. Relationship to 5.2

The GS 5.2 Python implementation has been retired from the repository
(`src/gscripts`, `tests/`, `scripts/setup.py`, `plugin.json`/`plugin.py`, the
`router.json` dispatch path). Users still migrating their own old plugins can run
`gs plugin migrate <dir>` to convert a `plugin.json` into a `plugin.toml`.
Decision records live in [docs/adr](../adr/).

## Related documents

- [Plugin protocol](../protocol.md) — manifest / RPC / cache / daemon spec
- [Plugin development](./plugin-development-en.md)
- [Installation](./installation-en.md) · [Quick start](./quickstart-en.md)
- [Migration status](./migration-status-en.md)
