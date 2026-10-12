//! Global Scripts core: the `plugin.toml` plugin model and the pure logic the
//! `gs` front door is built on.
//!
//! The crate is deliberately **side-effect free**: it owns discovery, the
//! manifest model, tier dispatch decisions, completion, caching, capability
//! checks and the resident-daemon protocol, but never spawns a process itself.
//! Execution lives in the `gs` binary, which keeps the core unit-testable.
//!
//! Module map (see `docs/protocol.md` for the manifest/wire contract):
//! - [`manifest`] — the `plugin.toml` schema and the normalized command model
//!   shared by every tier (T1 declarative, T2/T3 rpc, T4 wasm).
//! - [`index`] — lazy plugin discovery and the command index.
//! - [`engine`] — positional (Tab) completion for plugin commands.
//! - [`exec`] — T1 argv binding and `run` template rendering.
//! - [`rpc`] — JSON-RPC 2.0 over stdio with LSP framing, plus the one-shot
//!   transport used for T2 plugins.
//! - [`daemon`] — T3 resident plugin daemons.
//! - [`cache`] — on-disk describe/complete caches for the completion hot path.
//! - [`caps`] — least-privilege capability arbitration (deny by default).
//! - [`migrate`] — `gs plugin migrate`: legacy `plugin.json` to `plugin.toml`.
//! - [`init`] — the machine provisioning step list behind `gs init`.

use std::path::PathBuf;

pub mod cache;
pub mod caps;
pub mod daemon;
pub mod engine;
pub mod exec;
pub mod index;
pub mod init;
pub mod manifest;
pub mod migrate;
pub mod rpc;

/// Home directory from `$HOME` (POSIX) or `$USERPROFILE` (Windows).
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}
