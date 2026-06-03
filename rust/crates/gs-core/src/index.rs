//! Plugin discovery + the command index. For `plugin.toml`-based plugins this
//! replaces `router.json` as the source of truth (§2.4 / §6 #2).
//!
//! Loading is **lazy** by design: discovery only parses each `plugin.toml`
//! (cheap, no process launched), so top-level completion and `gs help` list
//! plugins without describing any of them. A plugin's command *tree* is resolved
//! on demand — inline from the manifest for T1/`static`, or via the `describe`
//! RPC for a T2+ `runtime` plugin. Completion batches `describe`+`complete` into
//! a single [`rpc::call_oneshot`] spawn, so resolving a tree at Tab time costs
//! at most one process; a persistent `index.json` cache (§2.4) is a pure
//! optimization layered on later.

use crate::cache;
use crate::manifest::{Capabilities, CommandSpec, PluginManifest, Tier};
use crate::rpc;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A parsed manifest plus the directory it lives in (used to resolve `entry`
/// and as the plugin process's cwd).
#[derive(Debug, Clone)]
pub struct LoadedManifest {
    pub manifest: PluginManifest,
    pub dir: PathBuf,
}

impl LoadedManifest {
    /// The interpreter program + argv to spawn this plugin (T2/T3). `python` →
    /// `python3`; other runtimes map 1:1. `entry` is resolved against `dir`.
    /// Returns `None` for T1 (never spawned) and T4 wasm (deferred).
    pub fn spawn(&self) -> Option<(String, Vec<String>)> {
        match self.manifest.tier {
            Tier::Script | Tier::Rpc => {
                let entry = self.dir.join(&self.manifest.entry);
                Some((
                    runtime_program(&self.manifest.runtime),
                    vec![entry.to_string_lossy().into_owned()],
                ))
            }
            Tier::Declarative | Tier::Wasm => None,
        }
    }

    /// Resolve the command tree: inline (T1 / `describe_cache != runtime`) or
    /// fetched via the `describe` RPC (T2+ runtime). A describe result is cached
    /// to disk keyed by `(plugin.toml/entry mtime, protocol, locale)`, so only
    /// the first Tab after a change pays for it (§2.4). The RPC is bounded by
    /// [`rpc::describe_timeout`]; a timeout/failure yields an empty tree — the
    /// plugin still lists, it just offers no sub-completions until next time.
    pub fn commands(&self, locale: &str) -> Vec<CommandSpec> {
        if self.manifest.commands_are_inline() {
            return self.manifest.commands.clone();
        }
        let Some((prog, args)) = self.spawn() else {
            return Vec::new();
        };
        let name = &self.manifest.name;
        let key = cache::DescribeKey::new(
            &self.dir,
            &self.manifest.entry,
            self.manifest.protocol,
            locale,
        );
        if let Some(result) = cache::read_describe(name, &key) {
            if let Ok(d) = rpc::parse_describe(&result) {
                return d.commands;
            }
        }
        let req = rpc::request(
            1,
            "describe",
            serde_json::json!({
                "protocol": self.manifest.protocol,
                "locale": locale,
                "plugin": name,
            }),
        );
        let dir = self.dir.clone();
        let exchange =
            rpc::with_timeout(rpc::describe_timeout(), move || {
                rpc::call_oneshot(&prog, &args, Some(&dir), &[req], true)
            });
        match exchange {
            Some(Ok(ex)) => match ex.result_for(1) {
                Some(r) => {
                    cache::write_describe(name, &key, r);
                    rpc::parse_describe(r).map(|d| d.commands).unwrap_or_default()
                }
                None => Vec::new(),
            },
            _ => Vec::new(), // timeout or spawn error → empty tree (non-fatal)
        }
    }

    pub fn capabilities(&self) -> &Capabilities {
        &self.manifest.capabilities
    }
}

/// The set of discovered plugins, ordered by `(priority, name)`.
#[derive(Debug, Default, Clone)]
pub struct Registry {
    pub plugins: Vec<LoadedManifest>,
}

impl Registry {
    /// Scan each root for `<root>/<plugin>/plugin.toml`, parse and validate it,
    /// and collect the valid ones. A malformed manifest is skipped (not fatal);
    /// the first definition of a given plugin `name` wins (earlier roots
    /// shadow later ones).
    pub fn discover(roots: &[PathBuf]) -> Registry {
        let mut plugins = Vec::new();
        let mut seen = BTreeSet::new();
        for root in roots {
            let Ok(entries) = std::fs::read_dir(root) else {
                continue;
            };
            for e in entries.flatten() {
                let path = e.path().join("plugin.toml");
                if !path.is_file() {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                if let Ok(manifest) = PluginManifest::parse(&text) {
                    if seen.insert(manifest.name.clone()) {
                        plugins.push(LoadedManifest {
                            manifest,
                            dir: e.path(),
                        });
                    }
                }
            }
        }
        plugins.sort_by(|a, b| {
            a.manifest
                .priority
                .cmp(&b.manifest.priority)
                .then_with(|| a.manifest.name.cmp(&b.manifest.name))
        });
        Registry { plugins }
    }

    pub fn get(&self, name: &str) -> Option<&LoadedManifest> {
        self.plugins.iter().find(|p| p.manifest.name == name)
    }

    /// Enabled plugins only (for completion / dispatch).
    pub fn enabled(&self) -> impl Iterator<Item = &LoadedManifest> {
        self.plugins.iter().filter(|p| p.manifest.enabled)
    }

    /// Targeted load for the dispatch hot path: the plugin named `name` from the
    /// first root that has `<root>/<name>/plugin.toml`, parsing only that one
    /// manifest (no full discovery). `None` if absent or malformed. The
    /// `enabled` flag is preserved so the caller can report a disabled plugin.
    pub fn find(roots: &[PathBuf], name: &str) -> Option<LoadedManifest> {
        // Fast path: the directory is usually named after the plugin.
        for root in roots {
            let dir = root.join(name);
            if let Ok(text) = std::fs::read_to_string(dir.join("plugin.toml")) {
                if let Ok(manifest) = PluginManifest::parse(&text) {
                    if manifest.name == name {
                        return Some(LoadedManifest { manifest, dir });
                    }
                }
            }
        }
        // Fallback: the manifest `name` may differ from its directory (e.g. dir
        // `demo-py`, name `demo`) — scan and match by name.
        Registry::discover(roots)
            .plugins
            .into_iter()
            .find(|p| p.manifest.name == name)
    }

    /// Like [`find`], but tells a *missing* plugin apart from a *broken* one:
    ///   - `Ok(Some(_))` — found and valid → dispatch it.
    ///   - `Ok(None)` — no `plugin.toml` for `name` → caller falls back (legacy
    ///     router.json / Python).
    ///   - `Err(msg)` — `<root>/<name>/plugin.toml` exists but is invalid → the
    ///     front door reports `msg` instead of silently delegating, so a broken
    ///     manifest surfaces the moment you run the plugin.
    ///
    /// Only the fast path (directory named after the plugin) reports errors; the
    /// by-name fallback stays lenient (a malformed sibling shouldn't block an
    /// unrelated command).
    pub fn find_checked(roots: &[PathBuf], name: &str) -> Result<Option<LoadedManifest>, String> {
        for root in roots {
            let dir = root.join(name);
            let toml = dir.join("plugin.toml");
            let Ok(text) = std::fs::read_to_string(&toml) else {
                continue; // no manifest here → try the next root
            };
            return match PluginManifest::parse(&text) {
                Ok(manifest) if manifest.name == name => Ok(Some(LoadedManifest { manifest, dir })),
                // Dir matches but the declared name differs — unusual; keep the
                // lenient by-name scan below rather than erroring.
                Ok(_) => break,
                Err(e) => Err(format!("{}：{e}", toml.display())),
            };
        }
        Ok(Registry::discover(roots)
            .plugins
            .into_iter()
            .find(|p| p.manifest.name == name))
    }
}

/// Map a manifest `runtime` to the program to spawn. `python` resolves to
/// `python3` (the de-facto interpreter on macOS/most Linux); everything else is
/// used verbatim.
pub fn runtime_program(runtime: &str) -> String {
    match runtime {
        "python" => "python3".into(),
        other => other.into(),
    }
}

/// Plugin-discovery roots, highest priority first (earlier roots shadow later
/// ones for a given plugin name):
///   1. `$GS_PLUGIN_PATH` — explicit, `:`-separated override (power users).
///   2. `$GS_ROOT/plugins` + `$GS_ROOT/examples` — the repo / dev tree.
///   3. `~/.config/global-scripts/plugins` — user-installed plugins; the durable
///      location that works with **no** `GS_ROOT` set.
pub fn default_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(pp) = std::env::var_os("GS_PLUGIN_PATH") {
        roots.extend(std::env::split_paths(&pp));
    }
    if let Some(gs_root) = std::env::var_os("GS_ROOT") {
        let r = PathBuf::from(gs_root);
        roots.push(r.join("plugins"));
        roots.push(r.join("examples"));
    }
    if let Some(home) = crate::home_dir() {
        roots.push(home.join(".config/global-scripts/plugins"));
    }
    roots
}

/// Resolve a plugin `entry`/path that may be relative to `dir`.
pub fn resolve_under(dir: &Path, rel: &str) -> PathBuf {
    let p = Path::new(rel);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        dir.join(rel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Build a throwaway plugin tree under a unique temp dir and return its root.
    fn scratch(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("gs-index-test-{tag}"));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    fn write_plugin(root: &Path, name: &str, toml: &str) -> PathBuf {
        let dir = root.join(name);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("plugin.toml"), toml).unwrap();
        dir
    }

    #[test]
    fn discovers_valid_manifests_sorted_and_skips_bad() {
        let root = scratch("discover");
        write_plugin(
            &root,
            "gitx",
            r#"name="gitx"
               tier="declarative"
               priority=30
               [[commands]]
               name="co"
               run="git checkout {b}""#,
        );
        write_plugin(
            &root,
            "aaa",
            r#"name="aaa"
               tier="declarative"
               priority=10
               [[commands]]
               name="x"
               run="true""#,
        );
        // malformed (T1 with runtime) → skipped, not fatal
        write_plugin(
            &root,
            "bad",
            "name=\"bad\"\ntier=\"declarative\"\nruntime=\"python\"\n",
        );
        // not a plugin dir (no plugin.toml) → ignored
        fs::create_dir_all(root.join("notplugin")).unwrap();

        let reg = Registry::discover(std::slice::from_ref(&root));
        let names: Vec<&str> = reg
            .plugins
            .iter()
            .map(|p| p.manifest.name.as_str())
            .collect();
        assert_eq!(
            names,
            vec!["aaa", "gitx"],
            "sorted by priority then name; bad skipped"
        );
        assert!(reg.get("gitx").is_some());
        assert!(reg.get("bad").is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn t1_commands_come_from_manifest_no_spawn() {
        let root = scratch("t1");
        write_plugin(
            &root,
            "gitx",
            r#"name="gitx"
               tier="declarative"
               [[commands]]
               name="co"
               summary={en="Checkout"}
               run="git checkout {branch}"
                 [[commands.args]]
                 name="branch""#,
        );
        let reg = Registry::discover(std::slice::from_ref(&root));
        let cmds = reg.get("gitx").unwrap().commands("en");
        assert_eq!(cmds.len(), 1);
        assert_eq!(cmds[0].name, "co");
        assert_eq!(cmds[0].run, "git checkout {branch}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn runtime_program_maps_python() {
        assert_eq!(runtime_program("python"), "python3");
        assert_eq!(runtime_program("bash"), "bash");
        assert_eq!(runtime_program("node"), "node");
    }

    // T2 runtime-describe path, exercised with a `sh` mock plugin that ignores
    // stdin and prints a framed `describe` response (no Python needed).
    #[cfg(unix)]
    #[test]
    fn t2_commands_come_from_runtime_describe() {
        let _g = crate::cache::test_isolate("index-t2");
        let root = scratch("t2");
        let dir = write_plugin(
            &root,
            "mock",
            r#"name="mock"
               tier="script"
               runtime="sh"
               entry="plugin.sh"
               describe_cache="runtime""#,
        );
        // The describe result the mock will emit.
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"protocol":1,"name":"mock","commands":[{"name":"hello","summary":{"en":"Hi"}}]}}"#;
        let script = format!(
            "printf 'Content-Length: {}\\r\\n\\r\\n%s' '{}'\n",
            body.len(),
            body
        );
        fs::write(dir.join("plugin.sh"), script).unwrap();

        let reg = Registry::discover(std::slice::from_ref(&root));
        let m = reg.get("mock").unwrap();
        assert!(
            !m.manifest.commands_are_inline(),
            "runtime cache → describe"
        );
        let cmds = m.commands("en");
        assert_eq!(cmds.len(), 1, "tree fetched via describe RPC");
        assert_eq!(cmds[0].name, "hello");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn find_checked_reports_invalid_and_distinguishes_missing() {
        let root = scratch("find-checked");
        write_plugin(
            &root,
            "ok",
            r#"name="ok"
               tier="declarative"
               [[commands]]
               name="x"
               run="true""#,
        );
        // Broken: a T1 plugin may not declare `runtime` (validate rejects it).
        write_plugin(
            &root,
            "broken",
            "name=\"broken\"\ntier=\"declarative\"\nruntime=\"python\"\n",
        );
        let roots = std::slice::from_ref(&root);

        assert!(matches!(Registry::find_checked(roots, "ok"), Ok(Some(_))));
        assert!(
            matches!(Registry::find_checked(roots, "missing"), Ok(None)),
            "no manifest → delegate, not error"
        );
        let err = Registry::find_checked(roots, "broken").unwrap_err();
        assert!(
            err.contains("broken") && err.contains("runtime"),
            "error names the file and the reason; got: {err}"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn default_roots_puts_explicit_path_first() {
        let _g = crate::cache::test_isolate("index-roots");
        std::env::set_var("GS_PLUGIN_PATH", "/opt/gs-plugins");
        let roots = default_roots();
        assert_eq!(roots.first(), Some(&PathBuf::from("/opt/gs-plugins")));
        std::env::remove_var("GS_PLUGIN_PATH");
    }
}
