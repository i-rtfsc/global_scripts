//! Global Scripts core (PoC scope).
//!
//! Holds the data model for the generated `router.json` index (schema v2.0,
//! produced by the Python `gscripts.router.indexer`), the path-resolution
//! rules for locating that index, and the pure command-resolution logic the
//! `gs` front door uses to decide *how* to dispatch a command.
//!
//! Execution (spawning processes) lives in the `gs` binary; this crate stays
//! side-effect free so it can be unit-tested and reused by the CLI.

use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub mod cache;
pub mod caps;
pub mod engine;
pub mod exec;
pub mod index;
pub mod manifest;
pub mod migrate;
pub mod rpc;

/// Top-level `router.json` shape. Unknown fields are ignored on purpose: the
/// Python indexer writes many more keys (description, author, …) the front
/// door does not need on the hot path.
#[derive(Debug, Default, Deserialize)]
pub struct RouterIndex {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub plugins: BTreeMap<String, PluginEntry>,
}

#[derive(Debug, Deserialize)]
pub struct PluginEntry {
    /// Bilingual (or arbitrary-locale) description, e.g. `{ "zh": …, "en": … }`.
    #[serde(default)]
    pub description: BTreeMap<String, String>,
    /// Absent/null is treated as enabled (matches the shell wrapper).
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub commands: BTreeMap<String, CommandEntry>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CommandEntry {
    /// The command token (function name). Hyphens map to underscores for shell.
    #[serde(default)]
    pub name: String,
    /// "shell" | "json" | "python" (normalized by the indexer).
    #[serde(default)]
    pub kind: String,
    /// Subplugin name, or "" for a direct plugin command.
    #[serde(default)]
    pub subplugin: String,
    /// Absolute path: `.sh` for shell, the `config_file` for json, `.py` for python.
    #[serde(default)]
    pub entry: String,
    /// Command template — only populated for `kind == "json"`.
    #[serde(default)]
    pub command: String,
    /// Bilingual (or arbitrary-locale) one-line summary, e.g. `{ "zh": …, "en": … }`.
    #[serde(default)]
    pub description: BTreeMap<String, String>,
}

fn default_true() -> bool {
    true
}

/// Outcome of resolving an argv against the router index.
#[derive(Debug)]
pub enum Resolution {
    /// A plugin command matched. `consumed` is how many leading argv tokens the
    /// match used (1 = `gs <plugin>`, 2 = `gs <plugin> <cmd>`, 3 = subplugin form).
    Command {
        plugin: String,
        consumed: usize,
        entry: CommandEntry,
        enabled: bool,
    },
    /// Not a recognized native command — hand off to the Python CLI.
    Delegate,
}

/// Resolve `args` (everything after `gs`) against the router index.
///
/// Tries the two-token subplugin form (`"<a> <b>"`) first, then the single
/// command token, then the bare-plugin form. Anything unmatched delegates.
pub fn resolve(router: &RouterIndex, args: &[String]) -> Resolution {
    let Some(plugin) = args.first() else {
        return Resolution::Delegate;
    };
    let Some(p) = router.plugins.get(plugin) else {
        return Resolution::Delegate;
    };

    // Subplugin form: `gs <plugin> <sub> <cmd> …` keyed as "<sub> <cmd>".
    if args.len() >= 3 {
        let key = format!("{} {}", args[1], args[2]);
        if let Some(c) = p.commands.get(&key) {
            return command(plugin, 3, c, p.enabled);
        }
    }
    // Direct command: `gs <plugin> <cmd> …`.
    if args.len() >= 2 {
        if let Some(c) = p.commands.get(&args[1]) {
            return command(plugin, 2, c, p.enabled);
        }
    }
    // Bare plugin: `gs <plugin>` where a command shares the plugin name.
    if let Some(c) = p.commands.get(plugin) {
        return command(plugin, 1, c, p.enabled);
    }
    Resolution::Delegate
}

fn command(plugin: &str, consumed: usize, entry: &CommandEntry, enabled: bool) -> Resolution {
    Resolution::Command {
        plugin: plugin.to_string(),
        consumed,
        entry: entry.clone(),
        enabled,
    }
}

/// Home directory from `$HOME` (POSIX) or `$USERPROFILE` (Windows).
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

/// Locate `router.json`, trying the most specific source first.
///
/// `$ROUTER_INDEX`, then `$GS_CACHE_DIR/{router,cache/router}.json`, then the
/// two well-known `~/.config/global-scripts` locations. Returns the first that
/// exists (the Python writer and the legacy `env.sh` disagree on `/cache`, so
/// we accept both).
pub fn router_index_path() -> Option<PathBuf> {
    let isolated = std::env::var_os("GS_ROOT").is_some()
        && std::env::var_os("GS_ALLOW_LEGACY").as_deref() != Some(std::ffi::OsStr::new("1"));
    if isolated {
        return None;
    }
    if let Some(p) = std::env::var_os("ROUTER_INDEX") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }

    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(cache) = std::env::var_os("GS_CACHE_DIR") {
        let c = PathBuf::from(cache);
        candidates.push(c.join("router.json"));
        candidates.push(c.join("cache").join("router.json"));
    }
    if let Some(home) = home_dir() {
        candidates.push(home.join(".config/global-scripts/cache/router.json"));
        candidates.push(home.join(".config/global-scripts/router.json"));
    }
    candidates.into_iter().find(|p| p.is_file())
}

/// Parse a `router.json` file into a [`RouterIndex`].
pub fn load_router(path: &Path) -> std::io::Result<RouterIndex> {
    let data = std::fs::read(path)?;
    serde_json::from_slice(&data)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

// F8 — native, jq-free Tab completion. The `gs __complete` engine: given the
// words already typed after `gs` (excluding the partial word at the cursor),
// return the candidates for the next position, each with an optional
// locale-picked description (zsh/fish show it). Pure & testable; the front door
// wires argv/printing and the per-shell scripts call it. Spec: design.md §14 /
// §13 Q5 and tmp/phase0-plugin-protocol.md §3–§4.
// ---------------------------------------------------------------------------
pub mod completion {
    use crate::{PluginEntry, RouterIndex};
    use std::collections::BTreeMap;

    /// One completion candidate: the token plus an optional description (shown
    /// by zsh/fish; ignored by bash).
    #[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    pub struct Candidate {
        pub value: String,
        pub description: Option<String>,
    }

    impl Candidate {
        fn new(value: impl Into<String>, description: Option<String>) -> Self {
            Self {
                value: value.into(),
                description,
            }
        }
    }

    /// Pick a description for `locale` from a `{locale: text}` map, falling back
    /// to en → zh → any. Empty strings count as absent.
    fn pick(d: &BTreeMap<String, String>, locale: &str) -> Option<String> {
        [locale, "en", "zh"]
            .into_iter()
            .filter_map(|k| d.get(k))
            .chain(d.values())
            .find(|s| !s.is_empty())
            .cloned()
    }

    /// Candidates for the position *after* `completed` (the words typed after
    /// `gs`, without the partial word at the cursor). `system` is
    /// (command, description, subcommands) for the front door's own commands.
    /// Returns value-sorted, value-unique, non-empty candidates with
    /// descriptions picked for `locale`; the shell does the prefix filtering.
    pub fn complete(
        router: &RouterIndex,
        system: &[(&str, &str, &[&str])],
        completed: &[String],
        locale: &str,
    ) -> Vec<Candidate> {
        let mut out: Vec<Candidate> = match completed {
            // first token: front-door commands + enabled plugins
            [] => system
                .iter()
                .map(|(c, d, _)| Candidate::new(*c, (!d.is_empty()).then(|| (*d).to_string())))
                .chain(
                    router
                        .plugins
                        .iter()
                        .filter(|(_, p)| p.enabled)
                        .map(|(name, p)| {
                            Candidate::new(name.clone(), pick(&p.description, locale))
                        }),
                )
                .collect(),
            // second token: a front-door command's subcommands, else a plugin's commands
            [head] => {
                let head = head.as_str();
                if let Some((_, _, subs)) = system.iter().find(|(c, _, _)| *c == head) {
                    subs.iter().map(|s| Candidate::new(*s, None)).collect()
                } else if let Some(p) = router.plugins.get(head) {
                    plugin_tokens(p, locale)
                } else {
                    Vec::new()
                }
            }
            // third token: commands under a subplugin (keys are "<sub> <cmd>")
            [head, sub] => router
                .plugins
                .get(head.as_str())
                .map(|p| subplugin_cmds(p, sub, locale))
                .unwrap_or_default(),
            _ => Vec::new(),
        };
        out.retain(|c| !c.value.is_empty());
        out.sort_by(|a, b| a.value.cmp(&b.value));
        out.dedup_by(|a, b| a.value == b.value);
        out
    }

    /// A plugin's first-level tokens: direct commands (with description) +
    /// subplugin group names (router.json has no per-group description).
    fn plugin_tokens(p: &PluginEntry, locale: &str) -> Vec<Candidate> {
        p.commands
            .iter()
            .map(|(key, cmd)| {
                if cmd.subplugin.is_empty() {
                    Candidate::new(key.clone(), pick(&cmd.description, locale)) // direct (key == name)
                } else {
                    Candidate::new(cmd.subplugin.clone(), None) // subplugin group (deduped by caller)
                }
            })
            .collect()
    }

    /// Commands under subplugin `sub` within a plugin.
    fn subplugin_cmds(p: &PluginEntry, sub: &str, locale: &str) -> Vec<Candidate> {
        p.commands
            .values()
            .filter(|c| c.subplugin == sub)
            .map(|c| Candidate::new(c.name.clone(), pick(&c.description, locale)))
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const SYSTEM: &[(&str, &str, &[&str])] = &[
            ("version", "show version", &[]),
            ("completions", "", &["bash", "zsh", "fish"]),
        ];

        fn router() -> RouterIndex {
            serde_json::from_str(
                r#"{
                "plugins": {
                    "demo": { "enabled": true,
                      "description": {"zh":"演示插件","en":"Demo plugin"},
                      "commands": {
                        "echo": {"name":"echo","kind":"json","subplugin":"","command":"echo {args}","description":{"zh":"打印","en":"Echo"}},
                        "greet": {"name":"greet","kind":"shell","subplugin":"","entry":"/x.sh"},
                        "tools build": {"name":"build","kind":"shell","subplugin":"tools","entry":"/x.sh","description":{"zh":"构建","en":"Build"}},
                        "tools run": {"name":"run","kind":"shell","subplugin":"tools","entry":"/x.sh"}
                    }},
                    "off": { "enabled": false, "commands": {
                        "x": {"name":"x","kind":"json","subplugin":"","command":"true"}
                    }}
                }
            }"#,
            )
            .unwrap()
        }

        fn vals(cs: Vec<Candidate>) -> Vec<String> {
            cs.into_iter().map(|c| c.value).collect()
        }

        #[test]
        fn top_level_lists_system_and_enabled_plugins() {
            let got = vals(complete(&router(), SYSTEM, &[], "en"));
            assert!(got.contains(&"version".to_string()));
            assert!(got.contains(&"demo".to_string()));
            assert!(
                !got.contains(&"off".to_string()),
                "disabled plugin hidden at top level"
            );
        }

        #[test]
        fn plugin_tokens_merge_direct_and_subplugin() {
            // direct commands + the subplugin group name, sorted & deduped
            assert_eq!(
                vals(complete(&router(), SYSTEM, &["demo".into()], "en")),
                vec!["echo", "greet", "tools"]
            );
        }

        #[test]
        fn subplugin_commands() {
            assert_eq!(
                vals(complete(
                    &router(),
                    SYSTEM,
                    &["demo".into(), "tools".into()],
                    "en"
                )),
                vec!["build", "run"]
            );
        }

        #[test]
        fn system_subcommands_and_unknowns() {
            assert!(complete(&router(), SYSTEM, &["nope".into()], "en").is_empty());
        }

        #[test]
        fn descriptions_follow_locale_with_fallback() {
            let find = |cs: &[Candidate], v: &str| {
                cs.iter()
                    .find(|c| c.value == v)
                    .unwrap()
                    .description
                    .clone()
            };
            let zh = complete(&router(), SYSTEM, &[], "zh");
            assert_eq!(find(&zh, "demo").as_deref(), Some("演示插件"));
            let en = complete(&router(), SYSTEM, &[], "en");
            assert_eq!(find(&en, "demo").as_deref(), Some("Demo plugin"));
            // unknown locale falls back en → zh → any
            let cmds = complete(&router(), SYSTEM, &["demo".into()], "fr");
            assert_eq!(find(&cmds, "echo").as_deref(), Some("Echo"));
            assert_eq!(find(&cmds, "greet"), None, "no description → None");
            // system command descriptions: present, and "" → None
            assert_eq!(find(&en, "version").as_deref(), Some("show version"));
            assert_eq!(find(&en, "completions"), None);
        }
    }
}
