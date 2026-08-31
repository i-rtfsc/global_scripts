//! Front-door **completion engine** for `plugin.toml` plugins — the F8 core
//! (and, with [`crate::exec`], the dispatch decision). Spec:
//! tmp/phase0-plugin-protocol.md §3–§4.
//!
//! Input is the words already completed after `gs` (the shell tokenizes — we
//! deliberately consume pre-split words rather than re-parse a raw `COMP_LINE`,
//! sidestepping per-shell quoting divergence). Output is the candidates for the
//! next position plus a **Cobra-style directive** (`:<bits>` on the final line),
//! which tells the shell whether to also do file / directory completion. The
//! shell filters candidates by the partial word, so the engine never needs it.
//!
//! Resolution per position:
//!   - nothing typed   → front-door commands + enabled plugins
//!   - `<plugin>`       → that plugin's command names (`.`-dotted, flat)
//!   - `<plugin> <cmd> …` → that command's args: a flag's value, or the next
//!     positional, resolved by its [`CompleteRule`] —
//!     `enum` (static) · `file`/`dir` (directive) · `dynamic` (T1 runs
//!     `command`, capability-checked; T2+ calls the plugin via RPC).

use crate::cache;
use crate::caps;
use crate::completion::Candidate;
use crate::index::{LoadedManifest, Registry};
use crate::manifest::{pick, ArgSpec, CommandSpec, CompleteKind, Tier};
use crate::rpc;
use std::process::{Command, Stdio};

/// Cobra-compatible completion directives (subset), emitted as `:<bits>` on the
/// final output line so the shell scripts can act on them.
pub mod directive {
    /// Let the shell fall back to its default (file) completion.
    pub const DEFAULT: u32 = 0;
    /// Don't add a space after a single match.
    pub const NO_SPACE: u32 = 1 << 1; // 2
    /// Don't fall back to file completion (we returned the full candidate set).
    pub const NO_FILE: u32 = 1 << 2; // 4
    /// Complete directory names.
    pub const FILTER_DIRS: u32 = 1 << 4; // 16
}

/// Candidates for the next position plus the directive controlling file/dir
/// fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Completion {
    pub candidates: Vec<Candidate>,
    pub directive: u32,
}

fn cand(value: impl Into<String>, description: Option<String>) -> Candidate {
    Candidate {
        value: value.into(),
        description,
    }
}

fn finalize(mut candidates: Vec<Candidate>, directive: u32) -> Completion {
    candidates.retain(|c| !c.value.is_empty());
    candidates.sort_by(|a, b| a.value.cmp(&b.value));
    candidates.dedup_by(|a, b| a.value == b.value);
    Completion {
        candidates,
        directive,
    }
}

/// Top-level entry: candidates for the position after `completed` (the words
/// typed after `gs`, excluding the partial at the cursor). `system` is the front
/// door's own `(name, summary, subcommands)`.
pub fn complete(
    reg: &Registry,
    system: &[(&str, &str, &[&str])],
    completed: &[String],
    locale: &str,
) -> Completion {
    match completed {
        [] => {
            let mut v: Vec<Candidate> = system
                .iter()
                .map(|(c, d, _)| cand(*c, (!d.is_empty()).then(|| (*d).to_string())))
                .collect();
            v.extend(
                reg.enabled()
                    .map(|p| cand(&p.manifest.name, pick(&p.manifest.description, locale))),
            );
            finalize(v, directive::NO_FILE)
        }
        [head, rest @ ..] => {
            // A front-door command with (shallow) subcommands.
            if let Some((_, _, subs)) = system.iter().find(|(c, _, _)| c == head) {
                if rest.is_empty() {
                    let v = subs
                        .iter()
                        .map(|s| cand(*s, Some(format!("{} 子命令", s))))
                        .collect();
                    return finalize(v, directive::NO_FILE);
                }
                return finalize(vec![], directive::NO_FILE);
            }
            // A plugin.toml plugin.
            if let Some(p) = reg.enabled().find(|p| p.manifest.name == *head) {
                return complete_in_plugin(p, rest, locale);
            }
            finalize(vec![], directive::NO_FILE)
        }
    }
}

/// Completion once a known plugin is the first token: choose a command, or
/// complete a chosen command's arguments.
fn complete_in_plugin(p: &LoadedManifest, rest: &[String], locale: &str) -> Completion {
    let cmds = p.commands(locale);
    if rest.is_empty() {
        return finalize(
            namespace_candidates(p, &cmds, &[], locale),
            directive::NO_FILE,
        );
    }

    // Resolve dotted commands typed either as one token (`prompt.set`) or as
    // multiple shell words (`prompt set`). Longest match wins, mirroring
    // dispatch_manifest in the front door.
    if let Some((cmd, consumed)) = (1..=rest.len()).rev().find_map(|take| {
        let joined = rest[..take].join(".");
        cmds.iter()
            .find(|c| !c.hidden && c.name == joined)
            .map(|c| (c, take))
    }) {
        return resolve_args(p, cmd, &rest[consumed..], locale);
    }

    let cands = namespace_candidates(p, &cmds, rest, locale);
    if !cands.is_empty() {
        return finalize(cands, directive::NO_FILE);
    }
    finalize(command_candidates(&cmds, locale), directive::NO_FILE)
}

/// Candidates one namespace level below `prefix`. At the plugin root this
/// turns `prompt.set`/`prompt.current` into one `prompt` group; after
/// `gs system prompt` it offers `set`/`current`/`themes`.
fn namespace_candidates(
    plugin: &LoadedManifest,
    cmds: &[CommandSpec],
    prefix: &[String],
    locale: &str,
) -> Vec<Candidate> {
    let prefix = if prefix.is_empty() {
        String::new()
    } else {
        format!("{}.", prefix.join("."))
    };
    cmds.iter()
        .filter(|c| !c.hidden && c.name.starts_with(&prefix))
        .filter_map(|c| {
            let remaining = &c.name[prefix.len()..];
            let next = remaining.split('.').next()?;
            let group_path = if prefix.is_empty() {
                next.to_string()
            } else {
                format!("{}.{}", prefix.trim_end_matches('.'), next)
            };
            let description = if remaining.contains('.') {
                plugin
                    .manifest
                    .groups
                    .get(&group_path)
                    .and_then(|text| pick(text, locale))
                    .or_else(|| Some(format!("{} 命令组", next)))
            } else {
                pick(&c.summary, locale)
            };
            Some(cand(next, description))
        })
        .collect()
}

fn command_candidates(cmds: &[CommandSpec], locale: &str) -> Vec<Candidate> {
    cmds.iter()
        .filter(|c| !c.hidden)
        .map(|c| cand(&c.name, pick(&c.summary, locale)))
        .collect()
}

/// What the cursor is positioned to complete within a command's args.
#[derive(Debug)]
enum Plan<'a> {
    /// Completing the value of this (value-taking) flag.
    FlagValue(&'a ArgSpec),
    /// Completing the next positional (if any) — and we also offer flag names.
    PositionalOrFlags(Option<&'a ArgSpec>),
}

/// Decide what the args completion is targeting, from the completed arg tokens
/// alone (the shell supplies no partial; it filters our union by prefix).
fn plan_args<'a>(cmd: &'a CommandSpec, toks: &[String]) -> Plan<'a> {
    // A trailing value-taking flag → complete its value.
    if let Some(last) = toks.last() {
        if last.starts_with('-') {
            if let Some(a) = cmd.arg_by_flag(last) {
                if a.takes_value() {
                    return Plan::FlagValue(a);
                }
            }
        }
    }
    // Otherwise count filled positionals (skipping each value-taking flag's
    // value) and target the next one — or the trailing variadic.
    let positionals: Vec<&ArgSpec> = cmd.args.iter().filter(|a| !a.is_flag()).collect();
    let mut filled = 0usize;
    let mut i = 0usize;
    while i < toks.len() {
        if toks[i].starts_with('-') {
            if let Some(a) = cmd.arg_by_flag(&toks[i]) {
                if a.takes_value() {
                    i += 1; // its value is the next token
                }
            }
        } else {
            filled += 1;
        }
        i += 1;
    }
    let next = positionals
        .get(filled)
        .copied()
        .or_else(|| positionals.last().copied().filter(|a| a.variadic));
    Plan::PositionalOrFlags(next)
}

fn flag_candidates(cmd: &CommandSpec, locale: &str) -> Vec<Candidate> {
    cmd.args
        .iter()
        .filter(|a| a.is_flag())
        .map(|a| cand(&a.flag, pick(&a.description, locale)))
        .collect()
}

fn resolve_args(
    p: &LoadedManifest,
    cmd: &CommandSpec,
    toks: &[String],
    locale: &str,
) -> Completion {
    match plan_args(cmd, toks) {
        Plan::FlagValue(arg) => resolve_rule(p, cmd, arg, locale),
        Plan::PositionalOrFlags(maybe) => {
            let mut cands = flag_candidates(cmd, locale);
            let mut dir = directive::NO_FILE;
            if let Some(arg) = maybe {
                let r = resolve_rule(p, cmd, arg, locale);
                cands.extend(r.candidates);
                dir = combine_dir(dir, r.directive);
            }
            finalize(cands, dir)
        }
    }
}

/// Merge a positional rule's directive into the base (`NO_FILE`): a file/dir
/// rule re-enables the matching native completion alongside the offered flags.
fn combine_dir(base: u32, rule: u32) -> u32 {
    if rule & directive::FILTER_DIRS != 0 {
        directive::FILTER_DIRS
    } else if rule == directive::DEFAULT {
        directive::DEFAULT
    } else {
        base
    }
}

/// Resolve one argument's [`CompleteRule`] to candidates + a directive.
fn resolve_rule(p: &LoadedManifest, cmd: &CommandSpec, arg: &ArgSpec, locale: &str) -> Completion {
    match arg.complete.kind {
        // Unknown → let the shell do default (file) completion.
        CompleteKind::None => finalize(vec![], directive::DEFAULT),
        CompleteKind::Enum => {
            let description = pick(&arg.description, locale);
            let v = arg
                .complete
                .values
                .iter()
                .map(|s| cand(s, description.clone()))
                .collect();
            finalize(v, directive::NO_FILE)
        }
        // File pattern filtering is deferred; plain native file completion.
        CompleteKind::File => finalize(vec![], directive::DEFAULT),
        CompleteKind::Dir => finalize(vec![], directive::FILTER_DIRS),
        CompleteKind::Dynamic => dynamic_rule(p, cmd, arg, locale),
    }
}

/// Tab-time dynamic completion: T1 runs `complete.command` directly (gated by
/// the `exec` allowlist); T2+ calls the plugin's `complete` over RPC with the
/// arg's `source`. Both are bounded by [`rpc::complete_timeout`]; T2+ results
/// are served from / written to the disk TTL cache ([`crate::cache`]). Any
/// failure or timeout path yields no candidates — never a broken or frozen Tab.
fn dynamic_rule(p: &LoadedManifest, cmd: &CommandSpec, arg: &ArgSpec, locale: &str) -> Completion {
    if p.manifest.tier == Tier::Declarative {
        let line = arg.complete.command.trim();
        if line.is_empty() || caps::check_exec_line(p.capabilities(), line).is_err() {
            return finalize(vec![], directive::NO_FILE);
        }
        // Exec form (no shell): matches the doc's "exec" semantics and avoids
        // shell-metacharacter hazards — e.g. git's `--format=%(refname:short)`
        // is one literal argv token here, but a syntax error under `sh -c`.
        let argv: Vec<String> = line.split_whitespace().map(String::from).collect();
        let Some((prog, rest)) = argv.split_first() else {
            return finalize(vec![], directive::NO_FILE);
        };
        // Bound the external command so a slow/hung `command` can't freeze Tab.
        let (prog, rest, dir) = (prog.clone(), rest.to_vec(), p.dir.clone());
        let out = rpc::with_timeout(rpc::complete_timeout(), move || {
            Command::new(&prog)
                .args(&rest)
                .current_dir(&dir)
                .stderr(Stdio::null())
                .output()
        });
        let cands = match out {
            Some(Ok(o)) if o.status.success() => String::from_utf8_lossy(&o.stdout)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .filter_map(|l| {
                    let mut value = filter_candidate(arg.complete.filter.trim(), l)?;
                    value.description = pick(&arg.description, locale);
                    Some(value)
                })
                .collect(),
            _ => vec![],
        };
        finalize(cands, directive::NO_FILE)
    } else {
        let plugin = &p.manifest.name;
        let key = cache::complete_key(&cmd.name, &arg.name, &arg.complete.source, locale);
        // Serve a fresh cached set without spawning anything.
        if let Some(values) = cache::read_complete(plugin, &key) {
            return finalize(values, directive::NO_FILE);
        }
        let Some((prog, args)) = p.spawn() else {
            return finalize(vec![], directive::NO_FILE);
        };
        let all_env: std::collections::BTreeMap<String, String> = std::env::vars().collect();
        let env = caps::filter_env(p.capabilities(), &all_env);
        let params = serde_json::json!({
            "command": cmd.name,
            "arg": arg.name,
            "source": arg.complete.source,
            "current": "",
            "args": {},
            "cwd": p.dir.to_string_lossy(),
            "locale": locale,
            "env": env,
        });
        let req = rpc::request(1, "complete", params);
        let dir = p.dir.clone();
        let exchange = rpc::with_timeout(rpc::complete_timeout(), move || {
            rpc::call_oneshot(&prog, &args, Some(&dir), &[req], true)
        });
        let (cands, ttl): (Vec<Candidate>, Option<u64>) = match exchange {
            Some(Ok(ex)) => ex
                .result_for(1)
                .map(|r| {
                    let (vals, ttl) = rpc::parse_complete(r);
                    (
                        vals.into_iter()
                            .map(|v| {
                                cand(
                                    v.value,
                                    v.description.or_else(|| pick(&arg.description, locale)),
                                )
                            })
                            .collect(),
                        ttl,
                    )
                })
                .unwrap_or((vec![], None)),
            _ => (vec![], None),
        };
        // Honor the plugin's TTL (§3.2): cache only when it asked us to.
        if let Some(ttl) = ttl {
            cache::write_complete(plugin, &key, &cands, ttl);
        }
        finalize(cands, directive::NO_FILE)
    }
}

fn filter_candidate(pattern: &str, line: &str) -> Option<Candidate> {
    if pattern.is_empty() {
        return Some(cand(line, None));
    }
    let re = regex::Regex::new(pattern).ok()?;
    let value = re
        .captures(line)
        .and_then(|caps| caps.get(1).or_else(|| caps.get(0)))?
        .as_str();
    Some(cand(value, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::PluginManifest;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn manifest(toml: &str, dir: &str) -> LoadedManifest {
        LoadedManifest {
            manifest: PluginManifest::parse(toml).unwrap(),
            dir: PathBuf::from(dir),
        }
    }

    const SYSTEM: &[(&str, &str, &[&str])] = &[("version", "显示版本号", &[])];

    fn gitx() -> LoadedManifest {
        manifest(
            r#"name="gitx"
               tier="declarative"
               description={en="Git shortcuts"}
               [capabilities]
               exec=["git","printf"]
               [[commands]]
               name="co"
               summary={en="Checkout"}
               run="git checkout {branch}"
                 [[commands.args]]
                 name="branch"
                 required=true
                 [commands.args.complete]
                 kind="dynamic"
                 command="printf 'main\ndev\nrelease\n'"
               [[commands]]
               name="open"
               summary={en="Open dir"}
               run="code {dir}"
                 [[commands.args]]
                 name="dir"
                 type="path"
                 [commands.args.complete]
                 kind="dir"
               [[commands]]
               name="log"
               run="git log --level {level}"
                 [[commands.args]]
                 name="level"
                 flag="--level"
                 type="enum"
                 [commands.args.complete]
                 kind="enum"
                 values=["oneline","full","short"]
                 [[commands.args]]
                 name="verbose"
                 flag="--verbose"
                 type="bool""#,
            ".",
        )
    }

    fn registry(plugins: Vec<LoadedManifest>) -> Registry {
        Registry { plugins }
    }

    #[test]
    fn top_level_merges_system_and_enabled_plugins() {
        let reg = registry(vec![gitx()]);
        let c = complete(&reg, SYSTEM, &[], "en");
        let vals: Vec<&str> = c.candidates.iter().map(|c| c.value.as_str()).collect();
        assert!(vals.contains(&"version"));
        assert!(vals.contains(&"gitx"));
        assert_eq!(c.directive, directive::NO_FILE);
        // descriptions flow through
        let gv = c.candidates.iter().find(|c| c.value == "gitx").unwrap();
        assert_eq!(gv.description.as_deref(), Some("Git shortcuts"));
    }

    #[test]
    fn lists_plugin_commands() {
        let reg = registry(vec![gitx()]);
        let c = complete(&reg, SYSTEM, &["gitx".into()], "en");
        let vals: Vec<&str> = c.candidates.iter().map(|c| c.value.as_str()).collect();
        assert_eq!(vals, vec!["co", "log", "open"]);
        assert_eq!(
            c.candidates
                .iter()
                .find(|c| c.value == "co")
                .unwrap()
                .description
                .as_deref(),
            Some("Checkout")
        );
    }

    #[test]
    fn dotted_commands_complete_as_space_namespaces() {
        let reg = registry(vec![manifest(
            r#"name="system"
               tier="declarative"
               [[commands]]
               name="prompt.set"
               summary={en="Set theme"}
               run="echo set"
               [[commands]]
               name="prompt.current"
               summary={en="Current theme"}
               run="echo current""#,
            ".",
        )]);
        let root = complete(&reg, SYSTEM, &["system".into()], "en");
        let root_values: Vec<&str> = root.candidates.iter().map(|c| c.value.as_str()).collect();
        assert_eq!(root_values, vec!["prompt"]);
        let group = complete(&reg, SYSTEM, &["system".into(), "prompt".into()], "en");
        let group_values: Vec<&str> = group.candidates.iter().map(|c| c.value.as_str()).collect();
        assert_eq!(group_values, vec!["current", "set"]);
    }

    #[test]
    fn enum_flag_value_completion() {
        let reg = registry(vec![gitx()]);
        // `gs gitx log --level <Tab>` → enum values, NoFileComp
        let c = complete(
            &reg,
            SYSTEM,
            &["gitx".into(), "log".into(), "--level".into()],
            "en",
        );
        let vals: Vec<&str> = c.candidates.iter().map(|c| c.value.as_str()).collect();
        assert_eq!(vals, vec!["full", "oneline", "short"]);
        assert_eq!(c.directive, directive::NO_FILE);
    }

    #[test]
    fn bool_flag_takes_no_value_offers_flags_next() {
        let reg = registry(vec![gitx()]);
        // after a boolean flag, we're not completing its value → offer flags
        let c = complete(
            &reg,
            SYSTEM,
            &["gitx".into(), "log".into(), "--verbose".into()],
            "en",
        );
        let vals: Vec<&str> = c.candidates.iter().map(|c| c.value.as_str()).collect();
        assert!(vals.contains(&"--level"));
        assert!(vals.contains(&"--verbose"));
    }

    #[test]
    fn dir_positional_sets_filter_dirs_directive() {
        let reg = registry(vec![gitx()]);
        // `gs gitx open <Tab>` → directory completion (open has one positional, a dir)
        let c = complete(&reg, SYSTEM, &["gitx".into(), "open".into()], "en");
        assert_eq!(c.directive, directive::FILTER_DIRS);
    }

    #[cfg(unix)]
    #[test]
    fn t1_dynamic_runs_command_under_capability() {
        use std::os::unix::fs::PermissionsExt;
        let _g = crate::cache::test_isolate("engine-t1");
        // exec-form runs the `command` without a shell, so use a real executable
        // (one argv token) that prints three "branches".
        let root = std::env::temp_dir().join("gs-engine-t1");
        let _ = fs::remove_dir_all(&root);
        let dir = root.join("gitish");
        fs::create_dir_all(&dir).unwrap();
        let script = dir.join("branches.sh");
        fs::write(&script, "#!/bin/sh\nprintf 'main\\ndev\\nrelease\\n'\n").unwrap();
        fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(
            dir.join("plugin.toml"),
            format!(
                r#"name="gitish"
                   tier="declarative"
                   [capabilities]
                   exec=["branches.sh"]
                   [[commands]]
                   name="co"
                   run="git checkout {{b}}"
                     [[commands.args]]
                     name="b"
                     [commands.args.complete]
                     kind="dynamic"
                     command="{}""#,
                script.display()
            ),
        )
        .unwrap();
        let reg = Registry::discover(std::slice::from_ref(&root));
        let c = complete(&reg, SYSTEM, &["gitish".into(), "co".into()], "en");
        let vals: Vec<&str> = c.candidates.iter().map(|c| c.value.as_str()).collect();
        assert_eq!(vals, vec!["dev", "main", "release"]);
        assert_eq!(c.directive, directive::NO_FILE);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn t1_dynamic_filter_extracts_first_capture() {
        assert_eq!(
            filter_candidate("^item:(.+)$", "item:alpha").unwrap().value,
            "alpha"
        );
        assert!(filter_candidate("^item:(.+)$", "other").is_none());
        assert_eq!(filter_candidate("", "raw").unwrap().value, "raw");
    }

    #[test]
    fn t1_dynamic_denied_when_command_not_in_exec_allowlist() {
        // same as gitx but `co.branch.command` uses a program outside `exec`
        let p = manifest(
            r#"name="x"
               tier="declarative"
               [capabilities]
               exec=["git"]
               [[commands]]
               name="co"
               run="git checkout {b}"
                 [[commands.args]]
                 name="b"
                 [commands.args.complete]
                 kind="dynamic"
                 command="rm -rf /tmp/should-not-run""#,
            "/tmp",
        );
        let reg = registry(vec![p]);
        let c = complete(&reg, SYSTEM, &["x".into(), "co".into()], "en");
        assert!(
            c.candidates.is_empty(),
            "denied command yields no candidates"
        );
    }

    #[test]
    fn plan_args_targets_positional_then_flag_value() {
        let g = gitx();
        let co = g.manifest.commands.iter().find(|c| c.name == "co").unwrap();
        // no tokens → first positional (branch)
        match plan_args(co, &[]) {
            Plan::PositionalOrFlags(Some(a)) => assert_eq!(a.name, "branch"),
            other => panic!("expected branch positional, got {other:?}"),
        }
        let log = g
            .manifest
            .commands
            .iter()
            .find(|c| c.name == "log")
            .unwrap();
        // trailing value-taking flag → its value
        match plan_args(log, &["--level".into()]) {
            Plan::FlagValue(a) => assert_eq!(a.name, "level"),
            other => panic!("expected level flag value, got {other:?}"),
        }
        // after a bool flag → no positional left, offer flags
        match plan_args(log, &["--verbose".into()]) {
            Plan::PositionalOrFlags(None) => {}
            other => panic!("expected no positional, got {other:?}"),
        }
    }

    // T2 dynamic complete via a `sh` mock plugin that answers a `complete`
    // request with framed values (no Python needed).
    #[cfg(unix)]
    #[test]
    fn t2_dynamic_calls_plugin_complete_over_rpc() {
        let _g = crate::cache::test_isolate("engine-t2");
        let root = std::env::temp_dir().join("gs-engine-t2");
        let _ = fs::remove_dir_all(&root);
        let dir = root.join("mock");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("plugin.toml"),
            r#"name="mock"
               tier="script"
               runtime="sh"
               entry="plugin.sh"
               describe_cache="static"
               [[commands]]
               name="paint"
               run=""
                 [[commands.args]]
                 name="color"
                 flag="--color"
                 [commands.args.complete]
                 kind="dynamic"
                 source="colors""#,
        )
        .unwrap();
        // describe_cache="static" → commands inline (no describe spawn); only the
        // `complete` call hits the mock, which emits framed color values.
        let body = r#"{"jsonrpc":"2.0","id":1,"result":{"values":[{"value":"red","description":"warm"},{"value":"blue"}]}}"#;
        fs::write(
            dir.join("plugin.sh"),
            format!(
                "printf 'Content-Length: {}\\r\\n\\r\\n%s' '{}'\n",
                body.len(),
                body
            ),
        )
        .unwrap();

        let reg = Registry::discover(std::slice::from_ref(&root));
        let c = complete(
            &reg,
            SYSTEM,
            &["mock".into(), "paint".into(), "--color".into()],
            "en",
        );
        let vals: Vec<&str> = c.candidates.iter().map(|c| c.value.as_str()).collect();
        assert_eq!(vals, vec!["blue", "red"]);
        assert_eq!(
            c.candidates
                .iter()
                .find(|c| c.value == "red")
                .unwrap()
                .description
                .as_deref(),
            Some("warm")
        );
        let _ = fs::remove_dir_all(&root);
        let _ = Path::new("/tmp"); // keep `Path` import used on all cfgs
    }

    // A fresh, unexpired cache entry is served verbatim without spawning the
    // plugin runtime at all (here the runtime is bogus — it would yield nothing
    // if ever launched).
    #[cfg(unix)]
    #[test]
    fn t2_dynamic_served_from_cache_without_spawn() {
        let _g = crate::cache::test_isolate("engine-t2cache");
        let root = std::env::temp_dir().join("gs-engine-t2c");
        let _ = fs::remove_dir_all(&root);
        let dir = root.join("mockc");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("plugin.toml"),
            r#"name="mockc"
               tier="script"
               runtime="false"
               entry="nope"
               describe_cache="static"
               [[commands]]
               name="paint"
               run=""
                 [[commands.args]]
                 name="color"
                 flag="--color"
                 [commands.args.complete]
                 kind="dynamic"
                 source="colors""#,
        )
        .unwrap();
        let key = crate::cache::complete_key("paint", "color", "colors", "en");
        crate::cache::write_complete("mockc", &key, &[cand("cyan", None)], 60);

        let reg = Registry::discover(std::slice::from_ref(&root));
        let c = complete(
            &reg,
            SYSTEM,
            &["mockc".into(), "paint".into(), "--color".into()],
            "en",
        );
        let vals: Vec<&str> = c.candidates.iter().map(|c| c.value.as_str()).collect();
        assert_eq!(vals, vec!["cyan"], "served from cache; runtime not spawned");
        let _ = fs::remove_dir_all(&root);
    }
}
