//! Capability arbitration (§1.2 / §6.4): the least-privilege checks the core
//! runs *before* it acts on a plugin's behalf — exec a program, read/write a
//! path, open a socket, or hand over an env var. **Deny by default**: an empty
//! allowlist permits nothing. Pure functions over [`manifest::Capabilities`].
//!
//! Enforcement scope for 6.0:
//!   - **exec / env** are *enforced* — the core controls the spawn (T1 `run`,
//!     T1 dynamic `complete.command`) and the child env it builds for `invoke`.
//!   - **fs / net** are *advisory* — true sandboxing needs OS facilities
//!     (sandbox-exec / seccomp / AppContainer) and is deferred; the predicates
//!     here let the core warn and let the SDK self-restrict (caps are echoed to
//!     the plugin in `invoke`, §5.1).

use crate::manifest::{Capabilities, Net};
use std::collections::BTreeMap;

/// A denied capability request, rendered as a friendly (Chinese) message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Denied {
    Exec(String),
    Fs { mode: char, path: String },
    Net(String),
}

impl std::fmt::Display for Denied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Denied::Exec(cmd) => {
                write!(f, "命令 '{cmd}' 不在插件能力白名单 [capabilities].exec 内")
            }
            Denied::Fs { mode, path } => {
                write!(f, "路径 '{path}' 的 {mode} 访问未授权（[capabilities].fs）")
            }
            Denied::Net(host) => write!(f, "网络访问 '{host}' 未授权（[capabilities].net）"),
        }
    }
}

/// Is external command `cmd` allowed? Matches the program **basename**, so a
/// grant of `git` covers `/usr/bin/git`. `["*"]` permits anything.
pub fn allows_exec(caps: &Capabilities, cmd: &str) -> bool {
    let base = cmd.rsplit(['/', '\\']).next().unwrap_or(cmd);
    caps.exec.iter().any(|e| e == "*" || e == base || e == cmd)
}

/// Gate the first word of an exec/shell line (T1 `run` template, T1 dynamic
/// `complete.command`) against the `exec` allowlist (OQ-3: reuse `exec`).
pub fn check_exec_line(caps: &Capabilities, line: &str) -> Result<(), Denied> {
    let prog = line.split_whitespace().next().unwrap_or("");
    if allows_exec(caps, prog) {
        Ok(())
    } else {
        Err(Denied::Exec(prog.to_string()))
    }
}

/// May the plugin read env var `name`?
pub fn allows_env(caps: &Capabilities, name: &str) -> bool {
    caps.env.iter().any(|e| e == name)
}

/// The subset of `all` the plugin is allowed to see — used to build the child
/// env passed to `invoke` (the plugin only ever sees authorized variables).
pub fn filter_env(caps: &Capabilities, all: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    all.iter()
        .filter(|(k, _)| allows_env(caps, k))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Advisory: is a connection to `host:port` permitted? `false` denies all,
/// `true` allows all, a list is matched exactly (CIDR/port-range nuance is
/// deferred — see module note).
pub fn net_allows(caps: &Capabilities, hostport: &str) -> bool {
    match &caps.net {
        Net::All(b) => *b,
        Net::Hosts(list) => list.iter().any(|h| h == hostport),
    }
}

/// Parse an fs grant `"rw:$PROJECT/x"` → `("rw", "$PROJECT/x")`. `None` if the
/// mode is not `read|write|rw` or the path is empty.
pub fn parse_fs_grant(grant: &str) -> Option<(&str, &str)> {
    let (mode, path) = grant.split_once(':')?;
    (matches!(mode, "read" | "write" | "rw") && !path.is_empty()).then_some((mode, path))
}

fn mode_permits(mode: &str, want: char) -> bool {
    match want {
        'r' => mode == "read" || mode == "rw",
        'w' => mode == "write" || mode == "rw",
        _ => false,
    }
}

fn expand_vars(s: &str, vars: &BTreeMap<&str, String>) -> String {
    let mut out = s.to_string();
    for (k, v) in vars {
        out = out.replace(&format!("${k}"), v);
    }
    out
}

/// Advisory: does any fs grant permit `want` (`'r'`/`'w'`) access to `path`?
/// Grants' `$HOME`/`$PROJECT`/`$PLUGIN_DIR` are expanded via `vars` before a
/// path-prefix match (a grant on a directory covers everything beneath it).
pub fn allows_fs(
    caps: &Capabilities,
    want: char,
    path: &str,
    vars: &BTreeMap<&str, String>,
) -> bool {
    caps.fs
        .iter()
        .filter_map(|g| parse_fs_grant(g))
        .any(|(mode, gpath)| {
            mode_permits(mode, want) && {
                let base = expand_vars(gpath, vars);
                let base = base.trim_end_matches('/');
                path == base || path.starts_with(&format!("{base}/"))
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(toml: &str) -> Capabilities {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn exec_allowlist_matches_basename_and_star() {
        let c = caps(r#"exec = ["git", "adb"]"#);
        assert!(allows_exec(&c, "git"));
        assert!(allows_exec(&c, "/usr/bin/git"), "basename match");
        assert!(allows_exec(&c, "adb"));
        assert!(!allows_exec(&c, "rm"));
        // deny-by-default
        assert!(!allows_exec(&Capabilities::default(), "git"));
        // star = anything
        assert!(allows_exec(&caps(r#"exec = ["*"]"#), "anything"));
    }

    #[test]
    fn check_exec_line_gates_first_word() {
        let c = caps(r#"exec = ["git"]"#);
        assert!(check_exec_line(&c, "git checkout main").is_ok());
        let e = check_exec_line(&c, "rm -rf /").unwrap_err();
        assert_eq!(e, Denied::Exec("rm".into()));
        assert!(e.to_string().contains("rm"));
        // empty line → denied (no program)
        assert!(check_exec_line(&c, "").is_err());
    }

    #[test]
    fn env_filtering_keeps_only_whitelisted() {
        let c = caps(r#"env = ["ANDROID_HOME", "PATH"]"#);
        assert!(allows_env(&c, "ANDROID_HOME"));
        assert!(!allows_env(&c, "SECRET_TOKEN"));
        let all: BTreeMap<String, String> = [
            ("ANDROID_HOME", "/opt/sdk"),
            ("PATH", "/bin"),
            ("SECRET_TOKEN", "hunter2"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        let filtered = filter_env(&c, &all);
        assert_eq!(filtered.len(), 2);
        assert!(filtered.contains_key("ANDROID_HOME"));
        assert!(!filtered.contains_key("SECRET_TOKEN"), "secret stripped");
    }

    #[test]
    fn net_policy_false_true_list() {
        assert!(!net_allows(&caps("net = false"), "api.github.com:443"));
        assert!(net_allows(&caps("net = true"), "anything:1"));
        let c = caps(r#"net = ["api.github.com:443"]"#);
        assert!(net_allows(&c, "api.github.com:443"));
        assert!(!net_allows(&c, "evil.example:443"));
        // default deny
        assert!(!net_allows(&Capabilities::default(), "x:1"));
    }

    #[test]
    fn fs_grants_parse_and_prefix_match_with_vars() {
        assert_eq!(
            parse_fs_grant("rw:$PROJECT/app"),
            Some(("rw", "$PROJECT/app"))
        );
        assert_eq!(parse_fs_grant("read:$HOME"), Some(("read", "$HOME")));
        assert_eq!(parse_fs_grant("bogus:/x"), None);
        assert_eq!(parse_fs_grant("rw:"), None);

        let c = caps(r#"fs = ["read:$HOME/.android", "rw:$PROJECT"]"#);
        let vars: BTreeMap<&str, String> = [
            ("HOME", "/Users/solo".to_string()),
            ("PROJECT", "/work/app".to_string()),
        ]
        .into_iter()
        .collect();
        // read under $HOME/.android
        assert!(allows_fs(&c, 'r', "/Users/solo/.android/adbkey", &vars));
        // but not write there (grant is read-only)
        assert!(!allows_fs(&c, 'w', "/Users/solo/.android/adbkey", &vars));
        // rw under $PROJECT
        assert!(allows_fs(&c, 'w', "/work/app/build.gradle", &vars));
        assert!(allows_fs(&c, 'r', "/work/app", &vars), "exact dir matches");
        // outside any grant
        assert!(!allows_fs(&c, 'r', "/etc/passwd", &vars));
        // a sibling that merely shares a prefix string must NOT match
        assert!(!allows_fs(&c, 'r', "/work/app-secrets/x", &vars));
    }
}
