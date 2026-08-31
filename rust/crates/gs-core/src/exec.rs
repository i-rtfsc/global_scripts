//! T1 declarative executor: bind a command's argv to its [`ArgSpec`]s and render
//! the `run` template into a concrete **argv** (exec form — no shell), gated by
//! the `exec` capability. Spec: phase0-plugin-protocol.md §1.3 (`run`), §6 #7.
//!
//! Exec-form on purpose: the template is split into argv tokens and a bare
//! `{name}` placeholder expands to the bound value(s) as *separate* argv
//! elements, so a branch named `feat/x y` stays a single argument with no shell
//! quoting hazard. Inline placeholders (`prefix-{name}`) substitute textually.
//! This module is pure (bind + render + capability check); the `gs` binary does
//! the actual spawn.

use crate::caps::{self, Denied};
use crate::manifest::{ArgSpec, Capabilities, CommandSpec};
use serde_json::Value;
use std::collections::BTreeMap;

/// Bound argument values: arg name → one-or-more values (flags & positionals).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Bound {
    pub values: BTreeMap<String, Vec<String>>,
}

/// Parse raw argv (the tokens after `gs <plugin> <command>`) against `cmd`'s
/// args: `--flag value` (or a bare `--flag` for a bool) binds that arg; `--`
/// ends option parsing; other tokens fill positionals in order, with a trailing
/// variadic soaking up extras. Applies defaults, then checks required args.
pub fn bind(cmd: &CommandSpec, argv: &[String]) -> Result<Bound, String> {
    let mut b = Bound::default();
    let positionals: Vec<&ArgSpec> = cmd.args.iter().filter(|a| !a.is_flag()).collect();
    let mut pos_i = 0usize;
    let mut no_more_flags = false;
    let mut i = 0usize;
    while i < argv.len() {
        let tok = &argv[i];
        if !no_more_flags && tok == "--" {
            no_more_flags = true;
            i += 1;
            continue;
        }
        if !no_more_flags && tok.starts_with('-') && tok.len() > 1 {
            let Some(arg) = cmd.arg_by_flag(tok) else {
                // A trailing variadic positional is commonly used for safe
                // pass-through options (for example grep's `-i`, `-A 2`).
                // Preserve those tokens instead of treating them as core
                // flags; commands without a variadic declaration still fail
                // closed as before.
                if let Some(variadic) = positionals.last().copied().filter(|a| a.variadic) {
                    b.values
                        .entry(variadic.name.clone())
                        .or_default()
                        .push(tok.clone());
                    i += 1;
                    continue;
                }
                return Err(format!("未知选项 '{tok}'"));
            };
            if arg.takes_value() {
                i += 1;
                let Some(val) = argv.get(i) else {
                    return Err(format!("选项 '{tok}' 需要一个值"));
                };
                b.values
                    .entry(arg.name.clone())
                    .or_default()
                    .push(val.clone());
            } else {
                b.values
                    .entry(arg.name.clone())
                    .or_default()
                    .push("true".into());
            }
        } else {
            // Positional: the next unfilled one, else the trailing variadic.
            let target = positionals
                .get(pos_i)
                .copied()
                .or_else(|| positionals.last().copied().filter(|a| a.variadic));
            match target {
                Some(arg) => {
                    b.values
                        .entry(arg.name.clone())
                        .or_default()
                        .push(tok.clone());
                    if !arg.variadic {
                        pos_i += 1;
                    }
                }
                None => return Err(format!("多余的参数 '{tok}'")),
            }
        }
        i += 1;
    }
    // Defaults for anything still unbound.
    for arg in &cmd.args {
        if !b.values.contains_key(&arg.name) {
            if let Some(s) = arg.default.as_ref().and_then(json_scalar) {
                b.values.insert(arg.name.clone(), vec![s]);
            }
        }
    }
    // Required-arg check.
    for arg in &cmd.args {
        if arg.required && !b.values.contains_key(&arg.name) {
            return Err(format!("缺少必填参数 '{}'", arg.name));
        }
    }
    Ok(b)
}

/// Render `cmd.run` into a concrete argv from `bound`. A bare `{name}` token
/// expands to the value(s) as separate argv elements; an inline `{name}`
/// substitutes textually (multiple values space-joined). An unbound optional
/// placeholder contributes nothing.
pub fn render(cmd: &CommandSpec, bound: &Bound) -> Result<Vec<String>, String> {
    if cmd.run.trim().is_empty() {
        return Err(format!("命令 '{}' 无 run 模板", cmd.name));
    }
    let mut argv: Vec<String> = Vec::new();
    for tok in cmd.run.split_whitespace() {
        if let Some(name) = bare_placeholder(tok) {
            if let Some(vals) = bound.values.get(name) {
                argv.extend(vals.iter().cloned());
            }
        } else if tok.contains('{') {
            let mut s = tok.to_string();
            for (name, vals) in &bound.values {
                s = s.replace(&format!("{{{name}}}"), &vals.join(" "));
            }
            argv.push(s);
        } else {
            argv.push(tok.to_string());
        }
    }
    if argv.is_empty() {
        return Err(format!("命令 '{}' 渲染后为空", cmd.name));
    }
    Ok(argv)
}

/// Render `cmd.run` as a single shell line (`shell = true`). Placeholders are
/// substituted textually, but each bound value is single-quote-escaped so a
/// value can never break out of the command. An arg-free command renders `run`
/// verbatim — the common case for migrated legacy commands.
pub fn render_shell(cmd: &CommandSpec, bound: &Bound) -> Result<String, String> {
    if cmd.run.trim().is_empty() {
        return Err(format!("命令 '{}' 无 run 模板", cmd.name));
    }
    let mut line = cmd.run.clone();
    for (name, vals) in &bound.values {
        let joined = vals
            .iter()
            .map(|v| shell_quote(v))
            .collect::<Vec<_>>()
            .join(" ");
        line = line.replace(&format!("{{{name}}}"), &joined);
    }
    Ok(line)
}

/// POSIX single-quote escaping: wrap in `'…'`, rewriting any embedded `'` as
/// `'\''`. Safe to interpolate into a `sh -c` line.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The argv that runs `line` through the platform shell.
fn shell_argv(line: String) -> Vec<String> {
    if cfg!(windows) {
        vec!["cmd".into(), "/C".into(), line]
    } else {
        vec!["sh".into(), "-c".into(), line]
    }
}

/// Render a `cd` target: substitute `{arg}` placeholders (textually, multiple
/// values space-joined) into `cmd.cd`. Env-var / `~` expansion is left to
/// [`expand_path`] (it needs the live environment). Errors if there's no `cd`.
pub fn render_cd(cmd: &CommandSpec, bound: &Bound) -> Result<String, String> {
    if cmd.cd.trim().is_empty() {
        return Err(format!("命令 '{}' 无 cd 目标", cmd.name));
    }
    let mut path = cmd.cd.clone();
    for (name, vals) in &bound.values {
        path = path.replace(&format!("{{{name}}}"), &vals.join(" "));
    }
    Ok(path)
}

/// Expand a leading `~`, plus `$VAR` and `${VAR}`, using `lookup` (typically the
/// process environment). A `~` only expands at the start; an unknown variable
/// expands to empty. Pure so it can be unit-tested without touching real env.
pub fn expand_path(s: &str, lookup: impl Fn(&str) -> Option<String>) -> String {
    let mut s = s.to_string();
    if s == "~" || s.starts_with("~/") {
        if let Some(home) = lookup("HOME") {
            s = format!("{home}{}", &s[1..]);
        }
    }
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            out.push(bytes[i] as char);
            i += 1;
            continue;
        }
        // `${name}` or `$name` (name = [A-Za-z0-9_]); a bare `$` stays literal.
        let (name, next) = if i + 1 < bytes.len() && bytes[i + 1] == b'{' {
            match s[i + 2..].find('}') {
                Some(end) => (&s[i + 2..i + 2 + end], i + 2 + end + 1),
                None => {
                    out.push('$');
                    i += 1;
                    continue;
                }
            }
        } else {
            let start = i + 1;
            let mut j = start;
            while j < bytes.len() && (bytes[j].is_ascii_alphanumeric() || bytes[j] == b'_') {
                j += 1;
            }
            (&s[start..j], j)
        };
        if name.is_empty() {
            out.push('$');
            i += 1;
        } else {
            out.push_str(&lookup(name).unwrap_or_default());
            i = next;
        }
    }
    out
}

/// Full T1 plan: bind → render → capability-check. Exec form gates the rendered
/// `argv[0]`; shell form (`shell = true`) wraps the line in `sh -c` / `cmd /C`
/// and gates the line's first word (the program), not the shell itself. Returns
/// the argv to exec, or a friendly error (missing arg, denied program, …).
pub fn plan_exec(
    caps: &Capabilities,
    cmd: &CommandSpec,
    argv: &[String],
) -> Result<Vec<String>, String> {
    let bound = bind(cmd, argv)?;
    if cmd.shell {
        let line = render_shell(cmd, &bound)?;
        caps::check_exec_line(caps, &line).map_err(|d| d.to_string())?;
        return Ok(shell_argv(line));
    }
    let rendered = render(cmd, &bound)?;
    if !caps::allows_exec(caps, &rendered[0]) {
        return Err(Denied::Exec(rendered[0].clone()).to_string());
    }
    Ok(rendered)
}

/// `"{name}"` → `Some("name")` (a whole-token placeholder, no nested braces).
fn bare_placeholder(tok: &str) -> Option<&str> {
    let inner = tok.strip_prefix('{')?.strip_suffix('}')?;
    (!inner.is_empty() && !inner.contains(['{', '}'])).then_some(inner)
}

/// A JSON scalar default rendered as a string (string/number/bool); structured
/// defaults are ignored.
fn json_scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::PluginManifest;

    fn cmd(name: &str, toml: &str) -> CommandSpec {
        let m = PluginManifest::parse(toml).unwrap();
        m.commands.into_iter().find(|c| c.name == name).unwrap()
    }

    const GITX: &str = r#"name="gitx"
        tier="declarative"
        [capabilities]
        exec=["git","code"]
        [[commands]]
        name="co"
        run="git checkout {branch}"
          [[commands.args]]
          name="branch"
          required=true
        [[commands]]
        name="log"
        run="git log {level}"
          [[commands.args]]
          name="level"
          flag="--level"
          type="enum"
          default="oneline"
        [[commands]]
        name="add"
        run="git add {files}"
          [[commands.args]]
          name="files"
          variadic=true"#;

    #[test]
    fn binds_and_renders_positional() {
        let co = cmd("co", GITX);
        let b = bind(&co, &["main".into()]).unwrap();
        assert_eq!(b.values["branch"], vec!["main"]);
        assert_eq!(render(&co, &b).unwrap(), vec!["git", "checkout", "main"]);
    }

    #[test]
    fn flag_value_and_default() {
        let log = cmd("log", GITX);
        // explicit flag value
        let b = bind(&log, &["--level".into(), "full".into()]).unwrap();
        assert_eq!(render(&log, &b).unwrap(), vec!["git", "log", "full"]);
        // default applied when omitted
        let b2 = bind(&log, &[]).unwrap();
        assert_eq!(render(&log, &b2).unwrap(), vec!["git", "log", "oneline"]);
    }

    #[test]
    fn variadic_positional_expands_to_separate_argv() {
        let add = cmd("add", GITX);
        let b = bind(&add, &["a.rs".into(), "b.rs".into(), "c.rs".into()]).unwrap();
        assert_eq!(
            render(&add, &b).unwrap(),
            vec!["git", "add", "a.rs", "b.rs", "c.rs"]
        );
    }

    #[test]
    fn trailing_variadic_accepts_option_like_tokens() {
        let add = cmd("add", GITX);
        let b = bind(
            &add,
            &["file.rs".into(), "-A".into(), "2".into(), "-i".into()],
        )
        .unwrap();
        assert_eq!(b.values["files"], vec!["file.rs", "-A", "2", "-i"]);
    }

    #[test]
    fn missing_required_and_unknown_flag_error() {
        let co = cmd("co", GITX);
        assert!(bind(&co, &[]).unwrap_err().contains("branch"));
        let log = cmd("log", GITX);
        assert!(bind(&log, &["--nope".into()])
            .unwrap_err()
            .contains("--nope"));
        assert!(bind(&log, &["--level".into()]).unwrap_err().contains("值"));
    }

    #[test]
    fn double_dash_ends_option_parsing() {
        // a value that looks like a flag, passed positionally after `--`
        let add = cmd("add", GITX);
        let b = bind(&add, &["--".into(), "--weird-filename".into()]).unwrap();
        assert_eq!(b.values["files"], vec!["--weird-filename"]);
    }

    #[test]
    fn inline_placeholder_substitutes_textually() {
        let c = cmd(
            "tag",
            r#"name="x"
               tier="declarative"
               [[commands]]
               name="tag"
               run="git tag v{ver}"
                 [[commands.args]]
                 name="ver"
                 required=true"#,
        );
        let b = bind(&c, &["1.2".into()]).unwrap();
        assert_eq!(render(&c, &b).unwrap(), vec!["git", "tag", "v1.2"]);
    }

    #[test]
    fn plan_exec_enforces_exec_capability() {
        let caps = PluginManifest::parse(GITX).unwrap().capabilities;
        let co = cmd("co", GITX);
        // git is allowed
        assert_eq!(
            plan_exec(&caps, &co, &["main".into()]).unwrap(),
            vec!["git", "checkout", "main"]
        );
        // a command rendering to a non-allowlisted program is denied
        let evil = cmd(
            "evil",
            r#"name="x"
               tier="declarative"
               [capabilities]
               exec=["git"]
               [[commands]]
               name="evil"
               run="rm {path}"
                 [[commands.args]]
                 name="path"
                 required=true"#,
        );
        let caps2 = PluginManifest::parse(
            r#"name="x"
               tier="declarative"
               [capabilities]
               exec=["git"]"#,
        )
        .unwrap()
        .capabilities;
        let e = plan_exec(&caps2, &evil, &["/tmp/x".into()]).unwrap_err();
        assert!(e.contains("rm"), "denied program surfaced: {e}");
    }

    const SH: &str = r#"name="x"
        tier="declarative"
        [capabilities]
        exec=["echo"]
        [[commands]]
        name="info"
        shell=true
        run="echo 'hi there' | cat"
        [[commands]]
        name="greet"
        shell=true
        run="echo {msg}"
          [[commands.args]]
          name="msg"
          required=true"#;

    #[test]
    fn shell_mode_wraps_in_shell_and_gates_first_word() {
        let caps = PluginManifest::parse(SH).unwrap().capabilities;
        let info = cmd("info", SH);
        let plan = plan_exec(&caps, &info, &[]).unwrap();
        assert_eq!(plan.len(), 3, "shell wrapper: <shell> -c/C <line>");
        assert_eq!(plan[0], if cfg!(windows) { "cmd" } else { "sh" });
        assert_eq!(plan[2], "echo 'hi there' | cat", "pipe/quotes preserved");

        // The line's first word is gated, not the shell binary.
        let denied = PluginManifest::parse(
            r#"name="x"
               tier="declarative"
               [capabilities]
               exec=["git"]
               [[commands]]
               name="info"
               shell=true
               run="echo nope""#,
        )
        .unwrap()
        .capabilities;
        let e = plan_exec(&denied, &info, &[]).unwrap_err();
        assert!(
            e.contains("echo"),
            "inner program gated, not the shell: {e}"
        );
    }

    #[test]
    fn render_shell_substitutes_and_quotes_values() {
        let greet = cmd("greet", SH);
        let b = bind(&greet, &["a b; rm -rf /".into()]).unwrap();
        // The value is single-quote-escaped, so the `;` can't start a new command.
        assert_eq!(render_shell(&greet, &b).unwrap(), "echo 'a b; rm -rf /'");
    }

    #[test]
    fn expand_path_handles_tilde_and_vars() {
        let env = |k: &str| match k {
            "HOME" => Some("/Users/solo".to_string()),
            "CODE" => Some("/Users/solo/code".to_string()),
            _ => None,
        };
        assert_eq!(expand_path("~/code", env), "/Users/solo/code");
        assert_eq!(expand_path("$HOME/x", env), "/Users/solo/x");
        assert_eq!(expand_path("${CODE}/aosp", env), "/Users/solo/code/aosp");
        // unknown var → empty; a bare `$` and mid-string `~` stay literal.
        assert_eq!(expand_path("$NOPE/a", env), "/a");
        assert_eq!(expand_path("a~b$", env), "a~b$");
    }

    #[test]
    fn render_cd_substitutes_placeholders() {
        let c = cmd(
            "go",
            r#"name="x"
               tier="declarative"
               [[commands]]
               name="go"
               cd="$HOME/code/{repo}"
                 [[commands.args]]
                 name="repo"
                 required=true"#,
        );
        let b = bind(&c, &["aosp".into()]).unwrap();
        assert_eq!(render_cd(&c, &b).unwrap(), "$HOME/code/aosp");
        // a command with no `cd` target errors.
        let info = cmd("info", SH);
        assert!(render_cd(&info, &Bound::default()).is_err());
    }
}
