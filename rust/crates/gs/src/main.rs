//! `gs` — the fast front door (PoC).
//!
//! Replaces the `gs()` shell function from `env.sh`. It resolves a command
//! against `router.json` *without* jq and dispatches:
//!   - native fast paths (`version`),
//!   - `kind == "json"`  → run the command template via `sh -c`,
//!   - `kind == "shell"` → `source` the entry and call `gs_<plugin>_[<sub>_]<fn>`,
//!   - everything else   → delegate to the existing Python CLI via `uv run`.
//!
//! Caveat vs. the shell wrapper: json/shell commands run in a child shell, so
//! `cd`/`export` side effects do not persist into the caller's shell. The
//! eventual design routes those through a thin `gs` wrapper that `eval`s
//! emitted shell; out of scope for this startup-latency PoC.

use gs_core::index::{LoadedManifest, Registry};
use gs_core::manifest::CommandSpec;
use gs_core::{load_router, resolve, router_index_path, CommandEntry, Resolution};
use std::process::Command;

fn main() {
    // Behave like a normal Unix filter: a closed reader (e.g. `gs … | head`, or
    // `source <(gs completions …)`) should terminate us quietly, not panic.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(run(&args));
}

fn run(args: &[String]) -> i32 {
    // System commands. The legacy wrapper sends all of these to Python; we keep
    // `version` native (the hot path we benchmark) and delegate the rest for now.
    match args.first().map(String::as_str) {
        None | Some("") => return delegate_python(args),
        Some("version") => return cmd_version(),
        Some("event") => return cmd_event(&args[1..]),
        Some("hooks") => return cmd_hooks(&args[1..]),
        Some("__complete") => return cmd_complete(&args[1..]),
        Some("completions") => return cmd_completions(&args[1..]),
        // `plugin migrate` is handled natively (legacy → plugin.toml); the other
        // `plugin` subcommands (list/enable/disable) still delegate to Python.
        Some("plugin") if args.get(1).map(String::as_str) == Some("migrate") => {
            return cmd_plugin_migrate(&args[2..]);
        }
        Some("help" | "plugin" | "status" | "doctor" | "refresh") => return delegate_python(args),
        _ => {}
    }

    // GS 6.0 plugin.toml plugins win over the legacy router.json path. A broken
    // manifest for the named plugin is reported here (not silently delegated),
    // so `gs <plugin>` tells you *why* it didn't run.
    if let Some(name) = args.first() {
        match Registry::find_checked(&engine_roots(), name) {
            Ok(Some(p)) => return dispatch_manifest(&p, &args[1..]),
            Ok(None) => {}
            Err(msg) => {
                eprintln!("错误: 插件 '{name}' 的 plugin.toml 无效：");
                eprintln!("  {msg}");
                return 1;
            }
        }
    }

    let Some(path) = router_index_path() else {
        return delegate_python(args);
    };
    let router = match load_router(&path) {
        Ok(r) => r,
        Err(_) => return delegate_python(args), // unreadable/corrupt index → safe fallback
    };

    match resolve(&router, args) {
        Resolution::Delegate => delegate_python(args),
        Resolution::Command {
            plugin,
            consumed,
            entry,
            enabled,
        } => {
            if !enabled {
                eprintln!("错误: 插件 '{plugin}' 已被禁用");
                eprintln!("提示: 使用 'gs plugin enable {plugin}' 启用插件");
                return 1;
            }
            let rest = &args[consumed..];
            match entry.kind.as_str() {
                "json" => dispatch_json(&entry, rest),
                "shell" => dispatch_shell(&plugin, &entry, rest),
                _ => delegate_python(args),
            }
        }
    }
}

/// Print the version from `$GS_ROOT/VERSION` (falls back to `$GS_VERSION`).
fn cmd_version() -> i32 {
    if let Some(root) = std::env::var_os("GS_ROOT") {
        let p = std::path::Path::new(&root).join("VERSION");
        if let Ok(v) = std::fs::read_to_string(&p) {
            println!("{}", v.trim());
            return 0;
        }
    }
    match std::env::var("GS_VERSION") {
        Ok(v) => println!("{v}"),
        Err(_) => println!("unknown"),
    }
    0
}

/// `kind == "json"`: substitute `{args}` (or append) and run via `sh -c`.
fn dispatch_json(entry: &CommandEntry, rest: &[String]) -> i32 {
    if entry.command.is_empty() {
        eprintln!("Error: No command template defined for json type");
        return 1;
    }
    let joined = rest.join(" ");
    let cmd = if entry.command.contains("{args}") {
        entry.command.replace("{args}", &joined)
    } else if rest.is_empty() {
        entry.command.clone()
    } else {
        format!("{} {joined}", entry.command)
    };
    let mut c = Command::new("sh");
    c.arg("-c").arg(cmd);
    exec_or_status(c)
}

/// `kind == "shell"`: `source` the entry script and call its gs_* function.
fn dispatch_shell(plugin: &str, entry: &CommandEntry, rest: &[String]) -> i32 {
    let entry_path = resolve_entry_path(&entry.entry);
    let func_norm = entry.name.replace('-', "_");
    let full_func = if entry.subplugin.is_empty() {
        format!("gs_{plugin}_{func_norm}")
    } else {
        format!("gs_{plugin}_{}_{func_norm}", entry.subplugin)
    };
    // `bash -c 'source <entry> && <fn> "$@"' bash <rest…>` — "$@" starts after $0.
    let program = format!("source {} && {full_func} \"$@\"", shell_quote(&entry_path));
    let mut c = Command::new("bash");
    c.arg("-c").arg(program).arg("bash").args(rest);
    exec_or_status(c)
}

// ---- GS 6.0 plugin.toml dispatch (T1 exec / T2 invoke) ----
//
// plugin.toml plugins take precedence over the legacy router.json path. T1
// (declarative) renders its `run` template to an argv and execs it (no shell,
// capability-gated); T2 (script) speaks JSON-RPC over stdio via the one-shot
// transport. Spec: tmp/phase0-plugin-protocol.md §5 / §6 #7.

/// Plugin-discovery roots for the engine (`$GS_ROOT/{plugins,examples}`).
fn engine_roots() -> Vec<PathBuf> {
    gs_core::index::default_roots()
}

/// Dispatch `gs <plugin> <command> [args…]` for a plugin.toml plugin.
fn dispatch_manifest(p: &LoadedManifest, rest: &[String]) -> i32 {
    use gs_core::manifest::{pick, Tier};
    if !p.manifest.enabled {
        eprintln!("错误: 插件 '{}' 已被禁用", p.manifest.name);
        return 1;
    }
    let locale = detect_locale();
    let cmds = p.commands(&locale);
    if rest.is_empty() {
        eprintln!("用法: gs {} <命令> [参数…]\n可用命令:", p.manifest.name);
        for c in cmds.iter().filter(|c| !c.hidden) {
            eprintln!(
                "  {:<18} {}",
                c.name.replace('.', " "),
                pick(&c.summary, &locale).unwrap_or_default()
            );
        }
        return 2;
    }
    // Resolve a (possibly `.`-namespaced) command typed either dotted
    // (`config.show`) or space-separated (`config show`); prefer the longest
    // path so `a b c` reaches `a.b.c` before falling back to `a.b` / `a`.
    let resolved = (1..=rest.len()).rev().find_map(|take| {
        let joined = rest[..take].join(".");
        cmds.iter()
            .find(|c| !c.hidden && c.name == joined)
            .map(|c| (c, &rest[take..]))
    });
    let Some((cmd, argv)) = resolved else {
        eprintln!(
            "错误: 插件 '{}' 没有命令 '{}'",
            p.manifest.name,
            rest.join(" ")
        );
        return 1;
    };
    match p.manifest.tier {
        Tier::Declarative => exec_t1(p, cmd, argv),
        Tier::Script | Tier::Rpc => invoke_t2(p, cmd, argv, &locale),
        Tier::Wasm => {
            eprintln!("错误: T4(wasm) 插件暂未实现");
            1
        }
    }
}

/// T1: render the `run` template to an argv (capability-gated) and exec it in
/// the user's current directory.
fn exec_t1(p: &LoadedManifest, cmd: &CommandSpec, argv: &[String]) -> i32 {
    match gs_core::exec::plan_exec(&p.manifest.capabilities, cmd, argv) {
        Ok(rendered) => {
            let mut c = Command::new(&rendered[0]);
            c.args(&rendered[1..]);
            exec_or_status(c)
        }
        Err(e) => {
            eprintln!("错误: {e}");
            2
        }
    }
}

/// T2: bind args, call the plugin's `invoke` over the one-shot RPC transport,
/// replay streamed output/log events, and propagate the exit code.
///
/// Caveat: the one-shot transport reads the plugin's stdout to EOF, so streamed
/// `output` events are replayed *after* the command finishes rather than live —
/// real-time streaming is a later enhancement.
fn invoke_t2(p: &LoadedManifest, cmd: &CommandSpec, argv: &[String], locale: &str) -> i32 {
    use gs_core::{caps, exec, rpc};
    use std::io::{IsTerminal, Write};

    let bound = match exec::bind(cmd, argv) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("错误: {e}");
            return 2;
        }
    };
    // Single value → string, multiple → array (per the describe arg's shape).
    let mut args_json = serde_json::Map::new();
    for (k, v) in &bound.values {
        let val = if v.len() == 1 {
            serde_json::Value::String(v[0].clone())
        } else {
            serde_json::Value::Array(v.iter().cloned().map(serde_json::Value::String).collect())
        };
        args_json.insert(k.clone(), val);
    }
    let full_env: std::collections::BTreeMap<String, String> = std::env::vars().collect();
    let env = caps::filter_env(&p.manifest.capabilities, &full_env);
    let cwd = std::env::current_dir()
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_default();
    let params = serde_json::json!({
        "command": cmd.name,
        "args": args_json,
        "cwd": cwd,
        "env": env,
        "context": { "locale": locale, "tty": std::io::stdout().is_terminal() },
        "capabilities": {
            "exec": p.manifest.capabilities.exec,
            "env": p.manifest.capabilities.env,
        },
    });
    let Some((prog, pargs)) = p.spawn() else {
        eprintln!("错误: 无法确定插件 '{}' 的启动方式", p.manifest.name);
        return 1;
    };
    let req = rpc::request(1, "invoke", params);
    match rpc::call_oneshot(&prog, &pargs, Some(&p.dir), &[req], false) {
        Ok(ex) => {
            let mut streamed = false;
            for e in &ex.events {
                match e.get("type").and_then(|v| v.as_str()) {
                    Some("output") => {
                        streamed = true;
                        let chunk = e.get("chunk").and_then(|v| v.as_str()).unwrap_or("");
                        if e.get("stream").and_then(|v| v.as_str()) == Some("stderr") {
                            let _ = write!(std::io::stderr(), "{chunk}");
                        } else {
                            let _ = write!(std::io::stdout(), "{chunk}");
                        }
                    }
                    Some("log") => {
                        if let Some(m) = e.get("message").and_then(|v| v.as_str()) {
                            eprintln!("[{}] {m}", p.manifest.name);
                        }
                    }
                    _ => {}
                }
            }
            if let Some(result) = ex.result_for(1) {
                if !streamed {
                    if let Some(s) = result.get("stdout").and_then(|v| v.as_str()) {
                        print!("{s}");
                    }
                }
                result
                    .get("exit_code")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0) as i32
            } else if let Some(err) = ex.error_for(1) {
                eprintln!(
                    "错误: 插件 '{}' invoke 失败: {}",
                    p.manifest.name, err.message
                );
                1
            } else {
                eprintln!("错误: 插件 '{}' 未返回结果", p.manifest.name);
                1
            }
        }
        Err(e) => {
            eprintln!("错误: 启动插件 '{}' 失败: {e}", p.manifest.name);
            127
        }
    }
}

/// Hand the full argv to the existing Python CLI.
fn delegate_python(args: &[String]) -> i32 {
    let root = std::env::var("GS_ROOT").unwrap_or_else(|_| ".".to_string());
    let mut c = Command::new("uv");
    c.arg("run")
        .arg("--directory")
        .arg(root)
        .arg("python")
        .arg("-m")
        .arg("gscripts.cli.main")
        .args(args);
    exec_or_status(c)
}

/// Use the entry path as-is if it exists, else resolve it under `$GS_ROOT`.
fn resolve_entry_path(entry: &str) -> String {
    if std::path::Path::new(entry).is_file() {
        return entry.to_string();
    }
    if let Ok(root) = std::env::var("GS_ROOT") {
        let alt = std::path::Path::new(&root).join(entry);
        if alt.is_file() {
            return alt.to_string_lossy().into_owned();
        }
    }
    entry.to_string()
}

/// Single-quote a string for safe embedding in a `sh`/`bash -c` program.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Replace the current process with `cmd` (Unix) so exit status and signals
/// propagate with no extra fork/wait. Falls back to spawn+wait elsewhere.
#[cfg(unix)]
fn exec_or_status(mut cmd: Command) -> i32 {
    use std::os::unix::process::CommandExt;
    let err = cmd.exec(); // returns only on failure
    eprintln!("gs: failed to exec ({}): {err}", program_name(&cmd));
    127
}

#[cfg(not(unix))]
fn exec_or_status(mut cmd: Command) -> i32 {
    match cmd.status() {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("gs: failed to run: {e}");
            127
        }
    }
}

#[cfg(unix)]
fn program_name(cmd: &Command) -> String {
    cmd.get_program().to_string_lossy().into_owned()
}

// ---- status-light event bus (`gs event emit`) ----

/// `gs event emit <type> --source <agent> [flags]` — forward an agent-state
/// event to gsd over the control socket. Best-effort: if gsd isn't running it
/// is a silent no-op, so a hook never slows down or breaks the agent.
fn cmd_event(args: &[String]) -> i32 {
    match args.first().map(String::as_str) {
        Some("emit") => cmd_event_emit(&args[1..]),
        _ => {
            eprintln!("usage: gs event emit <type> --source <claude-code|codex> [--from-notify] [--reason R] [--session ID]");
            2
        }
    }
}

fn cmd_event_emit(args: &[String]) -> i32 {
    let (mut event, mut source, mut reason, mut session) =
        (String::new(), String::new(), String::new(), String::new());
    let mut from_notify = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--source" => {
                i += 1;
                source = args.get(i).cloned().unwrap_or_default();
            }
            "--reason" => {
                i += 1;
                reason = args.get(i).cloned().unwrap_or_default();
            }
            "--session" => {
                i += 1;
                session = args.get(i).cloned().unwrap_or_default();
            }
            "--from-notify" => from_notify = true,
            s if !s.starts_with("--") && event.is_empty() => event = s.to_string(),
            _ => {}
        }
        i += 1;
    }
    if event.is_empty() || source.is_empty() {
        eprintln!("gs event emit: need <type> and --source");
        return 2;
    }
    if session.is_empty() {
        session = extract_session(from_notify, args).unwrap_or_else(|| "default".to_string());
    }
    send_to_gsd(&gs_core::Envelope {
        source,
        event,
        session_id: session,
        reason,
    });
    0
}

/// Best-effort session id from the hook payload: stdin JSON (Claude Code /
/// Codex hooks) or argv[-1] JSON (Codex `notify`). Falls back to "default".
fn extract_session(from_notify: bool, args: &[String]) -> Option<String> {
    let payload = if from_notify {
        args.last().cloned().unwrap_or_default()
    } else {
        use std::io::{IsTerminal, Read};
        if std::io::stdin().is_terminal() {
            return None;
        }
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s).ok()?;
        s
    };
    let v: serde_json::Value = serde_json::from_str(payload.trim()).ok()?;
    for k in [
        "session_id",
        "session-id",
        "thread-id",
        "thread_id",
        "turn_id",
    ] {
        if let Some(s) = v.get(k).and_then(serde_json::Value::as_str) {
            return Some(s.to_string());
        }
    }
    None
}

#[cfg(unix)]
fn send_to_gsd(env: &gs_core::Envelope) {
    use std::io::Write;
    let path = gs_core::gsd_socket_path();
    let Ok(mut stream) = std::os::unix::net::UnixStream::connect(&path) else {
        return; // gsd not running → no-op
    };
    if let Ok(mut line) = serde_json::to_string(env) {
        line.push('\n');
        let _ = stream.write_all(line.as_bytes());
    }
}

// A named-pipe client opens like a file, so the send side needs no FFI: open
// the pipe for write, push one framed line, drop. gsd absent (file-not-found)
// or momentarily busy → silent no-op, exactly like the UDS path.
#[cfg(windows)]
fn send_to_gsd(env: &gs_core::Envelope) {
    use std::io::Write;
    let Ok(mut pipe) = std::fs::OpenOptions::new()
        .write(true)
        .open(gs_core::gsd_pipe_name())
    else {
        return; // gsd not running → no-op
    };
    if let Ok(mut line) = serde_json::to_string(env) {
        line.push('\n');
        let _ = pipe.write_all(line.as_bytes());
    }
}

#[cfg(not(any(unix, windows)))]
fn send_to_gsd(_env: &gs_core::Envelope) {}

/// Whether gsd is currently listening, for `gs hooks status`.
/// Unix: the socket file exists. Windows: opening the pipe succeeds, or fails
/// with ERROR_PIPE_BUSY (231) — both mean a server is up (just no free instance
/// this instant).
#[cfg(windows)]
fn gsd_listening() -> bool {
    match std::fs::OpenOptions::new()
        .write(true)
        .open(gs_core::gsd_pipe_name())
    {
        Ok(_) => true,
        Err(e) => e.raw_os_error() == Some(231),
    }
}

// ---- `gs plugin migrate` (legacy plugin.json → plugin.toml) ----
//
// The only `plugin` subcommand handled natively; list/enable/disable still
// delegate to Python. Reads a legacy plugin dir, runs the §1.4 transform, then
// validates the result and either prints it or writes plugin.toml in place.

fn cmd_plugin_migrate(args: &[String]) -> i32 {
    use gs_core::migrate::{self, MigrateInputs};

    let mut path: Option<&str> = None;
    let mut write = false;
    for a in args {
        match a.as_str() {
            "--write" | "-w" => write = true,
            "-h" | "--help" => {
                println!("用法: gs plugin migrate <插件目录> [--write]");
                println!("  读取旧 plugin.json(+commands.json) 生成 6.0 plugin.toml。");
                println!("  默认打印到 stdout；--write 写入 <目录>/plugin.toml（不覆盖已存在文件）。");
                return 0;
            }
            other if other.starts_with('-') => {
                eprintln!("错误: 未知选项 '{other}'");
                return 2;
            }
            other => path = Some(other),
        }
    }
    let Some(path) = path else {
        eprintln!("用法: gs plugin migrate <插件目录> [--write]");
        return 2;
    };

    // Accept either the plugin dir or its plugin.json directly.
    let given = Path::new(path);
    let (dir, manifest) = if given.file_name().map(|f| f == "plugin.json").unwrap_or(false) {
        (
            given.parent().unwrap_or(Path::new(".")).to_path_buf(),
            given.to_path_buf(),
        )
    } else {
        (given.to_path_buf(), given.join("plugin.json"))
    };

    let plugin_json = match std::fs::read_to_string(&manifest) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("错误: 读取 {} 失败：{e}", manifest.display());
            return 1;
        }
    };

    // Pull in each subplugin's commands.json (paths come from the manifest).
    let mut sub_commands = Vec::new();
    match migrate::parse_plugin_json(&plugin_json) {
        Ok(p) => {
            for sub in &p.subplugins {
                if sub.entry.is_empty() {
                    continue;
                }
                let sp = gs_core::index::resolve_under(&dir, &sub.entry);
                match std::fs::read_to_string(&sp) {
                    Ok(text) => sub_commands.push((sub.name.clone(), text)),
                    Err(_) => eprintln!(
                        "注意: 子插件 '{}' 的 {} 读取失败，已跳过",
                        sub.name,
                        sp.display()
                    ),
                }
            }
        }
        Err(e) => {
            eprintln!("错误: {e}");
            return 1;
        }
    }

    let main_commands_json = std::fs::read_to_string(dir.join("commands.json")).ok();

    let out = match migrate::migrate(&MigrateInputs {
        plugin_json,
        main_commands_json,
        sub_commands,
    }) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("错误: 迁移失败：{e}");
            return 1;
        }
    };

    // Validate before handing it over — a heads-up beats a silent dud.
    let valid = gs_core::manifest::PluginManifest::parse(&out.toml);
    for n in &out.notes {
        eprintln!("注意: {n}");
    }
    if let Err(e) = &valid {
        eprintln!("警告: 生成的 plugin.toml 未通过校验：{e}");
        eprintln!("      （仍会输出，请人工修正后再用）");
    }

    if write {
        let target = dir.join("plugin.toml");
        if target.exists() {
            eprintln!(
                "错误: {} 已存在，拒绝覆盖（手动删除后重试，或省略 --write 看输出）",
                target.display()
            );
            return 1;
        }
        if let Err(e) = std::fs::write(&target, &out.toml) {
            eprintln!("错误: 写入 {} 失败：{e}", target.display());
            return 1;
        }
        println!("已写入 {}", target.display());
        if let Ok(m) = &valid {
            println!("校验通过；运行 `gs {} <命令>` 试试。", m.name);
        }
    } else {
        print!("{}", out.toml);
    }
    if valid.is_ok() {
        0
    } else {
        1
    }
}

// ---- agent hook install/uninstall (`gs hooks …`) ----
//
// Idempotently writes (or removes) the status-light hooks in the Claude Code
// and Codex configs. The pure text transforms live in `gs_core::hooks`; here we
// resolve paths, read/write files atomically, and print guidance. Spec §10 #3.

use std::path::{Path, PathBuf};

fn cmd_hooks(args: &[String]) -> i32 {
    let rest = args.get(1..).unwrap_or_default();
    match args.first().map(String::as_str) {
        Some("install") => hooks_apply(rest, true),
        Some("uninstall") => hooks_apply(rest, false),
        Some("status") => hooks_status(rest),
        None | Some("-h" | "--help") => {
            hooks_usage();
            0
        }
        Some(other) => {
            eprintln!("gs hooks: 未知子命令 '{other}'\n");
            hooks_usage();
            2
        }
    }
}

fn hooks_usage() {
    eprintln!(
        "用法: gs hooks <install|uninstall|status> [--claude-code] [--codex] [--gs-path PATH] [--dry-run]

  把 Agent 状态灯 hooks 幂等写入 Claude Code / Codex 配置（可卸载）。
  不指定 --claude-code/--codex 时，两者都处理。

  install     安装 hooks
  uninstall   移除 hooks（仅删除本工具写入的条目，不动你的其它配置）
  status      显示当前安装状态，不修改任何文件

  --claude-code   仅处理 ~/.claude/settings.json（或 $CLAUDE_CONFIG_DIR）
  --codex         仅处理 ~/.codex/config.toml（或 $CODEX_HOME）
  --gs-path PATH  hooks 里调用的 gs 路径（默认：当前 gs 可执行文件的绝对路径；
                  传 --gs-path gs 写成依赖 PATH 的便携形式，便于多机同步）
  --dry-run, -n   只打印将写入的内容，不落盘"
    );
}

struct HooksFlags {
    claude: bool,
    codex: bool,
    gs_path: Option<String>,
    dry_run: bool,
}

fn parse_hooks_flags(args: &[String]) -> Result<HooksFlags, String> {
    let (mut claude, mut codex, mut gs_path, mut dry_run) = (false, false, None, false);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--claude-code" | "--claude" => claude = true,
            "--codex" => codex = true,
            "--all" => {
                claude = true;
                codex = true;
            }
            "--gs-path" => {
                i += 1;
                gs_path = Some(args.get(i).cloned().ok_or("--gs-path 需要一个参数")?);
            }
            "--dry-run" | "-n" => dry_run = true,
            other => return Err(format!("未知参数 '{other}'")),
        }
        i += 1;
    }
    // Default: manage both agents.
    if !claude && !codex {
        claude = true;
        codex = true;
    }
    Ok(HooksFlags {
        claude,
        codex,
        gs_path,
        dry_run,
    })
}

/// The `gs` path baked into the hook commands. Defaults to this binary's own
/// absolute path (robust against minimal hook PATHs); `--gs-path gs` opts into a
/// portable, PATH-relative form.
fn resolve_gs_path(explicit: Option<String>) -> String {
    if let Some(p) = explicit {
        return p;
    }
    std::env::current_exe()
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|| "gs".to_string())
}

fn claude_settings_path() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("CLAUDE_CONFIG_DIR") {
        return Some(PathBuf::from(dir).join("settings.json"));
    }
    gs_core::home_dir().map(|h| h.join(".claude").join("settings.json"))
}

fn codex_config_path() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("CODEX_HOME") {
        return Some(PathBuf::from(dir).join("config.toml"));
    }
    gs_core::home_dir().map(|h| h.join(".codex").join("config.toml"))
}

/// Read a config file, treating "not found" as empty (first-time install).
fn read_or_empty(path: &Path) -> std::io::Result<String> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e),
    }
}

/// Write `content` to `path` atomically (temp file + rename in the same dir),
/// creating parent dirs and preserving the original file's permissions.
fn write_atomic(path: &Path, content: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let fname = path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config".into());
    let tmp = path.with_file_name(format!(".{fname}.gs-tmp"));
    std::fs::write(&tmp, content)?;
    #[cfg(unix)]
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&tmp, meta.permissions());
    }
    std::fs::rename(&tmp, path)
}

fn hooks_apply(args: &[String], install: bool) -> i32 {
    let flags = match parse_hooks_flags(args) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("gs hooks: {e}\n");
            hooks_usage();
            return 2;
        }
    };
    let gs = resolve_gs_path(flags.gs_path.clone());
    let mut had_err = false;

    if flags.claude {
        had_err |= apply_one(
            "Claude Code",
            claude_settings_path(),
            install,
            flags.dry_run,
            |existing| gs_core::hooks::apply_claude(existing, install, &gs),
        );
    }
    if flags.codex {
        had_err |= apply_one(
            "Codex",
            codex_config_path(),
            install,
            flags.dry_run,
            |existing| Ok(gs_core::hooks::apply_codex(existing, install, &gs)),
        );
    }

    if had_err {
        return 1;
    }
    if install && !flags.dry_run {
        println!("\n下一步:");
        println!("  • 状态灯需要 gsd 守护进程在运行才会真正亮起（gsd 未实现前 'gs event emit' 静默 no-op，不影响 agent）。");
        if flags.claude {
            println!("  • Claude Code 会自动热重载 hooks，无需重启。");
        }
        if flags.codex {
            println!("  • Codex 首次运行需在 /hooks 中信任这些 hook（或用 --dangerously-bypass-hook-trust）。");
            println!("    已保留你现有的 notify=（计算机使用）；hooks 关闭时的兜底如有需要请自行添加 notify。");
        }
        if !Path::new(&gs).is_absolute() {
            println!("  • hooks 调用 '{gs}'，请确保它在各 agent 运行环境的 PATH 上。");
        }
    }
    0
}

/// Read → transform → (print | write) one agent's config. `transform` returns
/// `(new_text, changed)` or an `Err` describing why the file was left untouched.
/// Returns `true` on error.
fn apply_one(
    label: &str,
    path: Option<PathBuf>,
    install: bool,
    dry_run: bool,
    transform: impl FnOnce(&str) -> Result<(String, bool), String>,
) -> bool {
    let Some(path) = path else {
        eprintln!("gs hooks: 无法定位 {label} 配置（HOME/CLAUDE_CONFIG_DIR/CODEX_HOME 未设置）");
        return true;
    };
    let existing = match read_or_empty(&path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("gs hooks: 读取 {} 失败: {e}", path.display());
            return true;
        }
    };
    let (new, changed) = match transform(&existing) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "gs hooks: {} 解析失败，已跳过（请先修复）: {e}",
                path.display()
            );
            return true;
        }
    };
    if dry_run {
        println!("# ── {label} · {} (dry-run) ──", path.display());
        print!("{new}");
        if !new.ends_with('\n') {
            println!();
        }
        return false;
    }
    if !changed {
        println!("{label}: 无变化（{}）", path.display());
        return false;
    }
    match write_atomic(&path, &new) {
        Ok(()) => {
            println!(
                "{label}: 已{} · {}",
                if install { "安装" } else { "移除" },
                path.display()
            );
            false
        }
        Err(e) => {
            eprintln!("gs hooks: 写入 {} 失败: {e}", path.display());
            true
        }
    }
}

fn hooks_status(args: &[String]) -> i32 {
    let flags = match parse_hooks_flags(args) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("gs hooks: {e}\n");
            hooks_usage();
            return 2;
        }
    };
    if flags.claude {
        report_status(
            "Claude Code",
            claude_settings_path(),
            gs_core::hooks::claude_installed,
        );
    }
    if flags.codex {
        report_status(
            "Codex",
            codex_config_path(),
            gs_core::hooks::codex_installed,
        );
    }
    // The light only lights up when gsd is listening — surface that here.
    #[cfg(unix)]
    {
        let sock = gs_core::gsd_socket_path();
        println!(
            "gsd socket: {} · {}",
            sock.display(),
            if sock.exists() {
                "存在"
            } else {
                "不存在（状态灯当前不会亮）"
            }
        );
    }
    #[cfg(windows)]
    {
        let name = gs_core::gsd_pipe_name();
        println!(
            "gsd 管道: {} · {}",
            name,
            if gsd_listening() {
                "在线"
            } else {
                "离线（状态灯当前不会亮）"
            }
        );
    }
    0
}

fn report_status(label: &str, path: Option<PathBuf>, installed: impl Fn(&str) -> bool) {
    let Some(path) = path else {
        println!("{label}: 无法定位配置文件");
        return;
    };
    match read_or_empty(&path) {
        Ok(s) if s.is_empty() && !path.exists() => {
            println!("{label}: 未安装（{} 不存在）", path.display())
        }
        Ok(s) => println!(
            "{label}: {} · {}",
            if installed(&s) {
                "已安装"
            } else {
                "未安装"
            },
            path.display()
        ),
        Err(e) => println!("{label}: 读取失败 {} ({e})", path.display()),
    }
}

// ---- native Tab completion (`gs __complete` engine + `gs completions <shell>`) ----
//
// F8 (design.md §14 / §13 Q5): jq-free completion. The shell scripts call
// `gs __complete <completed words>`; the Rust core reads router.json and prints
// one candidate per line — `value` or `value\tdescription` (locale-picked). The
// shell filters by the partial and shows the description where it can (zsh/fish/
// nu/pwsh; bash drops it).

/// Front-door commands as `(name, one-line summary, subcommands)`, for
/// top-level/`<cmd>` completion. (`__complete` itself is intentionally hidden.)
/// Summaries are locale-agnostic single strings — only plugin/command
/// descriptions (from router.json) are locale-picked.
const SYSTEM_CMDS: &[(&str, &str, &[&str])] = &[
    ("version", "显示版本号", &[]),
    ("help", "显示帮助", &[]),
    ("plugin", "插件管理（启用/禁用/列表/migrate）", &["migrate"]),
    ("status", "查看状态", &[]),
    ("doctor", "环境体检", &[]),
    ("refresh", "刷新命令索引", &[]),
    ("event", "上报 Agent 状态事件", &["emit"]),
    (
        "hooks",
        "安装/卸载状态灯 hooks",
        &["install", "uninstall", "status"],
    ),
    (
        "completions",
        "生成 Tab 补全脚本",
        &["bash", "zsh", "fish", "nushell", "powershell"],
    ),
];

/// `gs __complete <completed words…>` — the F8 engine. Prints candidates one per
/// line as `value` or `value\tdescription` (locale-picked), then a final
/// Cobra-style directive line `:<bits>` controlling file/dir fallback. Merges
/// three sources: front-door commands, plugin.toml plugins (with dynamic arg
/// rules), and legacy router.json plugins. Quiet and best-effort.
fn cmd_complete(completed: &[String]) -> i32 {
    use gs_core::engine;
    let locale = detect_locale();
    let registry = Registry::discover(&engine_roots());
    let router = router_index_path()
        .and_then(|p| load_router(&p).ok())
        .unwrap_or_default();

    // Engine: front-door commands + plugin.toml plugins (+ dynamic arg rules).
    let mut comp = engine::complete(&registry, SYSTEM_CMDS, completed, &locale);

    // Merge in legacy router.json plugins so old-style plugins still complete.
    match completed {
        [] => {
            let have: std::collections::BTreeSet<String> =
                comp.candidates.iter().map(|c| c.value.clone()).collect();
            for cand in gs_core::completion::complete(&router, SYSTEM_CMDS, completed, &locale) {
                if !have.contains(&cand.value) {
                    comp.candidates.push(cand);
                }
            }
        }
        [head, ..] => {
            // First token is neither a front-door command nor a plugin.toml
            // plugin → defer to legacy router completion for that plugin.
            let is_system = SYSTEM_CMDS.iter().any(|(c, _, _)| c == head);
            let is_manifest = registry.enabled().any(|p| &p.manifest.name == head);
            if !is_system && !is_manifest {
                comp.candidates =
                    gs_core::completion::complete(&router, SYSTEM_CMDS, completed, &locale);
                comp.directive = engine::directive::NO_FILE;
            }
        }
    }

    comp.candidates.sort_by(|a, b| a.value.cmp(&b.value));
    comp.candidates.dedup_by(|a, b| a.value == b.value);

    let mut out = String::new();
    for c in &comp.candidates {
        out.push_str(&c.value);
        if let Some(desc) = &c.description {
            out.push('\t');
            out.push_str(desc);
        }
        out.push('\n');
    }
    // Cobra-style directive on the final line; the shell scripts strip it.
    out.push_str(&format!(":{}\n", comp.directive));
    print!("{out}");
    0
}

/// Best-effort UI locale for completion descriptions: `GS_LANG` → `LC_ALL` →
/// `LC_MESSAGES` → `LANG`, reduced to the language subtag (`zh_CN.UTF-8` → `zh`).
/// Defaults to "en"; `completion::complete` still falls back en → zh → any.
fn detect_locale() -> String {
    for key in ["GS_LANG", "LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(v) = std::env::var(key) {
            let lang = v
                .split(['_', '.', '@'])
                .next()
                .unwrap_or("")
                .trim()
                .to_ascii_lowercase();
            if !lang.is_empty() && lang != "c" && lang != "posix" {
                return lang;
            }
        }
    }
    "en".to_string()
}

/// `gs completions <shell>` — print a completion script that wires the shell to
/// `gs __complete`.
fn cmd_completions(args: &[String]) -> i32 {
    let script = match args.first().map(String::as_str) {
        Some("bash") => COMP_BASH,
        Some("zsh") => COMP_ZSH,
        Some("fish") => COMP_FISH,
        Some("nu" | "nushell") => COMP_NUSHELL,
        Some("pwsh" | "powershell") => COMP_POWERSHELL,
        _ => {
            eprintln!("用法: gs completions <bash|zsh|fish|nushell|powershell>");
            eprintln!();
            eprintln!("启用（选你的 shell）:");
            eprintln!("  fish: gs completions fish > ~/.config/fish/completions/gs.fish   # 立即生效，无需 source");
            eprintln!("  zsh:  gs completions zsh  > \"${{fpath[1]}}/_gs\"   （或 .zshrc 里 source <(gs completions zsh)）");
            eprintln!("  bash: gs completions bash >> ~/.bash_completion    （或 source <(gs completions bash)）");
            eprintln!();
            eprintln!("补全候选由 'gs __complete' 原生计算，无 jq 依赖。");
            return 2;
        }
    };
    print!("{script}");
    0
}

const COMP_BASH: &str = r#"# gs bash completion.  Enable: source <(gs completions bash)
_gs_complete() {
    local cur line i directive=0
    local -a completed=() cands=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    for (( i = 1; i < COMP_CWORD; i++ )); do completed+=("${COMP_WORDS[i]}"); done
    # Each line is `value<TAB>desc`; the final `:<bits>` line is the directive.
    while IFS= read -r line; do
        if [[ $line == :* ]]; then directive="${line#:}"; continue; fi
        cands+=("${line%%$'\t'*}")          # bash shows only the value
    done < <(gs __complete "${completed[@]}" 2>/dev/null)
    COMPREPLY=()
    if (( directive & 16 )); then           # FILTER_DIRS
        COMPREPLY=( $(compgen -d -- "$cur") )
    else
        local IFS=$'\n'
        COMPREPLY=( $(compgen -W "${cands[*]}" -- "$cur") )
        (( (directive & 4) == 0 )) && COMPREPLY+=( $(compgen -f -- "$cur") )   # not NO_FILE
    fi
    (( directive & 2 )) && compopt -o nospace 2>/dev/null                      # NO_SPACE
}
complete -F _gs_complete gs
"#;

const COMP_ZSH: &str = r#"# gs zsh completion.  Enable (after compinit): source <(gs completions zsh)
_gs_complete() {
    local -a completed lines described
    local line directive=0
    completed=(${words[2,CURRENT-1]})
    lines=(${(f)"$(gs __complete ${completed} 2>/dev/null)"})
    for line in $lines; do
        if [[ $line == :* ]]; then directive=${line#:}; continue; fi
        described+=("${line/$'\t'/:}")      # value:desc for _describe
    done
    if (( directive & 16 )); then           # FILTER_DIRS
        _files -/
    else
        _describe 'gs' described
        (( (directive & 4) == 0 )) && _files   # not NO_FILE → also files
    fi
}
compdef _gs_complete gs
"#;

const COMP_FISH: &str = r#"# gs fish completion.  Enable: gs completions fish > ~/.config/fish/completions/gs.fish
# Each line is `value<TAB>desc` (fish shows the description); the final `:<bits>`
# line is the directive (16=dirs, 4=no-file, 0=files — the engine emits 0/4/16).
function __gs_complete
    set -l completed (commandline -opc)
    set -l directive 0
    for line in (gs __complete $completed[2..-1] 2>/dev/null)
        if string match -q ':*' -- $line
            set directive (string sub -s 2 -- $line)
        else
            printf '%s\n' $line
        end
    end
    if test "$directive" = 16
        __fish_complete_directories (commandline -ct)
    else if test "$directive" = 0
        __fish_complete_path (commandline -ct)
    end
end
complete -c gs -f -a '(__gs_complete)'
"#;

const COMP_NUSHELL: &str = r#"# gs nushell completion (experimental).  Add to your config.nu.
# Note: nushell uses ONE global external completer — merge this with any existing one.
$env.config.completions.external.enable = true
$env.config.completions.external.completer = {|spans|
    if ($spans | first) == "gs" {
        let completed = ($spans | skip 1 | drop 1)
        # Lines are `value<TAB>desc`; drop the trailing `:<directive>` line.
        (^gs __complete ...$completed | lines
            | where {|l| ($l | str trim) != "" and not ($l | str starts-with ":") }
            | each {|l|
                let p = ($l | split row "\t")
                {value: ($p | get 0), description: ($p | get 1? | default "")}
            })
    } else { null }
}
"#;

const COMP_POWERSHELL: &str = r#"# gs PowerShell completion (experimental).  Add to your $PROFILE.
Register-ArgumentCompleter -Native -CommandName gs -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $elems = @($commandAst.CommandElements | ForEach-Object { $_.ToString() })
    $end = $elems.Count - 1
    if ($wordToComplete -ne '') { $end-- }
    $completed = @()
    if ($end -ge 1) { $completed = $elems[1..$end] }
    # `gs __complete` prints `value<TAB>desc` then a `:<directive>` line (dropped).
    (gs __complete @completed 2>$null) | Where-Object { $_ -ne '' -and $_ -notmatch '^:' } | ForEach-Object {
        $parts = $_ -split "`t", 2
        $val = $parts[0]
        $desc = if ($parts.Count -gt 1 -and $parts[1]) { $parts[1] } else { $val }
        [System.Management.Automation.CompletionResult]::new($val, $val, 'ParameterValue', $desc)
    }
}
"#;
