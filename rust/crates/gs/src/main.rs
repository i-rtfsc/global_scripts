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

use gs_core::{load_router, resolve, router_index_path, CommandEntry, Resolution};
use std::process::Command;

fn main() {
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
        Some("help" | "plugin" | "status" | "doctor" | "refresh") => return delegate_python(args),
        _ => {}
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

#[cfg(not(unix))]
fn send_to_gsd(_env: &gs_core::Envelope) {}

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
