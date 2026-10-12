//! `gs` — the command front door.
//!
//! Everything the user types is resolved here against `plugin.toml` manifests
//! (`gs-core::index`) and dispatched by tier:
//!   - front-door commands (`version`, `help`, `status`, `doctor`, `plugin`,
//!     `init`, `completions`, `shell-init`, …) are native,
//!   - T1 `declarative` commands render their `run` template to an argv and
//!     exec it (capability-gated, no shell) — see `gs-core::exec`,
//!   - T2/T3 commands are invoked over JSON-RPC (`gs-core::rpc` / `daemon`),
//!   - a `cd` command emits a shell effect the wrapper `eval`s.
//!
//! Legacy dispatch through `router.json` and the Python `gscripts` CLI was
//! removed when GS 6.0 became the only runtime (see `docs/adr/005-*`).

use gs_core::index::Registry;
use shell::SYSTEM_CMDS;
use std::path::{Path, PathBuf};

mod dispatch;
mod init;
mod plugin;
mod shell;
mod system;
mod ui;

use dispatch::dispatch_manifest;
use init::cmd_init;
use plugin::{
    cmd_plugin_info, cmd_plugin_list, cmd_plugin_migrate, cmd_plugin_toggle, cmd_plugin_unknown,
};
use shell::{cmd_complete, cmd_completions, cmd_shell_init};
use system::{cmd_doctor, cmd_refresh, cmd_status};

fn main() {
    // Behave like a normal Unix filter: a closed reader (e.g. `gs … | head`, or
    // `source <(gs completions …)`) should terminate us quietly, not panic.
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    configure_distribution_env();
    configure_color_env();
    let args: Vec<String> = std::env::args().skip(1).collect();
    std::process::exit(run(&args));
}

fn configure_distribution_env() {
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let Some(root) = distribution_root_from_exe(&executable) else {
        return;
    };
    if std::env::var_os("GS_ROOT").is_none() {
        std::env::set_var("GS_ROOT", &root);
    }
    if std::env::var_os("GS_COMMAND_NAME").is_none() {
        if let Some(name) = executable.file_stem().and_then(|s| s.to_str()) {
            std::env::set_var("GS_COMMAND_NAME", name);
        }
    }
    if std::env::var_os("GS_COMMAND_PATH").is_none() {
        std::env::set_var("GS_COMMAND_PATH", &executable);
    }
    if std::env::var_os("GS_CACHE_DIR").is_none() {
        if let Some(cache) = default_cache_dir() {
            std::env::set_var("GS_CACHE_DIR", cache);
        }
    }
}

fn distribution_root_from_exe(executable: &Path) -> Option<PathBuf> {
    let root = executable.parent()?;
    (root.join("plugins").is_dir() && root.join("sdk").is_dir()).then(|| root.to_path_buf())
}

fn default_cache_dir() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        return std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .or_else(gs_core::home_dir)
            .map(|root| root.join("global-scripts").join("gs"));
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| gs_core::home_dir().map(|home| home.join(".cache")))
            .map(|root| root.join("global-scripts").join("gs"))
    }
}

fn configure_color_env() {
    let forced = matches!(
        std::env::var("GS_FORCE_COLOR").ok().as_deref(),
        Some("1") | Some("true") | Some("on")
    ) || matches!(
        std::env::var("GS_COLOR").ok().as_deref(),
        Some("1") | Some("true") | Some("on")
    );
    let disabled = matches!(
        std::env::var("GS_COLOR").ok().as_deref(),
        Some("0") | Some("false") | Some("off")
    );
    if forced {
        // The explicit application-level override for callers who want ANSI
        // even when the destination is a file or a pipe.
        std::env::remove_var("NO_COLOR");
    } else if disabled {
        // anstream (and tabled's colour) follow NO_COLOR, so an explicit opt-out
        // has to be expressed that way; children inherit it too.
        std::env::set_var("NO_COLOR", "1");
    }
}

fn run(args: &[String]) -> i32 {
    // Front-door commands, resolved before any plugin is consulted.
    match args.first().map(String::as_str) {
        None | Some("") => return cmd_help(),
        Some("version") => return cmd_version(),
        Some("help") => return cmd_help(),
        Some("status") => return cmd_status(),
        Some("doctor") => return cmd_doctor(),
        Some("refresh") => return cmd_refresh(&args[1..]),
        Some("__complete") => return cmd_complete(&args[1..]),
        Some("__daemon") => return cmd_daemon(&args[1..]),
        Some("init") => return cmd_init(&args[1..]),
        Some("completions") => return cmd_completions(&args[1..]),
        Some("shell-init") => return cmd_shell_init(&args[1..]),
        Some("plugin") => match args.get(1).map(String::as_str) {
            None => return cmd_plugin_list(&[]),
            Some("migrate") => return cmd_plugin_migrate(&args[2..]),
            Some("list") => return cmd_plugin_list(&args[2..]),
            Some("info") => return cmd_plugin_info(&args[2..]),
            Some("enable") => return cmd_plugin_toggle(&args[2..], true),
            Some("disable") => return cmd_plugin_toggle(&args[2..], false),
            Some(command) => return cmd_plugin_unknown(command),
        },
        _ => {}
    }

    // A plugin named on the command line dispatches through its manifest. A
    // broken manifest is reported here rather than silently ignored, so
    // `gs <plugin>` always tells you *why* it didn't run.
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

    // Nothing matched: it is not a front-door command and not a plugin.
    cmd_unknown(args)
}

/// `gs <something we don't know>` — fail loudly with a way forward instead of
/// guessing. Never spawns another interpreter.
fn cmd_unknown(args: &[String]) -> i32 {
    let name = args.first().map(String::as_str).unwrap_or("");
    eprintln!("错误: 未知命令或插件 '{name}'");
    eprintln!("提示: 'gs help' 查看用法 · 'gs plugin list' 查看插件");
    1
}

fn cmd_daemon(args: &[String]) -> i32 {
    let (Some(name), Some(socket)) = (args.first(), args.get(1)) else {
        eprintln!(
            "用法: {name} __daemon <plugin> <socket>",
            name = command_name()
        );
        return 2;
    };
    let plugin = match Registry::find_checked(&engine_roots(), name) {
        Ok(Some(p)) => p,
        Ok(None) => {
            eprintln!("错误: 未找到插件 '{name}'");
            return 2;
        }
        Err(msg) => {
            eprintln!("错误: 插件 '{name}' 的 plugin.toml 无效：");
            eprintln!("  {msg}");
            return 2;
        }
    };
    let Some(mut spec) = gs_core::daemon::resident_spec(&plugin) else {
        eprintln!("错误: 插件 '{name}' 不是常驻(rpc)插件或常驻传输已禁用");
        return 2;
    };
    // The client's path wins: it is the address that caller will reconnect to.
    spec.socket = PathBuf::from(socket);
    match gs_core::daemon::run(spec) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("gs __daemon: {error}");
            1
        }
    }
}

/// Print the GS 6.0 development version. The legacy `GS_VERSION=5.2.0` shell
/// variable is intentionally ignored so a stale 5.2 environment cannot make
/// the development binary report the wrong generation.
fn cmd_version() -> i32 {
    println!("6.0.0-dev (core 0.6.0-dev)");
    0
}

fn cmd_help() -> i32 {
    #[derive(tabled::Tabled)]
    struct Entry {
        #[tabled(rename = "命令")]
        name: String,
        #[tabled(rename = "说明")]
        summary: String,
    }

    let name = command_name();
    ui::write_line(&ui::styled(
        "Global Scripts 6.0 development CLI",
        ui::accent(),
    ));
    ui::write_line(&ui::styled(
        &format!("用法: {name} <命令> [参数…]"),
        ui::dim(),
    ));
    ui::write_line("");

    let systems: Vec<Entry> = SYSTEM_CMDS
        .iter()
        .map(|(name, summary, _)| Entry {
            name: (*name).to_string(),
            summary: (*summary).to_string(),
        })
        .collect();
    let systems = ui::titled("系统命令", systems, true);
    ui::print(&systems);
    ui::write_line("");

    let registry = Registry::discover(&engine_roots());
    let mut plugins: Vec<Entry> = registry
        .enabled()
        .map(|p| Entry {
            name: p.manifest.name.clone(),
            summary: gs_core::manifest::pick(&p.manifest.description, &detect_locale())
                .unwrap_or_default(),
        })
        .collect();
    // Help is for looking things up: alphabetical beats priority order here.
    plugins.sort_by(|a, b| a.name.cmp(&b.name));
    let summary_budget = ui::width().saturating_sub(24).max(24);
    for entry in &mut plugins {
        entry.summary = ui::truncate(&entry.summary, summary_budget);
    }
    let plugins = ui::titled("插件命令", plugins, true);
    ui::print(&plugins);
    ui::write_line("");
    ui::note(&format!(
        "用 `{name} <插件> --help` 查看某个插件的命令；`{name} help` 会随插件变化。"
    ));
    0
}

pub(crate) fn command_name() -> String {
    std::env::var("GS_COMMAND_NAME").unwrap_or_else(|_| "gs".into())
}

/// Plugin-discovery roots for the engine (`$GS_ROOT/plugins`; examples are
/// opt-in via `GS_INCLUDE_EXAMPLES=1`).
pub(crate) fn engine_roots() -> Vec<PathBuf> {
    gs_core::index::default_roots()
}

/// Dispatch `gs <plugin> <command> [args…]` for a plugin.toml plugin.
pub(crate) fn detect_locale() -> String {
    for key in ["GS_LANG", "GS_LANGUAGE", "LC_ALL", "LC_MESSAGES", "LANG"] {
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
#[cfg(test)]
mod tests {
    use super::distribution_root_from_exe;
    use crate::plugin::set_manifest_enabled;

    #[test]
    fn set_manifest_enabled_inserts_before_sections() {
        let input = "name=\"demo\"\ntier=\"declarative\"\n[capabilities]\nexec=[\"echo\"]\n";
        let output = set_manifest_enabled(input, false);
        assert!(output.contains("tier=\"declarative\"\nenabled = false\n[capabilities]"));
        assert_eq!(output.matches("enabled = false").count(), 1);
    }

    #[test]
    fn set_manifest_enabled_replaces_existing_value() {
        let input = "name=\"demo\"\nenabled = false\ntier=\"declarative\"\n";
        let output = set_manifest_enabled(input, true);
        assert!(output.contains("enabled = true"));
        assert!(!output.contains("enabled = false"));
    }

    #[test]
    fn detects_a_portable_distribution_beside_the_binary() {
        let root = std::env::temp_dir().join(format!("gs-portable-root-{}", std::process::id()));
        std::fs::create_dir_all(root.join("plugins")).unwrap();
        std::fs::create_dir_all(root.join("sdk")).unwrap();
        assert_eq!(
            distribution_root_from_exe(&root.join("gs")),
            Some(root.clone())
        );
        assert_eq!(distribution_root_from_exe(&root.join("bin/gs")), None);
    }
}
