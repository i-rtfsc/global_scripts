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
use std::path::{Path, PathBuf};
use std::process::Command;

mod ui;

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
    // System commands. The legacy wrapper sends all of these to Python; we keep
    // `version` native (the hot path we benchmark) and delegate the rest for now.
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

fn cmd_plugin_unknown(command: &str) -> i32 {
    eprintln!("错误: plugin 没有命令 '{command}'");
    eprintln!("可用命令: list, info, enable, disable, migrate");
    1
}

/// `gs init` —— 按 `$GS_ROOT/config/init.toml` 的步骤清单初始化这台机器。
///
/// 装什么由各插件负责(能力在插件里),这里只负责**顺序与筛选**。清单是数据,
/// 所以插件拆分/合并后只要改 `run` 一行,`gs init` 的用法不变。
///
/// 模式(与其它有副作用的命令一致,必须显式指定其一):
///   `--list`     只看清单
///   `--dry-run`  逐步预览(把 `--dry-run` 透传给需要门禁的命令)
///   `--yes`      真正执行(把 `--yes` 透传)
/// 筛选:`--group=a,b` `--only=<id|插件>` `--skip=<id|插件>` `--without=<组>`
fn cmd_init(args: &[String]) -> i32 {
    use gs_core::init::{Filter, Plan};

    let mut mode = String::new();
    let mut filter = Filter::default();
    let split = |value: &str| -> Vec<String> {
        value
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
            .map(String::from)
            .collect()
    };
    for arg in args {
        match arg.as_str() {
            "--list" | "--dry-run" | "--yes" => {
                if !mode.is_empty() && mode != *arg {
                    eprintln!("错误: --list/--dry-run/--yes 只能指定一个");
                    return 2;
                }
                mode = arg.clone();
            }
            _ if arg.starts_with("--group=") => filter.groups = split(&arg["--group=".len()..]),
            _ if arg.starts_with("--only=") => filter.only = split(&arg["--only=".len()..]),
            _ if arg.starts_with("--skip=") => filter.skip = split(&arg["--skip=".len()..]),
            _ if arg.starts_with("--without=") => {
                filter.without = split(&arg["--without=".len()..])
            }
            other => {
                eprintln!("错误: 未知参数 '{other}'");
                eprintln!("用法: {name} init <--list|--dry-run|--yes> [--group=…] [--only=…] [--skip=…] [--without=…]", name = command_name());
                return 2;
            }
        }
    }
    if mode.is_empty() {
        eprintln!(
            "用法: {name} init <--list|--dry-run|--yes> [--group=…] [--only=…] [--skip=…] [--without=…]",
            name = command_name()
        );
        eprintln!("  --list     查看步骤清单(不改任何东西)");
        eprintln!("  --dry-run  逐步预览");
        eprintln!("  --yes      真正执行(需要 root 的步骤会让你用 sudo 再跑一次)");
        return 2;
    }

    let root_dir = std::env::var("GS_ROOT").unwrap_or_else(|_| ".".into());
    let path = PathBuf::from(&root_dir).join("config/init.toml");
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) => {
            eprintln!("错误: 读不到步骤清单 {}: {error}", path.display());
            return 1;
        }
    };
    let plan = match Plan::parse(&text) {
        Ok(plan) => plan,
        Err(message) => {
            eprintln!("错误: {message}");
            return 1;
        }
    };

    let locale = detect_locale();
    let selected = plan.select(&filter);
    if selected.is_empty() {
        eprintln!("没有匹配的步骤(检查 --group/--only/--skip/--without)");
        return 2;
    }

    // 每一步是否真的能跑:插件存在 + 命令存在。
    let roots = engine_roots();
    let step_state = |step: &gs_core::init::Step| -> Result<(), String> {
        let plugin = step.plugin();
        let manifest = match Registry::find_checked(&roots, plugin) {
            Ok(Some(manifest)) => manifest,
            Ok(None) => return Err(format!("插件 '{plugin}' 尚未创建")),
            Err(message) => return Err(message),
        };
        let rest = &step.run[1..];
        let known = (1..=rest.len()).rev().any(|take| {
            let joined = rest[..take].join(".");
            manifest
                .commands(&locale)
                .iter()
                .any(|c| !c.hidden && c.name == joined)
        });
        if !known {
            return Err(format!("命令 '{}' 尚未实现", step.run.join(" ")));
        }
        Ok(())
    };

    #[derive(tabled::Tabled)]
    struct Row {
        #[tabled(rename = "步骤")]
        id: String,
        #[tabled(rename = "分组")]
        group: String,
        #[tabled(rename = "命令")]
        command: String,
        #[tabled(rename = "说明")]
        description: String,
        #[tabled(rename = "状态")]
        status: String,
    }

    let is_root = unsafe { libc::geteuid() } == 0;
    let mut rows = Vec::new();
    let mut pending = Vec::new();
    for step in &selected {
        let state = step_state(step);
        let status = match &state {
            Ok(()) if step.root && !is_root => "需要 sudo".to_string(),
            Ok(()) => "就绪".to_string(),
            Err(why) => why.clone(),
        };
        rows.push(Row {
            id: step.id.clone(),
            group: step.group.clone(),
            command: step.run.join(" "),
            description: ui::truncate(
                &step.description(&locale),
                ui::width().saturating_sub(44).max(20),
            ),
            status,
        });
        pending.push((*step).clone());
    }
    let mut table = ui::table(rows);
    ui::right(&mut table, 0);
    ui::print(&table);

    let implemented = selected.iter().filter(|s| step_state(s).is_ok()).count();
    ui::note(&format!(
        "共 {} 步 · 已实现 {} · 待实现 {}",
        selected.len(),
        implemented,
        selected.len() - implemented
    ));

    if mode == "--list" {
        return 0;
    }

    let flag = if mode == "--yes" {
        "--yes"
    } else {
        "--dry-run"
    };
    let mut failures = 0usize;
    let mut skipped_root = Vec::new();
    let mut skipped_missing = Vec::new();
    for step in &pending {
        if let Err(why) = step_state(step) {
            skipped_missing.push(format!("{} ({why})", step.id));
            continue;
        }
        if step.root && !is_root {
            skipped_root.push(step.id.clone());
            continue;
        }
        let argv = step.argv(Some(flag));
        ui::write_line("");
        ui::write_line(&format!(
            "{} {}",
            ui::styled(&format!("==> {}", step.id), ui::accent()),
            ui::styled(&argv.join(" "), ui::dim())
        ));
        let code = run(&argv);
        if code != 0 {
            failures += 1;
            eprintln!(
                "步骤 '{}' 失败(退出 {code});修好后可用 `{name} init --only={} --yes` 单独重跑",
                step.id,
                step.id,
                name = command_name()
            );
            break;
        }
    }

    if !skipped_root.is_empty() {
        ui::write_line("");
        ui::note(&format!(
            "以下步骤需要 root,gs 不会自己提权,请用 sudo 重跑:{}",
            skipped_root.join(", ")
        ));
        ui::write_line(&format!(
            "  sudo {name} init --only={} --yes",
            skipped_root.first().cloned().unwrap_or_default(),
            name = command_name()
        ));
    }
    if !skipped_missing.is_empty() && mode == "--yes" {
        ui::note(&format!(
            "跳过尚未实现的步骤:{}",
            skipped_missing.join(", ")
        ));
    }
    if failures > 0 {
        1
    } else {
        0
    }
}

/// Ask which plugin to act on. Only reachable in front of a terminal: scripted
/// runs still get the usage error they can handle.
fn pick_plugin(action: &str) -> Option<String> {
    if !ui::interactive() {
        return None;
    }
    let registry = Registry::discover(&engine_roots());
    let options: Vec<String> = registry
        .plugins
        .iter()
        .map(|p| {
            let state = if p.manifest.enabled {
                ""
            } else {
                " (已禁用)"
            };
            format!("{}{state}", p.manifest.name)
        })
        .collect();
    if options.is_empty() {
        return None;
    }
    let answer = inquire::Select::new(&format!("选择要{action}的插件"), options)
        .with_page_size(15)
        .prompt();
    answer.ok().map(|choice| {
        choice
            .split(" (已禁用)")
            .next()
            .unwrap_or(&choice)
            .to_string()
    })
}

/// `gs __daemon <plugin> <socket>` — internal: run a T3 resident plugin daemon.
/// Hidden from help; started by `gs_core::daemon` when a T3 plugin is first
/// used and lives until it goes idle or the plugin exits. It outlives its
/// client, so its stderr goes to `$GS_CACHE_DIR/daemon/<plugin>.<gen>.log`
/// rather than to any terminal.
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

fn command_name() -> String {
    std::env::var("GS_COMMAND_NAME").unwrap_or_else(|_| "gs".into())
}

fn cmd_status() -> i32 {
    let registry = Registry::discover(&engine_roots());
    let enabled = registry
        .plugins
        .iter()
        .filter(|p| p.manifest.enabled)
        .count();
    let disabled = registry.plugins.len().saturating_sub(enabled);
    let router = router_index_path().and_then(|p| load_router(&p).ok());
    let legacy = router
        .as_ref()
        .map(|r| {
            r.plugins
                .keys()
                .filter(|name| registry.get(name).is_none())
                .count()
        })
        .unwrap_or(0);

    #[derive(tabled::Tabled)]
    struct Fact {
        #[tabled(rename = "")]
        key: String,
        #[tabled(rename = "")]
        value: String,
    }
    let rows = vec![
        Fact {
            key: "manifest 插件".into(),
            value: format!(
                "{} 个（启用 {}，禁用 {}）",
                registry.plugins.len(),
                enabled,
                disabled
            ),
        },
        Fact {
            key: "legacy 插件".into(),
            value: format!("{legacy} 个"),
        },
        Fact {
            key: "插件根目录".into(),
            value: format!("{} 个", engine_roots().len()),
        },
        Fact {
            key: "router.json".into(),
            value: if router.is_some() {
                "可用".into()
            } else {
                "未发现（不影响 GS 6.0 插件）".into()
            },
        },
    ];
    let table = ui::facts("GS 6.0 状态", rows);
    ui::print(&table);
    0
}

fn cmd_doctor() -> i32 {
    let roots = engine_roots();
    let mut manifest_files = 0usize;
    let mut invalid = Vec::new();
    let mut missing_entries = Vec::new();
    for root in &roots {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path().join("plugin.toml");
            if !path.is_file() {
                continue;
            }
            manifest_files += 1;
            if let Ok(text) = std::fs::read_to_string(&path) {
                match gs_core::manifest::PluginManifest::parse(&text) {
                    Ok(manifest) if !manifest.entry.is_empty() => {
                        let entry = entry.path().join(&manifest.entry);
                        if !entry.is_file() {
                            missing_entries.push(format!("{}: entry 不存在", entry.display()));
                        }
                    }
                    Ok(_) => {}
                    Err(e) => invalid.push(format!("{}: {e}", path.display())),
                }
            } else {
                invalid.push(format!("{}: 无法读取", path.display()));
            }
        }
    }
    let root_ok = std::env::var_os("GS_ROOT")
        .map(|p| Path::new(&p).is_dir())
        .unwrap_or(false);
    let sdk_ok = std::env::var_os("GS_ROOT")
        .map(|p| PathBuf::from(p).join("sdk/python/gs_plugin").is_dir())
        .unwrap_or(false);
    let all_ok = root_ok && invalid.is_empty() && missing_entries.is_empty();
    #[derive(tabled::Tabled)]
    struct Check {
        #[tabled(rename = "")]
        item: String,
        #[tabled(rename = "")]
        result: String,
    }
    let rows = vec![
        Check {
            item: "GS_ROOT".into(),
            result: if root_ok {
                "正常".into()
            } else {
                "未设置或不存在".into()
            },
        },
        Check {
            item: "plugin.toml".into(),
            result: format!(
                "{} 个，{} 个有效",
                manifest_files,
                manifest_files.saturating_sub(invalid.len())
            ),
        },
        Check {
            item: "Python SDK".into(),
            result: if sdk_ok {
                "可用".into()
            } else {
                "未发现（T1 仍可用）".into()
            },
        },
        Check {
            item: "T2/T3 entry".into(),
            result: if missing_entries.is_empty() {
                "完整".into()
            } else {
                "有缺失".into()
            },
        },
        Check {
            item: "结果".into(),
            result: if all_ok {
                "通过".into()
            } else {
                "发现问题".into()
            },
        },
    ];
    let table = ui::facts("GS 6.0 体检", rows);
    ui::print(&table);
    for error in invalid.iter().take(10) {
        ui::write_line(&format!("  - {}", ui::styled(error, ui::fail())));
    }
    for error in missing_entries.iter().take(10) {
        ui::write_line(&format!("  - {}", ui::styled(error, ui::warn())));
    }

    // 元数据检查(警告,不影响退出码):命令用了点号分组却没在 manifest 里声明,
    // `gs <插件>` 就没有组描述可显示 —— 这正是分组显示不好看的根因。
    let locale = detect_locale();
    let mut undeclared: Vec<String> = Vec::new();
    for p in Registry::discover(&engine_roots()).plugins.iter() {
        let prefixes: std::collections::BTreeSet<String> = p
            .commands(&locale)
            .iter()
            .filter(|c| !c.hidden)
            .filter_map(|c| c.name.split_once('.').map(|(group, _)| group.to_string()))
            .collect();
        let missing: Vec<String> = prefixes
            .into_iter()
            .filter(|group| !p.manifest.groups.contains_key(group))
            .collect();
        if !missing.is_empty() {
            undeclared.push(format!(
                "{}: 缺 [groups] 声明 — {}",
                p.manifest.name,
                missing.join(", ")
            ));
        }
    }
    if undeclared.is_empty() {
        ui::note("分组元数据: 全部插件的分组都有 [groups] 声明");
    } else {
        for warning in &undeclared {
            ui::write_line(&format!("  ! {}", ui::styled(warning, ui::warn())));
        }
    }

    // shell 集成现状:环境文件在哪、哪些 rc 引用了它。
    // 这一节回答"gs 到底往我的 shell 里放了什么"。
    let home = gs_core::home_dir();
    let env_shells = ["bash", "zsh", "fish"];
    let consumers: Vec<(&str, String)> = vec![
        ("~/.bashrc", ".bashrc".to_string()),
        ("~/.zshrc", ".zshrc".to_string()),
        ("fish", ".config/fish/config.fish".to_string()),
    ];
    let mut shell_lines: Vec<String> = Vec::new();
    if let Some(home) = home {
        let env_dir = home.join(".config/global-scripts/shell");
        let present: Vec<&str> = env_shells
            .iter()
            .copied()
            .filter(|shell| env_dir.join(format!("gs-env.{shell}")).is_file())
            .collect();
        shell_lines.push(format!(
            "环境文件 {} ({})",
            env_dir.display(),
            if present.is_empty() {
                "缺失".to_string()
            } else {
                present.join("/")
            }
        ));
        for (label, relative) in &consumers {
            let path = home.join(relative);
            let referenced = std::fs::read_to_string(&path)
                .map(|text| text.contains("gs-env."))
                .unwrap_or(false);
            shell_lines.push(format!(
                "{label} 引用 {} {}",
                if referenced { "✓" } else { "✗" },
                ui::truncate(&path.display().to_string(), 60)
            ));
        }
    }
    ui::note(&format!("Shell 集成: {}", shell_lines.join(" · ")));

    ui::write_line(&ui::styled(
        if all_ok {
            "全部通过"
        } else {
            "需要处理"
        },
        if all_ok { ui::ok() } else { ui::fail() },
    ));
    if all_ok {
        0
    } else {
        1
    }
}

fn cmd_refresh(args: &[String]) -> i32 {
    if args.iter().any(|a| a == "--legacy") {
        return delegate_python(&["refresh".into()]);
    }
    let registry = Registry::discover(&engine_roots());
    let invalid = count_invalid_manifests(&engine_roots());
    println!("GS 6.0 refresh");
    println!("  已重新扫描 {} 个有效 plugin.toml", registry.plugins.len());
    println!("  原生补全无需生成文件，下次调用自动使用最新 manifest");
    if invalid > 0 {
        println!(
            "  警告: 发现 {} 个无效 manifest（运行 gs doctor 查看）",
            invalid
        );
        return 1;
    }
    0
}

fn count_invalid_manifests(roots: &[PathBuf]) -> usize {
    let mut invalid = 0;
    for root in roots {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path().join("plugin.toml");
            if path.is_file()
                && std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|text| gs_core::manifest::PluginManifest::parse(&text).err())
                    .is_some()
            {
                invalid += 1;
            }
        }
    }
    invalid
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

/// Plugin-discovery roots for the engine (`$GS_ROOT/plugins`; examples are opt-in).
fn engine_roots() -> Vec<PathBuf> {
    gs_core::index::default_roots()
}

/// Dispatch `gs <plugin> <command> [args…]` for a plugin.toml plugin.
fn dispatch_manifest(p: &LoadedManifest, rest: &[String]) -> i32 {
    use gs_core::manifest::Tier;
    if !p.manifest.enabled {
        eprintln!("错误: 插件 '{}' 已被禁用", p.manifest.name);
        return 1;
    }
    let locale = detect_locale();
    let cmds = p.commands(&locale);
    if rest.is_empty() {
        return print_plugin_overview(p, &cmds, &locale, None);
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
        if rest.len() == 1 {
            let prefix = format!("{}.", rest[0]);
            let group_cmds: Vec<CommandSpec> = cmds
                .iter()
                .filter(|c| !c.hidden && c.name.starts_with(&prefix))
                .cloned()
                .collect();
            if !group_cmds.is_empty() {
                return print_plugin_overview(p, &group_cmds, &locale, Some(rest[0].as_str()));
            }
        }
        eprintln!(
            "错误: 插件 '{}' 没有命令 '{}'",
            p.manifest.name.clone(),
            rest.join(" ")
        );
        return 1;
    };
    // A `cd` command is navigation (chdir), not exec — handle it before the
    // tier split. The shell wrapper performs the real `cd`; see `exec_cd`.
    if !cmd.cd.is_empty() {
        return exec_cd(cmd, argv);
    }
    match p.manifest.tier {
        Tier::Declarative => exec_t1(p, cmd, argv),
        Tier::Script | Tier::Rpc | Tier::Wasm => invoke_t2(p, cmd, argv, &locale),
    }
}

fn show_in_plugin_table(plugin: &str, spec: &CommandSpec) -> bool {
    let _ = plugin;
    !spec.hidden
}

fn command_usage(command: &str, spec: &CommandSpec) -> String {
    if spec.usage.is_empty() {
        return format!("{command} [选项]");
    }
    let words: Vec<&str> = spec.usage.split_whitespace().collect();
    if words.first() == Some(&"gs") && words.len() >= 3 {
        let rest = words[2..].join(" ").replace('.', " ");
        let declared = spec.name.replace('.', " ");
        let suffix = rest.strip_prefix(&declared).unwrap_or(&rest).trim();
        return if suffix.is_empty() {
            command.to_string()
        } else {
            format!("{command} {suffix}")
        };
    }
    spec.usage.clone()
}

fn print_plugin_overview(
    p: &LoadedManifest,
    cmds: &[CommandSpec],
    locale: &str,
    group: Option<&str>,
) -> i32 {
    use gs_core::manifest::pick;
    let command = command_name();
    let description = pick(&p.manifest.description, locale).unwrap_or_default();
    let plugin_type = if p.dir.to_string_lossy().contains("/plugins/") {
        "系统插件"
    } else if p.dir.to_string_lossy().contains("/custom/") {
        "第三方插件"
    } else {
        "插件"
    };
    let title = group
        .map(|g| format!("插件 · {} / {g}", p.manifest.name))
        .unwrap_or_else(|| p.manifest.name.clone());
    let visible_count = cmds
        .iter()
        .filter(|spec| show_in_plugin_table(&p.manifest.name, spec))
        .count();

    // Header block: the facts a caller needs before running anything.
    if group.is_none() {
        #[derive(tabled::Tabled)]
        struct Fact {
            #[tabled(rename = "")]
            key: String,
            #[tabled(rename = "")]
            value: String,
        }
        let facts = vec![
            Fact {
                key: "名称".into(),
                value: p.manifest.name.clone(),
            },
            Fact {
                key: "版本".into(),
                value: p.manifest.version.clone(),
            },
            Fact {
                key: "作者".into(),
                value: p.manifest.author.clone(),
            },
            Fact {
                key: "描述".into(),
                value: description.clone(),
            },
            Fact {
                key: "状态".into(),
                value: if p.manifest.enabled {
                    "已启用".into()
                } else {
                    "已禁用".into()
                },
            },
            Fact {
                key: "类型".into(),
                value: plugin_type.into(),
            },
            Fact {
                key: "优先级".into(),
                value: p.manifest.priority.to_string(),
            },
            Fact {
                key: "命令数".into(),
                value: visible_count.to_string(),
            },
        ];
        let table = ui::facts(&format!("插件 · {title}"), facts);
        ui::print(&table);
        ui::write_line("");
    }

    // Command tree: one section per group, so a group reads as a heading rather
    // than as one more row in the same table (`app  Application management`).
    #[derive(tabled::Tabled)]
    struct Cmd {
        #[tabled(rename = "")]
        name: String,
        #[tabled(rename = "")]
        usage: String,
        #[tabled(rename = "")]
        summary: String,
    }

    let width = ui::width();
    let show_summary = width >= 96;
    let usage_w = cmds
        .iter()
        .map(|spec| {
            command_usage(
                &format!(
                    "{} {} {}",
                    command,
                    p.manifest.name,
                    spec.name.replace('.', " ")
                ),
                spec,
            )
            .len()
        })
        .max()
        .unwrap_or(0)
        .min(38);
    // name + usage + the listing's own indentation/padding
    let summary_budget = width.saturating_sub(usage_w + 16).max(16);

    let mut groups = std::collections::BTreeMap::<String, Vec<&CommandSpec>>::new();
    for spec in cmds
        .iter()
        .filter(|spec| show_in_plugin_table(&p.manifest.name, spec))
    {
        groups
            .entry(spec.group().to_string())
            .or_default()
            .push(spec);
    }
    if group.is_none() {
        let named_groups = groups.keys().filter(|name| !name.is_empty()).count();
        ui::note(&format!("命令 · {visible_count} 条 · {named_groups} 组"));
    }

    // Ungrouped commands first (they are the plugin's own verbs), then the
    // declared groups; `pick` gives each section its localised description.
    let mut sections: Vec<(String, String, Vec<&CommandSpec>)> = Vec::new();
    if let Some(top) = groups.remove("") {
        sections.push((String::new(), String::new(), top));
    }
    for (name, specs) in groups {
        let detail = p
            .manifest
            .groups
            .get(&name)
            .and_then(|d| pick(d, locale))
            .unwrap_or_default();
        sections.push((name, detail, specs));
    }

    for (name, detail, specs) in sections {
        if !name.is_empty() {
            ui::section(&name, &detail);
        }
        let rows = specs
            .iter()
            .map(|spec| {
                let usage = command_usage(
                    &format!(
                        "{} {} {}",
                        command,
                        p.manifest.name,
                        spec.name.replace('.', " ")
                    ),
                    spec,
                );
                let summary = pick(&spec.summary, locale).unwrap_or_default();
                Cmd {
                    name: ui::styled(spec.leaf(), ui::accent()),
                    usage: ui::styled(&ui::truncate(&usage, usage_w), ui::dim()),
                    summary: if show_summary {
                        ui::truncate(&summary, summary_budget)
                    } else {
                        String::new()
                    },
                }
            })
            .collect();
        let table = ui::listing(rows);
        ui::print(&table);
    }
    0
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

/// T1 navigation: resolve a command's `cd` target (placeholders + `$VAR`/`~`)
/// and hand it to the shell. The shell wrapper (`gs shell-init`) exports
/// `GS_CD_FILE`; we write the resolved path there and it runs the real `cd`.
/// With no wrapper installed we just print the path (and say how to enable it),
/// so the command is still informative rather than silently inert.
fn exec_cd(cmd: &CommandSpec, argv: &[String]) -> i32 {
    let bound = match gs_core::exec::bind(cmd, argv) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("错误: {e}");
            return 2;
        }
    };
    let raw = match gs_core::exec::render_cd(cmd, &bound) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("错误: {e}");
            return 2;
        }
    };
    let path = gs_core::exec::expand_path(&raw, |k| std::env::var(k).ok());
    if !Path::new(&path).is_dir() {
        eprintln!("错误: 目录不存在: {path}");
        return 1;
    }
    match std::env::var_os("GS_CD_FILE") {
        Some(file) => {
            let file_path = Path::new(&file);
            if !valid_effect_file(file_path) {
                eprintln!("错误: GS_CD_FILE 必须是临时目录内已存在的空普通文件");
                return 1;
            }
            if let Err(e) = std::fs::write(file_path, &path) {
                eprintln!("错误: 写入 GS_CD_FILE 失败：{e}");
                return 1;
            }
            println!("📁 {path}");
        }
        None => {
            println!("{path}");
            eprintln!("提示: 未启用 shell 集成，无法切换目录。运行 `gs shell-init <shell>` 安装。");
        }
    }
    0
}

fn valid_effect_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .ok()
        .filter(|meta| meta.file_type().is_file() && meta.len() == 0)
        .and_then(|_| path.parent())
        .and_then(|parent| parent.canonicalize().ok())
        .zip(std::env::temp_dir().canonicalize().ok())
        .map(|(parent, temp)| parent.starts_with(temp))
        .unwrap_or(false)
}

fn write_env_effects(value: &serde_json::Value) -> Result<bool, String> {
    let Some(changes) = value.as_object() else {
        return Err("插件返回的 env 必须是对象".into());
    };
    if changes.is_empty() {
        return Ok(false);
    }
    let Some(file) = std::env::var_os("GS_ENV_FILE") else {
        eprintln!("提示: 环境变量变更需要 shell 集成；运行 `gs shell-init <shell>` 安装。");
        return Ok(false);
    };
    let path = Path::new(&file);
    if !valid_effect_file(path) {
        return Err("GS_ENV_FILE 必须是临时目录内已存在的空普通文件".into());
    }
    let mut lines = String::new();
    for (key, value) in changes {
        if key.is_empty()
            || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
            || key.chars().next().is_some_and(|c| c.is_ascii_digit())
        {
            return Err(format!("非法环境变量名: {key}"));
        }
        match value {
            serde_json::Value::Null => lines.push_str(&format!("U\t{key}\n")),
            serde_json::Value::String(text)
                if !text.chars().any(|c| matches!(c, '\n' | '\r' | '\t' | '\0')) =>
            {
                lines.push_str(&format!("S\t{key}\t{text}\n"));
            }
            serde_json::Value::String(_) => {
                return Err(format!("环境变量 {key} 的值包含不支持的控制字符"));
            }
            _ => return Err(format!("环境变量 {key} 的值必须是字符串或 null")),
        }
    }
    std::fs::write(path, lines).map_err(|e| format!("写入 GS_ENV_FILE 失败: {e}"))?;
    Ok(true)
}

fn exec_plugin_result(p: &LoadedManifest, value: &serde_json::Value) -> Result<i32, String> {
    let items = value
        .as_array()
        .ok_or_else(|| "插件返回的 exec 必须是字符串数组".to_string())?;
    let argv: Vec<String> = items
        .iter()
        .map(|item| {
            item.as_str()
                .filter(|text| !text.contains('\0'))
                .map(str::to_string)
                .ok_or_else(|| "插件返回的 exec 包含非法参数".to_string())
        })
        .collect::<Result<_, _>>()?;
    let Some(program) = argv.first() else {
        return Err("插件返回的 exec 不能为空".into());
    };
    if !gs_core::caps::allows_exec(&p.manifest.capabilities, program) {
        return Err(format!("命令 '{program}' 不在插件能力白名单内"));
    }
    let mut command = Command::new(program);
    command.args(&argv[1..]);
    Ok(exec_or_status(command))
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
    if p.spawn().is_none() {
        eprintln!("错误: 无法确定插件 '{}' 的启动方式", p.manifest.name);
        return 1;
    }
    let req = rpc::request(1, "invoke", params);
    match gs_core::daemon::send(p, &[req], false) {
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
                if let Some(env) = result.get("env") {
                    if let Err(error) = write_env_effects(env) {
                        eprintln!("错误: 无法应用插件环境变量变更: {error}");
                        return 1;
                    }
                }
                if !streamed {
                    if let Some(s) = result.get("stdout").and_then(|v| v.as_str()) {
                        print!("{s}");
                    }
                    if let Some(s) = result.get("stderr").and_then(|v| v.as_str()) {
                        eprint!("{s}");
                    }
                }
                let exit_code = result
                    .get("exit_code")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0) as i32;
                if exit_code == 0 {
                    if let Some(command) = result.get("exec") {
                        let _ = std::io::stdout().flush();
                        let _ = std::io::stderr().flush();
                        return match exec_plugin_result(p, command) {
                            Ok(code) => code,
                            Err(error) => {
                                eprintln!("错误: 无法执行插件请求的命令: {error}");
                                1
                            }
                        };
                    }
                }
                exit_code
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

fn powershell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Fish single-quote escaping: inside `'…'` only `\` and `'` need escaping.
fn fish_quote(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
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

// ---- GS 6.0 plugin management --------------------------------------------

fn legacy_command_count(name: &str) -> usize {
    match name {
        _ => 0,
    }
}

/// List GS 6.0 manifests and legacy router entries without requiring Python.
fn cmd_plugin_list(_args: &[String]) -> i32 {
    #[derive(tabled::Tabled)]
    struct Row {
        #[tabled(rename = "插件")]
        name: String,
        #[tabled(rename = "命令")]
        commands: String,
        #[tabled(rename = "说明")]
        description: String,
    }

    let registry = Registry::discover(&engine_roots());
    let formal_names: std::collections::BTreeSet<&str> = registry
        .plugins
        .iter()
        .map(|plugin| plugin.manifest.name.as_str())
        .collect();
    let locale = detect_locale();
    // A plugin's command tree may need a process (T2/T3 `describe`), so the
    // first listing after an edit can take a moment: say so instead of hanging.
    let progress = ui::spinner("读取插件命令…");
    let mut rows: Vec<(i64, String, Row, bool)> = registry
        .plugins
        .iter()
        .map(|p| {
            let description =
                gs_core::manifest::pick(&p.manifest.description, &locale).unwrap_or_default();
            let hidden = p
                .commands(&locale)
                .iter()
                .filter(|c| !c.hidden)
                .count()
                .to_string();
            (
                p.manifest.priority,
                p.manifest.name.clone(),
                Row {
                    name: p.manifest.name.clone(),
                    commands: hidden,
                    description,
                },
                p.manifest.enabled,
            )
        })
        .collect();
    if let Some(root) = std::env::var_os("GS_ROOT") {
        let legacy_dir = PathBuf::from(root).join("legacy");
        if let Ok(entries) = std::fs::read_dir(legacy_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) != Some("json") {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(&path) else {
                    continue;
                };
                let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) else {
                    continue;
                };
                let Some(name) = value.get("name").and_then(|v| v.as_str()) else {
                    continue;
                };
                if formal_names.contains(name) {
                    continue;
                }
                let desc = value
                    .get("description")
                    .and_then(|v| {
                        v.as_object()
                            .and_then(|m| {
                                m.get(&locale)
                                    .or_else(|| m.get("zh"))
                                    .or_else(|| m.get("en"))
                            })
                            .and_then(|v| v.as_str())
                    })
                    .unwrap_or("");
                rows.push((
                    value.get("priority").and_then(|v| v.as_i64()).unwrap_or(50),
                    name.into(),
                    Row {
                        name: name.into(),
                        commands: legacy_command_count(name).to_string(),
                        description: format!("{desc}（未迁移）"),
                    },
                    true,
                ));
            }
        }
    }
    progress.finish_and_clear();
    // A list is for finding things, so read it alphabetically; priority order
    // stays where it actually matters (completion ranking).
    rows.sort_by(|a, b| a.1.cmp(&b.1));
    if rows.is_empty() {
        ui::note("没有发现插件");
        return 0;
    }

    let enabled = rows.iter().filter(|r| r.3).count();
    let disabled = rows.len().saturating_sub(enabled);
    let formal = registry.plugins.len();
    let legacy = rows.len().saturating_sub(formal);
    let command_count: usize = registry
        .plugins
        .iter()
        .map(|p| p.commands(&locale).iter().filter(|c| !c.hidden).count())
        .sum();

    // One line per plugin: drop the columns that never varied (version, state)
    // and clip the description instead of letting it wrap the row.
    let budget = ui::width().saturating_sub(24).max(16);
    let listed: Vec<Row> = rows
        .into_iter()
        .map(|(_, _, mut row, _)| {
            row.description = ui::truncate(&row.description, budget);
            row
        })
        .collect();
    let mut table = ui::table(listed);
    ui::right(&mut table, 1);
    ui::print(&table);
    let mut summary = format!("{formal} 个插件 · {command_count} 条命令 · 启用 {enabled}",);
    if disabled > 0 {
        summary.push_str(&format!(" · 禁用 {disabled}"));
    }
    ui::note(&summary);

    #[derive(tabled::Tabled)]
    struct Stat {
        #[tabled(rename = "统计项")]
        item: String,
        #[tabled(rename = "总数")]
        total: String,
        #[tabled(rename = "说明")]
        detail: String,
    }
    let stats = vec![
        Stat {
            item: "版本".into(),
            total: plugin_versions(&registry),
            detail: "全部正式插件一致".into(),
        },
        Stat {
            item: "插件库存".into(),
            total: rows_total(formal, legacy),
            detail: format!("正式 {formal} · legacy {legacy} · menubar 已移除"),
        },
        Stat {
            item: "GS6 可执行命令".into(),
            total: command_count.to_string(),
            detail: "来自正式 plugin.toml/describe".into(),
        },
        Stat {
            item: "GS5.2 命令基线".into(),
            total: "260".into(),
            detail: "兼容性对照基线".into(),
        },
    ];
    let mut stats = ui::table(stats);
    ui::right(&mut stats, 1);
    ui::print(&stats);
    0
}

fn rows_total(formal: usize, legacy: usize) -> String {
    (formal + legacy).to_string()
}

/// The version shared by the formal plugins, or a short "mixed" summary when
/// they disagree — the inventory reports it once instead of on every row.
fn plugin_versions(registry: &Registry) -> String {
    let mut versions: Vec<&str> = registry
        .plugins
        .iter()
        .map(|p| p.manifest.version.as_str())
        .collect();
    versions.sort_unstable();
    versions.dedup();
    match versions.as_slice() {
        [] => "—".into(),
        [only] => (*only).to_string(),
        many => format!("{} 个版本", many.len()),
    }
}

/// Show one GS 6.0 manifest and its declared/runtime command tree.
fn cmd_plugin_info(args: &[String]) -> i32 {
    let picked;
    let name: &str = match args.first() {
        Some(name) => name,
        // In front of a person, offer the inventory instead of a usage error.
        None => match pick_plugin("查看") {
            Some(name) => {
                picked = name;
                &picked
            }
            None => {
                eprintln!("用法: gs plugin info <插件名>");
                return 2;
            }
        },
    };
    let p = match Registry::find_checked(&engine_roots(), name) {
        Ok(Some(p)) => p,
        Ok(None) => {
            eprintln!("错误: GS6 没有可管理的插件 '{name}'（不存在或尚未迁移）");
            return 1;
        }
        Err(e) => {
            eprintln!("错误: 插件 '{name}' 的 plugin.toml 无效：\n  {e}");
            return 1;
        }
    };
    let locale = detect_locale();
    // Same reason as `plugin list`: a T2/T3 `describe` may need a process.
    let progress = ui::spinner("读取插件命令…");
    let commands = p.commands(&locale);
    progress.finish_and_clear();
    if args.len() > 1 {
        let rest = &args[1..];
        if let Some((_command, _)) = (1..=rest.len()).rev().find_map(|take| {
            let joined = rest[..take].join(".");
            commands
                .iter()
                .find(|c| !c.hidden && c.name == joined)
                .map(|c| (c, take))
        }) {
            // A complete command path turns `plugin info` into an execution
            // shortcut. This keeps group-level `plugin info <name> <group>`
            // useful for browsing while ensuring a full path such as
            // `plugin info android app list-3rd` actually runs the command.
            return dispatch_manifest(&p, rest);
        }
    }
    let group = (args.len() > 1).then(|| args[1..].join("."));
    if let Some(group) = group {
        let prefix = format!("{group}.");
        let group_cmds: Vec<CommandSpec> = commands
            .iter()
            .filter(|c| !c.hidden && c.name.starts_with(&prefix))
            .cloned()
            .collect();
        if group_cmds.is_empty() {
            eprintln!("错误: 插件 '{}' 没有命令组 '{}'", name, group);
            return 1;
        }
        return print_plugin_overview(&p, &group_cmds, &locale, Some(&group));
    }
    print_plugin_overview(&p, &commands, &locale, None)
}

/// Toggle the persisted `enabled` field for one GS 6.0 manifest.
fn cmd_plugin_toggle(args: &[String], enabled: bool) -> i32 {
    let picked;
    let name: &str = match args.first() {
        Some(name) => name,
        None => {
            let action = if enabled { "启用" } else { "禁用" };
            match pick_plugin(action) {
                Some(name) => {
                    picked = name;
                    &picked
                }
                None => {
                    eprintln!(
                        "用法: gs plugin {} <插件名>",
                        if enabled { "enable" } else { "disable" }
                    );
                    return 2;
                }
            }
        }
    };
    let p = match Registry::find_checked(&engine_roots(), name) {
        Ok(Some(p)) => p,
        Ok(None) => {
            eprintln!("错误: GS6 没有可管理的插件 '{name}'（不存在或尚未迁移）");
            return 1;
        }
        Err(e) => {
            eprintln!("错误: 插件 '{name}' 的 plugin.toml 无效：\n  {e}");
            return 1;
        }
    };
    let manifest_path = p.dir.join("plugin.toml");
    let Ok(text) = std::fs::read_to_string(&manifest_path) else {
        eprintln!("错误: 读取 {} 失败", manifest_path.display());
        return 1;
    };
    let updated = set_manifest_enabled(&text, enabled);
    if let Err(e) = gs_core::manifest::PluginManifest::parse(&updated) {
        eprintln!("错误: 更新后的 plugin.toml 校验失败：{e}");
        return 1;
    }
    if let Err(e) = std::fs::write(&manifest_path, updated) {
        eprintln!("错误: 写入 {} 失败：{e}", manifest_path.display());
        return 1;
    }
    if let Err(e) = sync_legacy_config(&p.dir, name, enabled) {
        eprintln!("警告: plugin.toml 已更新，但旧版配置同步失败：{e}");
    }
    println!(
        "插件 '{}' 已{}",
        name,
        if enabled { "启用" } else { "禁用" }
    );
    0
}

/// Keep the legacy Python CLI's config view aligned while migration is ongoing.
/// The manifest remains authoritative for Rust dispatch; this mirror prevents
/// the Python fallback from showing stale state.
fn sync_legacy_config(plugin_dir: &Path, name: &str, enabled: bool) -> Result<(), String> {
    let mut candidates = Vec::new();
    if let Some(explicit) = std::env::var_os("GS_CONFIG_FILE") {
        candidates.push(PathBuf::from(explicit));
    }
    if let Some(home) = gs_core::home_dir() {
        candidates.push(home.join(".config/global-scripts/config/gs.json"));
    }
    if let Some(root) = std::env::var_os("GS_ROOT") {
        candidates.push(PathBuf::from(root).join("config/gs.json"));
    }
    let Some(path) = candidates.into_iter().find(|p| p.is_file()) else {
        return Ok(());
    };
    sync_legacy_config_file(&path, plugin_dir, name, enabled)
}

fn sync_legacy_config_file(
    path: &Path,
    plugin_dir: &Path,
    name: &str,
    enabled: bool,
) -> Result<(), String> {
    let text = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let mut value: serde_json::Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "配置根节点不是 JSON 对象".to_string())?;
    let section = if plugin_dir.components().any(|c| c.as_os_str() == "custom") {
        "custom_plugins"
    } else {
        "system_plugins"
    };
    let map = object
        .entry(section)
        .or_insert_with(|| serde_json::json!({}));
    let map = map
        .as_object_mut()
        .ok_or_else(|| format!("配置字段 {section} 不是对象"))?;
    map.insert(name.to_string(), serde_json::Value::Bool(enabled));
    let serialized = serde_json::to_string_pretty(&value).map_err(|e| e.to_string())? + "\n";
    std::fs::write(path, serialized).map_err(|e| e.to_string())
}

fn set_manifest_enabled(text: &str, enabled: bool) -> String {
    let value = if enabled { "true" } else { "false" };
    let mut found = false;
    let lines: Vec<&str> = text.lines().collect();
    let mut out = Vec::with_capacity(lines.len() + 1);
    let mut inserted = false;
    for line in lines {
        let trimmed = line.trim_start();
        if trimmed.starts_with('[') && !inserted && !found {
            out.push(format!("enabled = {value}"));
            inserted = true;
        }
        let replacement = if trimmed.starts_with("enabled")
            && trimmed["enabled".len()..].trim_start().starts_with('=')
        {
            found = true;
            format!("enabled = {value}")
        } else {
            line.to_string()
        };
        out.push(replacement);
    }
    if !found && !inserted {
        out.push(format!("enabled = {value}"));
    }
    let mut result = out.join("\n");
    if text.ends_with('\n') {
        result.push('\n');
    }
    result
}

// ---- `gs plugin migrate` (legacy plugin.json → plugin.toml) ----
//
// Legacy-only plugin management still delegates to Python. This command reads a
// legacy plugin dir, runs the §1.4 transform, then
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
                println!(
                    "  默认打印到 stdout；--write 写入 <目录>/plugin.toml（不覆盖已存在文件）。"
                );
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
    let (dir, manifest) = if given
        .file_name()
        .map(|f| f == "plugin.json")
        .unwrap_or(false)
    {
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
    (
        "init",
        "初始化这台机器（按 config/init.toml 的步骤清单）",
        &[],
    ),
    (
        "plugin",
        "插件管理（启用/禁用/列表/详情/migrate）",
        &["disable", "enable", "info", "list", "migrate"],
    ),
    ("status", "查看状态", &[]),
    ("doctor", "环境体检", &[]),
    ("refresh", "刷新命令索引", &[]),
    (
        "completions",
        "生成 Tab 补全脚本",
        &["bash", "zsh", "fish", "nushell", "powershell"],
    ),
    (
        "shell-init",
        "生成 gs 外壳函数（cd 集成）",
        &["bash", "zsh", "fish", "powershell"],
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

    // `plugin info <plugin> <group>` is a management command, but its final
    // argument should complete from the same manifest command tree as direct
    // plugin dispatch.
    if completed.len() == 2 && completed[0] == "plugin" && completed[1] == "info" {
        let mut out = String::new();
        for p in registry.enabled() {
            let desc =
                gs_core::manifest::pick(&p.manifest.description, &locale).unwrap_or_default();
            out.push_str(&p.manifest.name);
            if !desc.is_empty() {
                out.push('\t');
                out.push_str(&desc);
            }
            out.push('\n');
        }
        out.push_str(":4\n");
        print!("{out}");
        return 0;
    }
    if completed.len() >= 3 && completed[0] == "plugin" && completed[1] == "info" {
        if let Some(name) = completed.get(2) {
            if let Some(p) = registry.enabled().find(|p| p.manifest.name == *name) {
                let cmds = p.commands(&locale);
                // Once the words after the plugin name form a complete
                // command, switch to the normal plugin completion path. This
                // is important for `plugin info <p> <group> <command> [args]`:
                // the command is executable, and its flags/positional values
                // must complete exactly like `<p> <group> <command> [args]`.
                let info_rest = &completed[3..];
                let full_command = (1..=info_rest.len()).rev().find_map(|take| {
                    let joined = info_rest[..take].join(".");
                    cmds.iter()
                        .find(|c| !c.hidden && c.name == joined)
                        .map(|_| take)
                });
                if full_command.is_some() {
                    let mut direct = vec![name.clone()];
                    direct.extend(info_rest.iter().cloned());
                    let comp = engine::complete(&registry, SYSTEM_CMDS, &direct, &locale);
                    let mut out = String::new();
                    for c in &comp.candidates {
                        out.push_str(&c.value);
                        if let Some(desc) = &c.description {
                            out.push('\t');
                            out.push_str(desc);
                        }
                        out.push('\n');
                    }
                    out.push_str(&format!(":{}\n", comp.directive));
                    print!("{out}");
                    return 0;
                }
                let mut out = String::new();
                if let Some(group) = completed.get(3) {
                    let prefix = format!("{}.", group);
                    for cmd in cmds
                        .iter()
                        .filter(|c| !c.hidden && c.name.starts_with(&prefix))
                    {
                        out.push_str(cmd.leaf());
                        if let Some(desc) = gs_core::manifest::pick(&cmd.summary, &locale) {
                            out.push('\t');
                            out.push_str(&desc);
                        }
                        out.push('\n');
                    }
                } else {
                    let groups = cmds
                        .iter()
                        .filter(|c| c.name.contains('.'))
                        .filter_map(|c| c.name.split('.').next())
                        .collect::<std::collections::BTreeSet<_>>();
                    for g in groups {
                        let desc = p
                            .manifest
                            .groups
                            .get(g)
                            .and_then(|d| gs_core::manifest::pick(d, &locale))
                            .unwrap_or_else(|| format!("{} 命令组", g));
                        out.push_str(g);
                        out.push('\t');
                        out.push_str(&desc);
                        out.push('\n');
                    }
                }
                out.push_str(":4\n");
                print!("{out}");
                return 0;
            }
        }
    }

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

/// Best-effort UI locale for completion descriptions: `GS_LANG` / `GS_LANGUAGE` → `LC_ALL` →
/// `LC_MESSAGES` → `LANG`, reduced to the language subtag (`zh_CN.UTF-8` → `zh`).
/// Defaults to "en"; `completion::complete` still falls back en → zh → any.
fn detect_locale() -> String {
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
fn cmd_completions(args: &[String]) -> i32 {
    // `--install` 把补全写到该 shell 的标准位置(而不是只打印),这样用户不用
    // 自己重定向;不带它时保持"生成器"语义(可管道)。
    let install = args.iter().any(|a| a == "--install");
    let shell = args
        .iter()
        .find(|a| !a.starts_with("--"))
        .map(String::as_str);
    let script = match shell {
        Some("bash") => COMP_BASH,
        Some("zsh") => COMP_ZSH,
        Some("fish") => COMP_FISH,
        Some("nu" | "nushell") => COMP_NUSHELL,
        Some("pwsh" | "powershell") => COMP_POWERSHELL,
        None if install => {
            // 一并装到三个常用 shell(devenv 那套里也只有这三个有 vendor 目录)。
            let mut failures = 0;
            for shell in ["bash", "zsh", "fish"] {
                let argv: Vec<String> =
                    vec!["completions".into(), shell.into(), "--install".into()];
                if run(&argv) != 0 {
                    failures += 1;
                }
            }
            return if failures == 0 { 0 } else { 1 };
        }
        _ => {
            eprintln!("用法: gs completions <bash|zsh|fish|nushell|powershell> [--install]");
            eprintln!("      gs completions --install          # 装到 bash/zsh/fish 的标准位置");
            eprintln!();
            eprintln!("启用（选你的 shell）:");
            eprintln!("  fish: gs completions fish --install");
            eprintln!("  zsh:  gs completions zsh --install");
            eprintln!("  bash: gs completions bash --install");
            eprintln!();
            eprintln!("补全候选由 'gs __complete' 原生计算，无 jq 依赖。");
            return 2;
        }
    };
    let name = command_name();
    let rendered = render_completion_script(shell.unwrap_or_default(), script, &name);
    if !install {
        print!("{rendered}");
        return 0;
    }
    match completion_install_path(shell.unwrap_or_default(), &name) {
        Some(path) => {
            if let Some(parent) = path.parent() {
                if let Err(error) = std::fs::create_dir_all(parent) {
                    eprintln!("错误: 建目录 {} 失败: {error}", parent.display());
                    return 1;
                }
            }
            if let Err(error) = std::fs::write(&path, rendered) {
                eprintln!("错误: 写入 {} 失败: {error}", path.display());
                return 1;
            }
            ui::note(&format!("补全已安装: {}", path.display()));
            ui::note("重开终端(或 source 相应配置)后生效。");
            0
        }
        None => {
            eprintln!(
                "错误: {} 没有约定的安装位置,请用 `gs completions {} > <文件>` 自行放置",
                shell.unwrap_or("?"),
                shell.unwrap_or("")
            );
            2
        }
    }
}

/// Where a shell expects its user-level completion file, following the same XDG
/// locations the installer uses. `None` for shells that must be sourced.
fn completion_install_path(shell: &str, name: &str) -> Option<PathBuf> {
    let data = std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| gs_core::home_dir().map(|home| home.join(".local/share")))?;
    match shell {
        "bash" => Some(data.join("bash-completion/completions").join(name)),
        "zsh" => Some(data.join("zsh/site-functions").join(format!("_{name}"))),
        "fish" => Some(
            data.join("fish/vendor_completions.d")
                .join(format!("{name}.fish")),
        ),
        _ => None,
    }
}

fn render_completion_script(shell: &str, script: &str, requested_name: &str) -> String {
    let name = if !requested_name.is_empty()
        && requested_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
    {
        requested_name
    } else {
        "gs"
    };
    if name == "gs" {
        return script.to_string();
    }
    let ident = name.replace('-', "_");
    match shell {
        "bash" => script
            .replace("_gs_complete", &format!("_{ident}_complete"))
            .replace(
                &format!("complete -F _{ident}_complete gs"),
                &format!("complete -F _{ident}_complete {name}"),
            ),
        "zsh" => script
            .replace("_gs_complete", &format!("_{ident}_complete"))
            .replace(
                &format!("compdef _{ident}_complete gs"),
                &format!("compdef _{ident}_complete {name}"),
            ),
        "fish" => script
            .replace("__gs_complete", &format!("__{ident}_complete"))
            .replace("complete -c gs ", &format!("complete -c {name} ")),
        "nu" | "nushell" => script
            .replace("== \"gs\"", &format!("== \"{name}\""))
            .replace("(^gs __complete", &format!("(^{name} __complete")),
        "pwsh" | "powershell" => script
            .replace("-CommandName gs ", &format!("-CommandName {name} "))
            .replace("(gs __complete", &format!("({name} __complete")),
        _ => script.to_string(),
    }
}

/// `gs shell-init <shell>` — emit the `gs` shell *function* that gives `cd`
/// commands their teeth: it runs the real binary with `$GS_CD_FILE` pointed at a
/// temp file and, if the command wrote a path there, performs the `cd` in the
/// caller's shell. Completion is fast-pathed (no temp file) so per-Tab latency
/// is untouched.
fn cmd_shell_init(args: &[String]) -> i32 {
    let script = match args.first().map(String::as_str) {
        Some("bash") | Some("zsh") => SHELLINIT_POSIX,
        Some("fish") => SHELLINIT_FISH,
        Some("pwsh" | "powershell") => SHELLINIT_POWERSHELL,
        _ => {
            eprintln!("用法: gs shell-init <bash|zsh|fish|powershell>");
            eprintln!();
            eprintln!(
                "作用: 定义 gs 外壳函数，让 `cd` 类命令（如 navigator）真正切换当前 shell 的目录。"
            );
            eprintln!("启用（选你的 shell）:");
            eprintln!(
                "  fish: gs shell-init fish > ~/.config/fish/conf.d/gs.fish   # 新开终端生效"
            );
            eprintln!("  zsh:  echo 'source <(gs shell-init zsh)'  >> ~/.zshrc");
            eprintln!("  bash: echo 'source <(gs shell-init bash)' >> ~/.bashrc");
            eprintln!("  pwsh: gs shell-init powershell >> $PROFILE");
            eprintln!();
            eprintln!("（nushell 的 cd 集成待支持）");
            return 2;
        }
    };
    let name = command_name();
    let binary = std::env::var("GS_COMMAND_PATH").unwrap_or_else(|_| name.clone());
    if args.first().map(String::as_str) == Some("fish") {
        print!(
            "{}",
            script
                .replace("function gs\n", &format!("function {name}\n"))
                .replace("__GS_BINARY__", &fish_quote(&binary))
        );
        return 0;
    }
    if matches!(
        args.first().map(String::as_str),
        Some("pwsh" | "powershell")
    ) {
        print!(
            "{}",
            script
                .replace("__GS_FUNCTION__", &name)
                .replace("__GS_BINARY__", &powershell_quote(&binary))
        );
        return 0;
    }
    let command = format!("command {}", shell_quote(&binary));
    let script = if name == "gs" {
        script.replace("command gs", &command)
    } else {
        script
            .replace("function gs\n", &format!("function {name}\n"))
            .replace("command gs", &command)
            .replace("gs() {", &format!("{name}() {{"))
    };
    print!("{script}");
    0
}

#[cfg(test)]
mod tests {
    use super::{distribution_root_from_exe, set_manifest_enabled, sync_legacy_config_file};

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
    fn syncs_legacy_config_for_manifest_toggle() {
        let root = std::env::temp_dir().join(format!("gs-config-sync-{}", std::process::id()));
        let _ = std::fs::create_dir_all(root.join("config"));
        let config = root.join("config/gs.json");
        std::fs::write(&config, r#"{"system_plugins":{}}"#).unwrap();
        sync_legacy_config_file(&config, &root.join("plugins/demo"), "demo", false).unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(config).unwrap()).unwrap();
        assert_eq!(value["system_plugins"]["demo"], false);
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

// Fish's `command` is a builtin, so it cannot sit behind `env` (an external
// program) — that mismatch made every `gs` call fail with
// "env: 'command': No such file or directory". Export through `env` and exec
// the binary directly instead; `command` is still used where it is a builtin.
const SHELLINIT_FISH: &str = r#"# gs fish 外壳集成（cd 支持）。启用：gs shell-init fish > ~/.config/fish/conf.d/gs.fish
function gs
    # 补全对延迟敏感且无 cd 副作用——快速直通，不建临时文件。
    if test (count $argv) -gt 0; and test "$argv[1]" = __complete
        command __GS_BINARY__ $argv
        return $status
    end
    set -l __gs_cd (command mktemp)
    set -l __gs_env (command mktemp)
    env GS_CD_FILE=$__gs_cd GS_ENV_FILE=$__gs_env __GS_BINARY__ $argv
    set -l __gs_status $status
    if test -s $__gs_cd
        builtin cd (command cat $__gs_cd)
    end
    while read -l __gs_effect
        set -l __gs_parts (string split -m 2 \t -- $__gs_effect)
        if test "$__gs_parts[1]" = S
            set -gx $__gs_parts[2] "$__gs_parts[3]"
        else if test "$__gs_parts[1]" = U
            set -e $__gs_parts[2]
        end
    end < $__gs_env
    command rm -f $__gs_cd $__gs_env
    return $__gs_status
end
"#;

const SHELLINIT_POSIX: &str = r#"# gs bash/zsh 外壳集成（cd 支持）。
#   bash: echo 'source <(gs shell-init bash)' >> ~/.bashrc
#   zsh:  echo 'source <(gs shell-init zsh)'  >> ~/.zshrc
gs() {
    # Completion is latency-sensitive and has no cd side-effect — fast-path it.
    if [ "$1" = __complete ]; then
        command gs "$@"
        return $?
    fi
    local __gs_cd
    __gs_cd="$(mktemp)" || { command gs "$@"; return $?; }
    local __gs_env
    __gs_env="$(mktemp)" || { command rm -f "$__gs_cd"; command gs "$@"; return $?; }
    export GS_CD_FILE="$__gs_cd"
    export GS_ENV_FILE="$__gs_env"
    command gs "$@"
    local __gs_status=$?
    if [ -s "$__gs_cd" ]; then
        builtin cd "$(cat "$__gs_cd")"
    fi
    while IFS="$(printf '\t')" read -r __gs_action __gs_key __gs_value; do
        case "$__gs_action" in
            S) export "$__gs_key=$__gs_value" ;;
            U) unset "$__gs_key" ;;
        esac
    done < "$__gs_env"
    command rm -f "$__gs_cd" "$__gs_env"
    return $__gs_status
}
"#;

const SHELLINIT_POWERSHELL: &str = r#"# gs PowerShell shell integration (cd + environment effects).
function global:__GS_FUNCTION__ {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromRemainingArguments = $true)]
        [string[]] $GsArgs
    )

    if ($GsArgs.Count -gt 0 -and $GsArgs[0] -eq '__complete') {
        & __GS_BINARY__ @GsArgs
        return
    }

    $cdFile = [System.IO.Path]::GetTempFileName()
    $envFile = [System.IO.Path]::GetTempFileName()
    $oldCdFile = [Environment]::GetEnvironmentVariable('GS_CD_FILE', 'Process')
    $oldEnvFile = [Environment]::GetEnvironmentVariable('GS_ENV_FILE', 'Process')
    $status = 1
    try {
        [Environment]::SetEnvironmentVariable('GS_CD_FILE', $cdFile, 'Process')
        [Environment]::SetEnvironmentVariable('GS_ENV_FILE', $envFile, 'Process')
        & __GS_BINARY__ @GsArgs
        $status = $LASTEXITCODE

        if ((Get-Item -LiteralPath $cdFile).Length -gt 0) {
            $target = (Get-Content -LiteralPath $cdFile -Raw).Trim()
            if ($target) { Set-Location -LiteralPath $target }
        }

        foreach ($line in [System.IO.File]::ReadAllLines($envFile)) {
            $parts = $line.Split("`t", 3)
            if ($parts.Length -ge 2 -and $parts[0] -eq 'U') {
                [Environment]::SetEnvironmentVariable($parts[1], $null, 'Process')
            } elseif ($parts.Length -eq 3 -and $parts[0] -eq 'S') {
                [Environment]::SetEnvironmentVariable($parts[1], $parts[2], 'Process')
            }
        }
    } finally {
        [Environment]::SetEnvironmentVariable('GS_CD_FILE', $oldCdFile, 'Process')
        [Environment]::SetEnvironmentVariable('GS_ENV_FILE', $oldEnvFile, 'Process')
        Remove-Item -LiteralPath $cdFile, $envFile -Force -ErrorAction SilentlyContinue
    }
    $global:LASTEXITCODE = $status
}
"#;

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
    done < <(command "${COMP_WORDS[0]}" __complete "${completed[@]}" 2>/dev/null)
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
    lines=(${(f)"$(command "$words[1]" __complete ${completed} 2>/dev/null)"})
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
    set -l executable $completed[1]
    set -l directive 0
    for line in (command $executable __complete $completed[2..-1] 2>/dev/null)
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
