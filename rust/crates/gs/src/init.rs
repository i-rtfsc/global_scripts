//! `gs init` — run the machine-provisioning step list from `config/init.toml`.

use crate::{command_name, detect_locale, engine_roots, run, ui};
use gs_core::index::Registry;
use std::path::PathBuf;

pub(crate) fn cmd_init(args: &[String]) -> i32 {
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
