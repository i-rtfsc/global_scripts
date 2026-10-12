//! `gs plugin …` — the plugin management surface (list / info / enable /
//! disable / migrate) and the shared plugin overview renderer.

use crate::dispatch::dispatch_manifest;
use crate::{command_name, detect_locale, engine_roots, ui};
use gs_core::index::{LoadedManifest, Registry};
use gs_core::manifest::CommandSpec;
use std::path::Path;

pub(crate) fn cmd_plugin_unknown(command: &str) -> i32 {
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
pub(crate) fn pick_plugin(action: &str) -> Option<String> {
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
pub(crate) fn show_in_plugin_table(plugin: &str, spec: &CommandSpec) -> bool {
    let _ = plugin;
    !spec.hidden
}

pub(crate) fn command_usage(command: &str, spec: &CommandSpec) -> String {
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

pub(crate) fn print_plugin_overview(
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
pub(crate) fn cmd_plugin_list(_args: &[String]) -> i32 {
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
            total: formal.to_string(),
            detail: format!("正式插件 {formal} 个 · 全部为 plugin.toml"),
        },
        Stat {
            item: "GS6 可执行命令".into(),
            total: command_count.to_string(),
            detail: "来自正式 plugin.toml/describe".into(),
        },
    ];
    let mut stats = ui::table(stats);
    ui::right(&mut stats, 1);
    ui::print(&stats);
    0
}

/// The version shared by the formal plugins, or a short "mixed" summary when
/// they disagree — the inventory reports it once instead of on every row.
pub(crate) fn plugin_versions(registry: &Registry) -> String {
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
pub(crate) fn cmd_plugin_info(args: &[String]) -> i32 {
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
pub(crate) fn cmd_plugin_toggle(args: &[String], enabled: bool) -> i32 {
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
    println!(
        "插件 '{}' 已{}",
        name,
        if enabled { "启用" } else { "禁用" }
    );
    0
}

pub(crate) fn set_manifest_enabled(text: &str, enabled: bool) -> String {
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

pub(crate) fn cmd_plugin_migrate(args: &[String]) -> i32 {
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
