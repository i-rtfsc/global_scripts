//! Front-door system commands: `gs status`, `gs doctor` and `gs refresh`.

use crate::{detect_locale, engine_roots, ui};
use gs_core::index::Registry;
use std::path::{Path, PathBuf};

pub(crate) fn cmd_status() -> i32 {
    let registry = Registry::discover(&engine_roots());
    let enabled = registry
        .plugins
        .iter()
        .filter(|p| p.manifest.enabled)
        .count();
    let disabled = registry.plugins.len().saturating_sub(enabled);
    let commands: usize = registry
        .plugins
        .iter()
        .map(|p| {
            p.commands(&detect_locale())
                .iter()
                .filter(|c| !c.hidden)
                .count()
        })
        .sum();

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
            key: "插件根目录".into(),
            value: format!("{} 个", engine_roots().len()),
        },
        Fact {
            key: "可执行命令".into(),
            value: format!("{commands} 条"),
        },
    ];
    let table = ui::facts("GS 6.0 状态", rows);
    ui::print(&table);
    0
}

pub(crate) fn cmd_doctor() -> i32 {
    let roots = engine_roots();
    let mut manifest_files = 0usize;
    let mut invalid = Vec::new();
    let mut missing_entries = Vec::new();
    let mut runtimes: Vec<String> = Vec::new();
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
                    Ok(manifest) => {
                        // T2+ plugins need an interpreter; record it so doctor can
                        // prove the runtime is actually on PATH (nothing else
                        // ever told the user why every command failed).
                        if manifest.enabled
                            && !manifest.tier.is_declarative()
                            && !manifest.runtime.is_empty()
                        {
                            runtimes.push(manifest.runtime.clone());
                        }
                        if !manifest.entry.is_empty() {
                            let entry = entry.path().join(&manifest.entry);
                            if !entry.is_file() {
                                missing_entries.push(format!("{}: entry 不存在", entry.display()));
                            }
                        }
                    }
                    Err(e) => invalid.push(format!("{}: {e}", path.display())),
                }
            } else {
                invalid.push(format!("{}: 无法读取", path.display()));
            }
        }
    }
    runtimes.sort();
    runtimes.dedup();
    let missing_runtimes: Vec<String> = runtimes
        .iter()
        .filter(|runtime| {
            let program = gs_core::index::runtime_program(runtime);
            !Path::new(&gs_core::index::resolve_program(&program)).is_absolute()
        })
        .cloned()
        .collect();
    let root_ok = std::env::var_os("GS_ROOT")
        .map(|p| Path::new(&p).is_dir())
        .unwrap_or(false);
    let sdk_ok = std::env::var_os("GS_ROOT")
        .map(|p| PathBuf::from(p).join("sdk/python/gs_plugin").is_dir())
        .unwrap_or(false);
    let all_ok =
        root_ok && invalid.is_empty() && missing_entries.is_empty() && missing_runtimes.is_empty();
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
            item: "插件运行时".into(),
            result: if runtimes.is_empty() {
                "无需解释器（全部 T1 声明式）".into()
            } else if missing_runtimes.is_empty() {
                format!("{} 可用", runtimes.join(" / "))
            } else {
                format!(
                    "缺少 {}（T2/T3 插件无法运行）",
                    missing_runtimes.join(" / ")
                )
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
                if referenced { "是" } else { "否" },
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

pub(crate) fn cmd_refresh(args: &[String]) -> i32 {
    let _ = args;
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

pub(crate) fn count_invalid_manifests(roots: &[PathBuf]) -> usize {
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
