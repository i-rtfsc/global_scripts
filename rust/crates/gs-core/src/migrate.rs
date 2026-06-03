//! `gs plugin migrate`: turn a legacy `plugin.json` (+ `commands.json`, and any
//! subplugin `commands.json`) into a 6.0 `plugin.toml`. Pure transform per the
//! §1.4 mapping table — the `gs` front door does the file IO and printing.
//!
//! What maps cleanly (and is emitted):
//!   - all metadata (name/version/description/author/…/priority/enabled);
//!   - `type` → `tier`+`runtime` (json→declarative, shell→script+bash,
//!     python/hybrid→script+python);
//!   - every `commands.json` command → a declarative `[[commands]]` with
//!     `shell = true` (the legacy `command` was a shell line), its program
//!     hoisted into `[capabilities].exec`;
//!   - subplugins → `sub.command` namespaced command names.
//!
//! What can't be auto-extracted is surfaced as a *note*, never silently dropped:
//! Python `@plugin_function` command trees — a script-tier plugin answers
//! `describe` at runtime via the SDK instead (the migration emits the script
//! skeleton and says so).

use serde::Deserialize;
use std::collections::BTreeSet;

/// The legacy `plugin.json` manifest.
#[derive(Debug, Deserialize)]
pub struct LegacyPlugin {
    pub name: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub author: String,
    #[serde(default)]
    pub homepage: String,
    #[serde(default)]
    pub license: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub description: Bilingual,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub entry: String,
    #[serde(default)]
    pub priority: Option<i64>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub subplugins: Vec<LegacySub>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Bilingual {
    #[serde(default)]
    pub zh: String,
    #[serde(default)]
    pub en: String,
}

#[derive(Debug, Deserialize)]
pub struct LegacySub {
    pub name: String,
    #[serde(default)]
    pub entry: String,
}

#[derive(Debug, Deserialize)]
struct LegacyCommand {
    #[serde(default)]
    command: String,
    #[serde(default)]
    usage: String,
    #[serde(default)]
    examples: Vec<String>,
    #[serde(default)]
    description: Bilingual,
}

/// The legacy files the front door has read for one plugin.
pub struct MigrateInputs {
    pub plugin_json: String,
    pub main_commands_json: Option<String>,
    /// `(subplugin name, that subplugin's commands.json text)`, in order.
    pub sub_commands: Vec<(String, String)>,
}

/// The generated manifest plus any human-review notes.
pub struct MigrateOutput {
    pub toml: String,
    pub notes: Vec<String>,
}

/// Parse just the legacy manifest — the front door uses this to learn the
/// subplugin list (so it can read each subplugin's `commands.json`) before
/// calling [`migrate`].
pub fn parse_plugin_json(text: &str) -> Result<LegacyPlugin, String> {
    serde_json::from_str(text).map_err(|e| format!("plugin.json 解析失败：{e}"))
}

/// One command in the emitted manifest.
struct CmdOut {
    name: String,
    summary: Bilingual,
    usage: String,
    examples: Vec<String>,
    run: String,
}

/// Transform the legacy inputs into a `plugin.toml` string + review notes.
pub fn migrate(input: &MigrateInputs) -> Result<MigrateOutput, String> {
    let p = parse_plugin_json(&input.plugin_json)?;
    if p.name.trim().is_empty() {
        return Err("plugin.json 缺少 name".into());
    }
    let mut notes = Vec::new();

    // Declarative commands from main + each subplugin's commands.json, in order.
    let mut cmds: Vec<CmdOut> = Vec::new();
    if let Some(text) = &input.main_commands_json {
        cmds.extend(parse_commands("", text, &mut notes)?);
    }
    for (sub, text) in &input.sub_commands {
        cmds.extend(parse_commands(sub, text, &mut notes)?);
    }

    // Tier: declarative when we have declarative source (commands.json), else a
    // script plugin whose tree comes from runtime `describe`. `type` only picks
    // the script runtime.
    let has_inline = !cmds.is_empty();
    let (tier, runtime) = match (has_inline, p.kind.as_str()) {
        (true, _) => ("declarative", ""),
        (false, "shell") => ("script", "bash"),
        // python / hybrid / unknown → a Python script plugin.
        (false, _) => ("script", "python"),
    };
    if p.kind == "hybrid" {
        notes.push(
            "hybrid 已折叠：commands.json 命令迁为声明式；Python 命令请由运行时 describe（接入新 SDK）补齐"
                .into(),
        );
    }
    if tier == "script" {
        notes.push(
            "脚本插件命令树由运行时 describe 提供——按 sdk/python 接入 describe/complete/invoke 后即可列命令"
                .into(),
        );
        if p.entry.trim().is_empty() {
            notes.push("脚本插件缺少 entry，请手工补全入口文件".into());
        }
    }

    // exec allowlist for declarative commands: the first word of each shell line.
    let mut exec: BTreeSet<String> = BTreeSet::new();
    if tier == "declarative" {
        for c in &cmds {
            if let Some(prog) = c.run.split_whitespace().next() {
                exec.insert(prog.to_string());
            }
        }
    }

    // ---- emit TOML (bare keys first, then tables — TOML's ordering rule) ----
    let mut out = String::new();
    kv(&mut out, "name", &esc(&p.name));
    if !p.version.is_empty() {
        kv(&mut out, "version", &esc(&p.version));
    }
    kv(&mut out, "tier", &esc(tier));
    if !runtime.is_empty() {
        kv(&mut out, "runtime", &esc(runtime));
    }
    if tier != "declarative" && !p.entry.is_empty() {
        kv(&mut out, "entry", &esc(&p.entry));
    }
    kv(&mut out, "description", &bilingual(&p.description, &p.name));
    if !p.category.is_empty() {
        kv(&mut out, "category", &esc(&p.category));
    }
    if let Some(pr) = p.priority {
        kv(&mut out, "priority", &pr.to_string());
    }
    if p.enabled == Some(false) {
        kv(&mut out, "enabled", "false");
    }
    if !p.author.is_empty() {
        kv(&mut out, "author", &esc(&p.author));
    }
    if !p.homepage.is_empty() {
        kv(&mut out, "homepage", &esc(&p.homepage));
    }
    if !p.license.is_empty() {
        kv(&mut out, "license", &esc(&p.license));
    }
    if !p.keywords.is_empty() {
        kv(&mut out, "keywords", &str_array(&p.keywords));
    }
    if tier != "declarative" {
        kv(&mut out, "describe_cache", &esc("runtime"));
    }
    kv(&mut out, "protocol", "1");

    if !exec.is_empty() {
        out.push_str("\n[capabilities]\n");
        let v: Vec<String> = exec.into_iter().collect();
        kv(&mut out, "exec", &str_array(&v));
    }

    for c in &cmds {
        out.push_str("\n[[commands]]\n");
        kv(&mut out, "name", &esc(&c.name));
        kv(&mut out, "summary", &bilingual(&c.summary, &c.name));
        if !c.usage.is_empty() {
            kv(&mut out, "usage", &esc(&c.usage));
        }
        if !c.examples.is_empty() {
            kv(&mut out, "examples", &str_array(&c.examples));
        }
        kv(&mut out, "shell", "true");
        kv(&mut out, "run", &esc(&c.run));
    }

    Ok(MigrateOutput { toml: out, notes })
}

/// Parse one `commands.json`, returning its commands in author order. Names are
/// prefixed with `prefix.` for subplugins (`""` = main plugin). A command with
/// no `command` field (not a `type:"command"` entry) is noted and skipped.
fn parse_commands(
    prefix: &str,
    text: &str,
    notes: &mut Vec<String>,
) -> Result<Vec<CmdOut>, String> {
    // Iterate `commands` as an ordered object (serde_json `preserve_order` is on)
    // so author order survives the migration.
    let v: serde_json::Value =
        serde_json::from_str(text).map_err(|e| format!("commands.json 解析失败：{e}"))?;
    let Some(obj) = v.get("commands").and_then(|c| c.as_object()) else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for (name, body) in obj {
        let c: LegacyCommand = serde_json::from_value(body.clone())
            .map_err(|e| format!("命令 '{name}' 解析失败：{e}"))?;
        if c.command.trim().is_empty() {
            notes.push(format!(
                "命令 '{name}' 无 command 字段，已跳过（非 'command' 类型？）"
            ));
            continue;
        }
        let full = if prefix.is_empty() {
            name.clone()
        } else {
            format!("{prefix}.{name}")
        };
        out.push(CmdOut {
            name: full,
            summary: c.description,
            usage: c.usage,
            examples: c.examples,
            run: c.command,
        });
    }
    Ok(out)
}

// ---- tiny TOML writer (house style: inline tables for the i18n fields) ----

fn kv(out: &mut String, key: &str, value: &str) {
    out.push_str(key);
    out.push_str(" = ");
    out.push_str(value);
    out.push('\n');
}

/// A TOML basic string with the escapes a basic string requires.
fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn str_array(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|s| esc(s)).collect();
    format!("[{}]", inner.join(", "))
}

/// `{ zh = "…", en = "…" }`, dropping empty sides; falls back to `en = fallback`
/// when both are empty so the inline table is never degenerate.
fn bilingual(b: &Bilingual, fallback: &str) -> String {
    let mut parts = Vec::new();
    if !b.zh.is_empty() {
        parts.push(format!("zh = {}", esc(&b.zh)));
    }
    if !b.en.is_empty() {
        parts.push(format!("en = {}", esc(&b.en)));
    }
    if parts.is_empty() {
        parts.push(format!("en = {}", esc(fallback)));
    }
    format!("{{ {} }}", parts.join(", "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::PluginManifest;

    #[test]
    fn json_plugin_becomes_valid_declarative_manifest() {
        let plugin = r#"{
            "name": "json-simple",
            "version": "1.0.0",
            "type": "json",
            "entry": "commands.json",
            "priority": 90,
            "category": "example",
            "keywords": ["json", "demo"],
            "description": {"zh": "纯JSON插件", "en": "Pure JSON plugin"}
        }"#;
        let commands = r#"{
            "commands": {
                "info": {
                    "type": "command",
                    "command": "echo '📋 info' | cat",
                    "description": {"zh": "信息", "en": "Info"},
                    "usage": "gs json-simple info",
                    "examples": ["gs json-simple info"]
                },
                "status": {
                    "type": "command",
                    "command": "echo ok",
                    "description": {"en": "Status"}
                }
            }
        }"#;
        let out = migrate(&MigrateInputs {
            plugin_json: plugin.into(),
            main_commands_json: Some(commands.into()),
            sub_commands: vec![],
        })
        .unwrap();

        // The generated manifest must parse AND validate.
        let m = PluginManifest::parse(&out.toml)
            .unwrap_or_else(|e| panic!("generated toml invalid: {e}\n---\n{}", out.toml));
        assert_eq!(m.name, "json-simple");
        assert!(matches!(m.tier, crate::manifest::Tier::Declarative));
        assert_eq!(m.commands.len(), 2);

        let info = m.commands.iter().find(|c| c.name == "info").unwrap();
        assert!(info.shell, "legacy commands migrate to shell mode");
        assert_eq!(info.run, "echo '📋 info' | cat", "pipe/quotes preserved");
        // exec inferred from the first word of each command line.
        assert_eq!(m.capabilities.exec, vec!["echo".to_string()]);
        // command order preserved (info before status).
        assert_eq!(m.commands[0].name, "info");
        assert_eq!(m.commands[1].name, "status");
    }

    #[test]
    fn subplugins_namespace_command_names() {
        let plugin = r#"{
            "name": "json-subs",
            "type": "json",
            "subplugins": [{"name": "config", "entry": "config/commands.json"}]
        }"#;
        let sub = r#"{"commands": {"show": {"type": "command", "command": "cat config.toml"}}}"#;
        let out = migrate(&MigrateInputs {
            plugin_json: plugin.into(),
            main_commands_json: None,
            sub_commands: vec![("config".into(), sub.into())],
        })
        .unwrap();
        let m = PluginManifest::parse(&out.toml).unwrap();
        assert_eq!(m.commands.len(), 1);
        assert_eq!(m.commands[0].name, "config.show", "sub.command namespacing");
        assert_eq!(m.capabilities.exec, vec!["cat".to_string()]);
    }

    #[test]
    fn python_plugin_becomes_script_tier_with_note() {
        let plugin = r#"{
            "name": "py",
            "type": "python",
            "entry": "plugin.py",
            "description": {"en": "Py plugin"}
        }"#;
        let out = migrate(&MigrateInputs {
            plugin_json: plugin.into(),
            main_commands_json: None,
            sub_commands: vec![],
        })
        .unwrap();
        let m = PluginManifest::parse(&out.toml).unwrap();
        assert!(matches!(m.tier, crate::manifest::Tier::Script));
        assert_eq!(m.runtime, "python");
        assert_eq!(m.entry, "plugin.py");
        assert!(
            out.notes.iter().any(|n| n.contains("describe")),
            "tells the user the command tree needs the SDK"
        );
    }
}
