//! `plugin.toml` manifest schema + the normalized command/describe model.
//!
//! Spec: tmp/phase0-plugin-protocol.md §1 (manifest schema), §2 (describe — the
//! runtime command tree is *isomorphic* to the manifest's).
//!
//! A plugin's `plugin.toml` is the single source of truth, replacing the old
//! `plugin.json` + `commands.json` + `@plugin_function` decorators. For a **T1
//! declarative** plugin the whole command tree lives here and the core
//! executes/completes from it with zero runtime calls. For **T2/T3/T4** the
//! tree may be omitted and fetched at runtime via the `describe` RPC
//! ([`crate::rpc`]) — but the in-memory shape ([`CommandSpec`]) is identical, so
//! everything downstream (completion, help, validation) is tier-agnostic.
//!
//! The arg/command/complete structs deserialize from **both** TOML (the
//! manifest) and JSON (the describe response), so there is a single model: any
//! `Value`-typed field uses [`serde_json::Value`], which serde can populate from
//! the `toml` deserializer too.

use serde::Deserialize;
use std::collections::BTreeMap;

/// Locale → text map, e.g. `{ "zh": "…", "en": "…" }`.
pub type I18n = BTreeMap<String, String>;

/// Plugin execution tier (§6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Tier {
    /// No runtime; the core executes `run` templates and completes from the
    /// manifest. Never started to answer `describe`/`complete`/`invoke`.
    Declarative,
    /// A one-shot interpreter process speaking JSON-RPC over stdio.
    Script,
    /// A resident process speaking JSON-RPC (handshake once, reused).
    Rpc,
    /// A wasm module (wasmtime/Extism), capabilities = WASI grants.
    Wasm,
}

impl Tier {
    /// T1 is the only tier the core never launches.
    pub fn is_declarative(self) -> bool {
        matches!(self, Tier::Declarative)
    }
}

/// How the core obtains a plugin's command tree (§1.1 `describe_cache`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DescribeCache {
    /// Tree is fully inline in the manifest (T1 default).
    Manifest,
    /// Run `describe` at runtime once, then cache (T2/T3/T4 default).
    Runtime,
    /// Tree is inline though the tier is T2+ — skip runtime `describe`.
    Static,
}

/// `[capabilities]` — least-privilege allowlist (§1.2 / §6.4). Absent = deny.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Capabilities {
    /// External command names the plugin may run (`["adb","fastboot"]`);
    /// `["*"]` = unrestricted (discouraged).
    #[serde(default)]
    pub exec: Vec<String>,
    /// `"<mode>:<path>"`, mode ∈ `read|write|rw`; path may use `$HOME` /
    /// `$PROJECT` / `$PLUGIN_DIR`.
    #[serde(default)]
    pub fs: Vec<String>,
    /// Network policy.
    #[serde(default)]
    pub net: Net,
    /// Environment variable names the plugin may read.
    #[serde(default)]
    pub env: Vec<String>,
}

/// `net` is `false` | `true` | `["host:port", …]` (§1.2).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum Net {
    /// `false` = denied, `true` = unrestricted.
    All(bool),
    /// Host / CIDR allowlist.
    Hosts(Vec<String>),
}

impl Default for Net {
    fn default() -> Self {
        Net::All(false)
    }
}

/// Source kind for an argument's completion (§1.3.1 / §2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CompleteKind {
    /// No completion for this arg.
    #[default]
    None,
    /// Static value list, baked into the shell script — zero callback.
    Enum,
    /// Native file completion, optionally filtered by `pattern`.
    File,
    /// Native directory completion.
    Dir,
    /// Resolved at Tab time: T1 runs `command`; T2/T3/T4 call the plugin with
    /// `source`.
    Dynamic,
}

/// `[commands.args.complete]` — the completion rule for one argument.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct CompleteRule {
    #[serde(default)]
    pub kind: CompleteKind,
    /// `kind = "enum"`: the static candidate list.
    #[serde(default)]
    pub values: Vec<String>,
    /// `kind = "file"`: glob filter (e.g. `*.apk`).
    #[serde(default)]
    pub pattern: String,
    /// `kind = "dynamic"` (T2/T3/T4): the plugin-defined source id.
    #[serde(default)]
    pub source: String,
    /// `kind = "dynamic"` (T1 only): an exec line the core runs directly
    /// (capability-checked), one candidate per output line.
    #[serde(default)]
    pub command: String,
    /// Optional regex applied to `command` output; first capture = candidate.
    #[serde(default)]
    pub filter: String,
}

/// One argument of a command (§1.3 `[[commands.args]]`).
#[derive(Debug, Clone, Deserialize)]
pub struct ArgSpec {
    pub name: String,
    /// `string|int|float|bool|enum|path|flag`.
    #[serde(default = "default_arg_type", rename = "type")]
    pub arg_type: String,
    #[serde(default)]
    pub required: bool,
    /// Repeatable trailing positional.
    #[serde(default)]
    pub variadic: bool,
    #[serde(default)]
    pub description: I18n,
    /// Default value (any TOML/JSON scalar).
    #[serde(default)]
    pub default: Option<serde_json::Value>,
    /// Option form, e.g. `"--serial"` / `"-s"`; empty = positional.
    #[serde(default)]
    pub flag: String,
    #[serde(default)]
    pub complete: CompleteRule,
}

impl ArgSpec {
    /// A flag arg (has `--flag`) vs. a positional one.
    pub fn is_flag(&self) -> bool {
        !self.flag.is_empty()
    }

    /// Whether this arg consumes a following value. Boolean/flag-type args don't.
    pub fn takes_value(&self) -> bool {
        !matches!(self.arg_type.as_str(), "bool" | "flag")
    }
}

/// One command (§1.3 `[[commands]]`). `name` uses `.` for the subcommand path,
/// e.g. `device.logcat` (old `subplugin=device`, fn `logcat`).
#[derive(Debug, Clone, Deserialize)]
pub struct CommandSpec {
    pub name: String,
    /// One-line summary (note: commands use `summary`, args/plugins use
    /// `description`, mirroring the spec).
    #[serde(default)]
    pub summary: I18n,
    #[serde(default)]
    pub usage: String,
    #[serde(default)]
    pub examples: Vec<String>,
    /// T1 exec template (argv with `{arg}` placeholders); ignored by T2+.
    #[serde(default)]
    pub run: String,
    /// T1 only: run `run` through the system shell (`sh -c` / `cmd /C`) as a
    /// single line instead of exec-form argv splitting — needed for pipes,
    /// quoting, redirects, globs and `&&`. The `exec` capability still gates the
    /// line's first word; placeholders substitute textually (values are
    /// shell-quoted). This is the faithful target for migrated legacy commands,
    /// whose `command` field was always a shell string.
    #[serde(default)]
    pub shell: bool,
    /// T1 navigation: a directory to `cd` into (path template — `$VAR`, `${VAR}`,
    /// a leading `~`, and `{arg}` placeholders all expand). A command with a
    /// non-empty `cd` changes the shell's working directory via the `gs` shell
    /// wrapper (it reads the resolved path from `$GS_CD_FILE`); with no wrapper
    /// installed it just prints the target. Mutually exclusive with `run`.
    #[serde(default)]
    pub cd: String,
    /// Hidden commands are excluded from completion.
    #[serde(default)]
    pub hidden: bool,
    #[serde(default)]
    pub args: Vec<ArgSpec>,
}

impl CommandSpec {
    /// The leading `.`-separated path segment (the subcommand group), or `""`
    /// for a top-level command. `device.logcat` → `"device"`.
    pub fn group(&self) -> &str {
        match self.name.split_once('.') {
            Some((g, _)) => g,
            None => "",
        }
    }

    /// The final `.`-separated segment (the leaf command name).
    /// `device.logcat` → `"logcat"`; `co` → `"co"`.
    pub fn leaf(&self) -> &str {
        self.name.rsplit('.').next().unwrap_or(&self.name)
    }

    /// Look up an argument by its declared `name`.
    pub fn arg(&self, name: &str) -> Option<&ArgSpec> {
        self.args.iter().find(|a| a.name == name)
    }

    /// Find a flag arg by its `--flag` / `-x` token.
    pub fn arg_by_flag(&self, flag: &str) -> Option<&ArgSpec> {
        self.args.iter().find(|a| a.flag == flag)
    }
}

/// The whole `plugin.toml`. Unknown keys are ignored so newer manifests stay
/// loadable by an older core.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginManifest {
    pub name: String,
    #[serde(default)]
    pub version: String,
    pub tier: Tier,
    /// Interpreter for T2/T3 (`python`/`bash`/`node`/…); empty for T1/wasm.
    #[serde(default)]
    pub runtime: String,
    /// Script / RPC entry file, or the `.wasm` module; empty for T1.
    #[serde(default)]
    pub entry: String,
    #[serde(default)]
    pub description: I18n,
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
    /// Optional descriptions for dotted command namespaces (for example
    /// `device` in `device.devices`). Shell completion uses these before the
    /// user has selected a leaf command.
    #[serde(default)]
    pub groups: BTreeMap<String, I18n>,
    #[serde(default = "default_priority")]
    pub priority: i64,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_protocol")]
    pub protocol: u32,
    /// Absent → derived from `tier` (see [`Self::describe_cache_resolved`]).
    #[serde(default)]
    pub describe_cache: Option<DescribeCache>,
    #[serde(default)]
    pub capabilities: Capabilities,
    #[serde(default)]
    pub commands: Vec<CommandSpec>,
}

impl PluginManifest {
    /// Parse a `plugin.toml` string, then validate tier invariants.
    pub fn parse(toml_text: &str) -> Result<Self, String> {
        let m: PluginManifest =
            toml::from_str(toml_text).map_err(|e| format!("TOML 解析失败：{e}"))?;
        m.validate()?;
        Ok(m)
    }

    /// `describe_cache`, defaulted by tier: T1 → `manifest`, others → `runtime`.
    pub fn describe_cache_resolved(&self) -> DescribeCache {
        self.describe_cache.unwrap_or(match self.tier {
            Tier::Declarative => DescribeCache::Manifest,
            _ => DescribeCache::Runtime,
        })
    }

    /// True when the command tree is fully inline (T1, or T2+ with
    /// `describe_cache != "runtime"`) — no runtime `describe` is needed.
    pub fn commands_are_inline(&self) -> bool {
        !matches!(self.describe_cache_resolved(), DescribeCache::Runtime)
    }

    /// Tier invariants (§1.1 / §6.1). Returns a friendly message on violation.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("plugin.toml: `name` 不能为空".into());
        }
        for c in &self.commands {
            if c.name.trim().is_empty() {
                return Err("plugin.toml: 每个 [[commands]] 必须有非空 `name`".into());
            }
        }
        match self.tier {
            Tier::Declarative => {
                if !self.runtime.is_empty() {
                    return Err("T1(declarative) 插件禁止设置 `runtime`".into());
                }
                if !self.entry.is_empty() {
                    return Err("T1(declarative) 插件禁止设置 `entry`".into());
                }
                for c in &self.commands {
                    let has_run = !c.run.trim().is_empty();
                    let has_cd = !c.cd.trim().is_empty();
                    if has_run && has_cd {
                        return Err(format!("T1 命令 `{}` 不能同时设置 `run` 和 `cd`", c.name));
                    }
                    if !has_run && !has_cd {
                        return Err(format!(
                            "T1 命令 `{}` 必须定义 `run` 模板或 `cd` 目标",
                            c.name
                        ));
                    }
                }
            }
            Tier::Script | Tier::Rpc => {
                if self.runtime.is_empty() {
                    return Err(format!(
                        "T2/T3 插件 `{}` 必须设置 `runtime`(解释器)",
                        self.name
                    ));
                }
                if self.entry.is_empty() {
                    return Err(format!(
                        "T2/T3 插件 `{}` 必须设置 `entry`(入口文件)",
                        self.name
                    ));
                }
            }
            Tier::Wasm => {
                if self.entry.is_empty() {
                    return Err(format!(
                        "T4(wasm) 插件 `{}` 必须设置 `entry`(.wasm 模块)",
                        self.name
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Pick the text for `locale` from an [`I18n`] map, falling back en → zh → any
/// (§ OQ-6: the core does the fallback, plugins only provide best-effort).
/// Empty strings count as absent.
pub fn pick(map: &I18n, locale: &str) -> Option<String> {
    [locale, "en", "zh"]
        .into_iter()
        .filter_map(|k| map.get(k))
        .chain(map.values())
        .find(|s| !s.is_empty())
        .cloned()
}

fn default_true() -> bool {
    true
}
fn default_priority() -> i64 {
    50
}
fn default_protocol() -> u32 {
    1
}
fn default_arg_type() -> String {
    "string".into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Doc §1.5 — declarative (T1).
    const GITX: &str = r#"
        name        = "gitx"
        version     = "1.0.0"
        tier        = "declarative"
        description = { zh = "Git 快捷封装", en = "Git shortcuts" }
        category    = "development"
        priority    = 30

        [capabilities]
        exec = ["git", "code"]
        fs   = ["read:$PROJECT"]

        [[commands]]
        name    = "co"
        summary = { zh = "切换分支", en = "Checkout branch" }
        run     = "git checkout {branch}"
        examples = ["gs gitx co main"]

          [[commands.args]]
          name        = "branch"
          type        = "string"
          required    = true
          description = { zh = "目标分支", en = "Target branch" }

            [commands.args.complete]
            kind    = "dynamic"
            command = "git for-each-ref --format=%(refname:short) refs/heads"

        [[commands]]
        name    = "open"
        summary = { zh = "用 VSCode 打开仓库", en = "Open repo in VSCode" }
        run     = "code {dir}"

          [[commands.args]]
          name = "dir"
          type = "path"

            [commands.args.complete]
            kind = "dir"
    "#;

    // Doc §1.6 — script (T2 / python), with a subcommand path + enum + dynamic.
    const ANDROID: &str = r#"
        name        = "android"
        version     = "2.0.0"
        tier        = "script"
        runtime     = "python"
        entry       = "plugin.py"
        description = { zh = "Android 工具集", en = "Android tools" }
        priority    = 20
        describe_cache = "runtime"

        [capabilities]
        exec = ["adb", "fastboot"]
        fs   = ["read:$HOME/.android", "rw:$PROJECT"]
        net  = false
        env  = ["ANDROID_HOME", "ANDROID_SDK_ROOT"]

        [[commands]]
        name    = "device.logcat"
        summary = { zh = "查看设备日志", en = "View device logcat" }

          [[commands.args]]
          name = "serial"
          type = "string"
          flag = "--serial"

            [commands.args.complete]
            kind   = "dynamic"
            source = "device_serials"

          [[commands.args]]
          name    = "level"
          type    = "enum"
          flag    = "--level"
          default = "V"

            [commands.args.complete]
            kind   = "enum"
            values = ["V", "D", "I", "W", "E", "F"]
    "#;

    #[test]
    fn parses_declarative_t1() {
        let m = PluginManifest::parse(GITX).unwrap();
        assert_eq!(m.name, "gitx");
        assert_eq!(m.tier, Tier::Declarative);
        assert!(m.tier.is_declarative());
        assert_eq!(m.priority, 30);
        assert_eq!(m.protocol, 1, "protocol defaults to 1");
        assert!(m.enabled, "enabled defaults to true");
        assert_eq!(m.capabilities.exec, vec!["git", "code"]);
        assert_eq!(m.describe_cache_resolved(), DescribeCache::Manifest);
        assert!(m.commands_are_inline());

        let co = &m.commands[0];
        assert_eq!(co.name, "co");
        assert_eq!(co.run, "git checkout {branch}");
        assert_eq!(pick(&co.summary, "zh").as_deref(), Some("切换分支"));
        let branch = co.arg("branch").unwrap();
        assert!(branch.required);
        assert_eq!(branch.complete.kind, CompleteKind::Dynamic);
        assert_eq!(
            branch.complete.command,
            "git for-each-ref --format=%(refname:short) refs/heads"
        );
        // `open dir` → directory completion
        let dir = m.commands[1].arg("dir").unwrap();
        assert_eq!(dir.complete.kind, CompleteKind::Dir);
        assert_eq!(dir.arg_type, "path");
    }

    #[test]
    fn parses_script_t2_with_subcommand_and_rules() {
        let m = PluginManifest::parse(ANDROID).unwrap();
        assert_eq!(m.tier, Tier::Script);
        assert_eq!(m.runtime, "python");
        assert_eq!(m.entry, "plugin.py");
        assert_eq!(m.describe_cache_resolved(), DescribeCache::Runtime);
        assert!(!m.commands_are_inline(), "runtime cache → not inline");
        assert_eq!(m.capabilities.net, Net::All(false));
        assert_eq!(m.capabilities.env, vec!["ANDROID_HOME", "ANDROID_SDK_ROOT"]);

        let c = &m.commands[0];
        assert_eq!(c.name, "device.logcat");
        assert_eq!(c.group(), "device");
        assert_eq!(c.leaf(), "logcat");

        let serial = c.arg("serial").unwrap();
        assert!(serial.is_flag());
        assert_eq!(serial.flag, "--serial");
        assert_eq!(serial.complete.kind, CompleteKind::Dynamic);
        assert_eq!(serial.complete.source, "device_serials");
        assert_eq!(c.arg_by_flag("--serial").unwrap().name, "serial");

        let level = c.arg("level").unwrap();
        assert_eq!(level.complete.kind, CompleteKind::Enum);
        assert_eq!(level.complete.values, ["V", "D", "I", "W", "E", "F"]);
        assert_eq!(level.default, Some(serde_json::json!("V")));
    }

    #[test]
    fn net_is_false_true_or_list() {
        let f = |s: &str| {
            toml::from_str::<Capabilities>(s)
                .unwrap_or_else(|e| panic!("parse {s:?}: {e}"))
                .net
        };
        assert_eq!(f("net = false"), Net::All(false));
        assert_eq!(f("net = true"), Net::All(true));
        assert_eq!(
            f(r#"net = ["api.github.com:443", "10.0.0.0/8"]"#),
            Net::Hosts(vec!["api.github.com:443".into(), "10.0.0.0/8".into()])
        );
        // absent → deny
        assert_eq!(f(""), Net::All(false));
    }

    #[test]
    fn arg_type_and_priority_defaults() {
        let m = PluginManifest::parse(
            r#"
            name = "x"
            tier = "declarative"
            [[commands]]
            name = "c"
            run  = "true {a}"
            [[commands.args]]
            name = "a"
        "#,
        )
        .unwrap();
        assert_eq!(m.priority, 50, "default priority");
        assert_eq!(m.commands[0].arg("a").unwrap().arg_type, "string");
        assert_eq!(
            m.commands[0].arg("a").unwrap().complete.kind,
            CompleteKind::None
        );
    }

    #[test]
    fn validate_rejects_tier_violations() {
        // T1 must not carry runtime/entry.
        let t1_runtime = "name = \"x\"\ntier = \"declarative\"\nruntime = \"python\"\n";
        assert!(PluginManifest::parse(t1_runtime)
            .unwrap_err()
            .contains("runtime"));
        // T1 command without `run`.
        let e = PluginManifest::parse(
            r#"
            name = "x"
            tier = "declarative"
            [[commands]]
            name = "c"
        "#,
        )
        .unwrap_err();
        assert!(e.contains("run"), "got: {e}");
        // T2 needs runtime + entry.
        let t2_no_runtime = "name = \"x\"\ntier = \"script\"\nentry = \"p.py\"\n";
        assert!(PluginManifest::parse(t2_no_runtime)
            .unwrap_err()
            .contains("runtime"));
        let t2_no_entry = "name = \"x\"\ntier = \"script\"\nruntime = \"python\"\n";
        assert!(PluginManifest::parse(t2_no_entry)
            .unwrap_err()
            .contains("entry"));
        // Empty name.
        let empty_name = "name = \"\"\ntier = \"declarative\"\n";
        assert!(PluginManifest::parse(empty_name)
            .unwrap_err()
            .contains("name"));
    }

    #[test]
    fn describe_cache_static_keeps_inline() {
        let m = PluginManifest::parse(
            r#"
            name="x"
            tier="script"
            runtime="python"
            entry="p.py"
            describe_cache="static"
        "#,
        )
        .unwrap();
        assert_eq!(m.describe_cache_resolved(), DescribeCache::Static);
        assert!(
            m.commands_are_inline(),
            "static → inline, no runtime describe"
        );
    }

    #[test]
    fn pick_locale_fallback() {
        let mut m = I18n::new();
        m.insert("en".into(), "English".into());
        m.insert("zh".into(), "中文".into());
        assert_eq!(pick(&m, "zh").as_deref(), Some("中文"));
        assert_eq!(pick(&m, "en").as_deref(), Some("English"));
        assert_eq!(pick(&m, "fr").as_deref(), Some("English"), "fr → en");
        // only zh present, ask en → falls through to any
        let mut z = I18n::new();
        z.insert("zh".into(), "仅中文".into());
        assert_eq!(pick(&z, "en").as_deref(), Some("仅中文"));
        assert_eq!(pick(&I18n::new(), "en"), None);
    }
}
