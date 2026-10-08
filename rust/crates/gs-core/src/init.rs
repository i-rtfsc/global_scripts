//! The `gs init` step manifest: what "set up this machine" means, as data.
//!
//! Capabilities live in plugins; this module only describes *order*. A step
//! names a plugin command (`run = ["devenv", "install", "essential"]`), whether
//! that command wants a `--dry-run`/`--yes` flag (`gate`) and whether it needs
//! root (`root`). Repointing a step at a different plugin after a split is a
//! one-line edit here, with no change to `gs init`'s own interface.

use serde::Deserialize;
use std::collections::BTreeMap;

/// One step of the manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct Step {
    pub id: String,
    #[serde(default)]
    pub group: String,
    /// Plugin command plus its arguments, e.g. `["devenv", "install", "go"]`.
    pub run: Vec<String>,
    /// Does the target command require `--dry-run`/`--yes`?
    #[serde(default)]
    pub gate: bool,
    /// Does the target action need root? `gs` never escalates by itself.
    #[serde(default)]
    pub root: bool,
    #[serde(default)]
    pub desc: BTreeMap<String, String>,
}

impl Step {
    /// The plugin this step invokes (`run[0]`).
    pub fn plugin(&self) -> &str {
        self.run.first().map(String::as_str).unwrap_or("")
    }

    /// Localised description, falling back to any locale present.
    pub fn description(&self, locale: &str) -> String {
        self.desc
            .get(locale)
            .or_else(|| self.desc.get("zh"))
            .or_else(|| self.desc.get("en"))
            .or_else(|| self.desc.values().next())
            .cloned()
            .unwrap_or_default()
    }

    /// Argv for this step, with the gate flag appended when asked for.
    pub fn argv(&self, flag: Option<&str>) -> Vec<String> {
        let mut argv = self.run.clone();
        if self.gate {
            if let Some(flag) = flag {
                argv.push(flag.to_string());
            }
        }
        argv
    }
}

/// Which steps the caller asked for.
#[derive(Debug, Default, Clone)]
pub struct Filter {
    /// Restrict to these groups (empty = every group).
    pub groups: Vec<String>,
    /// Restrict to these step ids or plugin names (empty = all).
    pub only: Vec<String>,
    /// Drop these step ids or plugin names.
    pub skip: Vec<String>,
    /// Drop these groups.
    pub without: Vec<String>,
}

impl Filter {
    fn keeps(&self, step: &Step) -> bool {
        let id_or_plugin = |value: &String| value == &step.id || value == step.plugin();
        if !self.only.is_empty() && !self.only.iter().any(id_or_plugin) {
            return false;
        }
        if self.skip.iter().any(id_or_plugin) {
            return false;
        }
        if !self.groups.is_empty() && !self.groups.iter().any(|g| g == &step.group) {
            return false;
        }
        if self.without.iter().any(|g| g == &step.group) {
            return false;
        }
        true
    }
}

/// The parsed manifest.
#[derive(Debug, Clone, Deserialize)]
pub struct Plan {
    #[serde(default)]
    pub steps: Vec<Step>,
}

impl Plan {
    pub fn parse(text: &str) -> Result<Self, String> {
        let plan: Plan = toml::from_str(text).map_err(|e| format!("init.toml 解析失败：{e}"))?;
        if plan.steps.is_empty() {
            return Err("init.toml 里没有任何 [[steps]]".into());
        }
        let mut seen = std::collections::BTreeSet::new();
        for step in &plan.steps {
            if step.id.trim().is_empty() {
                return Err("init.toml: 每个 step 必须有 id".into());
            }
            if step.run.is_empty() {
                return Err(format!("init.toml: step '{}' 的 run 不能为空", step.id));
            }
            if !seen.insert(step.id.clone()) {
                return Err(format!("init.toml: step id '{}' 重复", step.id));
            }
        }
        Ok(plan)
    }

    /// The steps this filter selects, in manifest order.
    pub fn select(&self, filter: &Filter) -> Vec<&Step> {
        self.steps.iter().filter(|s| filter.keeps(s)).collect()
    }

    /// Group names in the order they first appear.
    pub fn groups(&self) -> Vec<String> {
        let mut seen = std::collections::BTreeSet::new();
        self.steps
            .iter()
            .filter(|s| !s.group.is_empty() && seen.insert(s.group.clone()))
            .map(|s| s.group.clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[[steps]]
id = "01-mirrors"
group = "mirror"
run = ["system", "repo", "tsinghua"]
gate = true
desc = { zh = "镜像", en = "Mirror" }

[[steps]]
id = "20-base"
group = "base"
run = ["devenv", "install", "essential"]
gate = true
root = true
desc = { zh = "基础", en = "Base" }

[[steps]]
id = "21-nvidia"
group = "gpu"
run = ["gpu", "install", "driver"]
root = true
desc = { zh = "驱动", en = "Driver" }
"#;

    #[test]
    fn parses_steps_and_appends_the_gate_flag() {
        let plan = Plan::parse(SAMPLE).unwrap();
        assert_eq!(plan.steps.len(), 3);
        let mirrors = &plan.steps[0];
        assert_eq!(
            mirrors.argv(Some("--dry-run")),
            vec!["system", "repo", "tsinghua", "--dry-run"]
        );
        // No gate declared → argv untouched even in plan mode.
        let nvidia = &plan.steps[2];
        assert_eq!(
            nvidia.argv(Some("--dry-run")),
            vec!["gpu", "install", "driver"]
        );
        assert!(nvidia.root);
        assert_eq!(plan.groups(), vec!["mirror", "base", "gpu"]);
    }

    #[test]
    fn selects_by_group_id_plugin_and_exclusions() {
        let plan = Plan::parse(SAMPLE).unwrap();

        let by_group = plan.select(&Filter {
            groups: vec!["base".into()],
            ..Default::default()
        });
        assert_eq!(
            by_group.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            vec!["20-base"]
        );

        // `--only` also accepts the plugin name, so `--only=devenv` works.
        let by_plugin = plan.select(&Filter {
            only: vec!["devenv".into()],
            ..Default::default()
        });
        assert_eq!(by_plugin.len(), 1);

        let without = plan.select(&Filter {
            without: vec!["gpu".into()],
            ..Default::default()
        });
        assert_eq!(without.len(), 2);

        let skipped = plan.select(&Filter {
            skip: vec!["20-base".into()],
            without: vec!["mirror".into()],
            ..Default::default()
        });
        assert_eq!(
            skipped.iter().map(|s| s.id.as_str()).collect::<Vec<_>>(),
            vec!["21-nvidia"]
        );
    }

    #[test]
    fn rejects_duplicate_ids_and_empty_plans() {
        let dup = r#"
[[steps]]
id = "a"
run = ["x"]

[[steps]]
id = "a"
run = ["y"]
"#;
        assert!(Plan::parse(dup).is_err());
        assert!(Plan::parse("").is_err());
    }
}
