//! Plugin dispatch: T1 declarative exec and T2/T3 JSON-RPC invoke, plus the
//! shell-effect plumbing (`cd`, environment variables) they share.

use crate::detect_locale;
use crate::plugin::print_plugin_overview;
use gs_core::index::LoadedManifest;
use gs_core::manifest::CommandSpec;
use std::path::Path;
use std::process::Command;

pub(crate) fn dispatch_manifest(p: &LoadedManifest, rest: &[String]) -> i32 {
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

pub(crate) fn exec_t1(p: &LoadedManifest, cmd: &CommandSpec, argv: &[String]) -> i32 {
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
pub(crate) fn exec_cd(cmd: &CommandSpec, argv: &[String]) -> i32 {
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
            println!("{path}");
        }
        None => {
            println!("{path}");
            eprintln!("提示: 未启用 shell 集成，无法切换目录。运行 `gs shell-init <shell>` 安装。");
        }
    }
    0
}

pub(crate) fn valid_effect_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .ok()
        .filter(|meta| meta.file_type().is_file() && meta.len() == 0)
        .and_then(|_| path.parent())
        .and_then(|parent| parent.canonicalize().ok())
        .zip(std::env::temp_dir().canonicalize().ok())
        .map(|(parent, temp)| parent.starts_with(temp))
        .unwrap_or(false)
}

pub(crate) fn write_env_effects(value: &serde_json::Value) -> Result<bool, String> {
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

pub(crate) fn exec_plugin_result(
    p: &LoadedManifest,
    value: &serde_json::Value,
) -> Result<i32, String> {
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
pub(crate) fn invoke_t2(
    p: &LoadedManifest,
    cmd: &CommandSpec,
    argv: &[String],
    locale: &str,
) -> i32 {
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

/// Single-quote a string for safe embedding in a `sh`/`bash -c` program.
pub(crate) fn exec_or_status(mut cmd: Command) -> i32 {
    use std::os::unix::process::CommandExt;
    let err = cmd.exec(); // returns only on failure
    eprintln!("gs: failed to exec ({}): {err}", program_name(&cmd));
    127
}

#[cfg(not(unix))]
pub(crate) fn exec_or_status(mut cmd: Command) -> i32 {
    match cmd.status() {
        Ok(s) => s.code().unwrap_or(1),
        Err(e) => {
            eprintln!("gs: failed to run: {e}");
            127
        }
    }
}

#[cfg(unix)]
pub(crate) fn program_name(cmd: &Command) -> String {
    cmd.get_program().to_string_lossy().into_owned()
}
