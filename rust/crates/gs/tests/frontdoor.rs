use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .expect("repository root")
}

fn gs_bin() -> &'static str {
    env!("CARGO_BIN_EXE_gs")
}

fn run(args: &[&str]) -> Output {
    let cache = std::env::temp_dir().join(format!(
        "gs-frontdoor-cache-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    Command::new(gs_bin())
        .args(args)
        .env("GS_ROOT", repo_root())
        .env("GS_INCLUDE_EXAMPLES", "1")
        .env("GS_CACHE_DIR", cache)
        .env("GS_DESCRIBE_TIMEOUT_MS", "5000")
        .current_dir(repo_root())
        .output()
        .expect("run gs front door")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn run_without_examples(args: &[&str]) -> Output {
    Command::new(gs_bin())
        .args(args)
        .env("GS_ROOT", repo_root())
        .env(
            "GS_CACHE_DIR",
            std::env::temp_dir().join("gs-frontdoor-no-examples"),
        )
        .env_remove("GS_INCLUDE_EXAMPLES")
        .env("GS_DESCRIBE_TIMEOUT_MS", "5000")
        .current_dir(repo_root())
        .output()
        .expect("run gs without examples")
}

fn run_as(command_name: &str, args: &[&str]) -> Output {
    Command::new(gs_bin())
        .args(args)
        .env("GS_ROOT", repo_root())
        .env("GS_COMMAND_NAME", command_name)
        .env("GS_DESCRIBE_TIMEOUT_MS", "5000")
        .env(
            "GS_CACHE_DIR",
            std::env::temp_dir().join("gs-frontdoor-command-name"),
        )
        .current_dir(repo_root())
        .output()
        .expect("run gs with a custom command name")
}

fn run_with_env_file(args: &[&str], env_file: &PathBuf) -> Output {
    Command::new(gs_bin())
        .args(args)
        .env("GS_ROOT", repo_root())
        .env("GS_ENV_FILE", env_file)
        .env("GS_DESCRIBE_TIMEOUT_MS", "5000")
        .env(
            "GS_CACHE_DIR",
            std::env::temp_dir().join("gs-frontdoor-env-effects"),
        )
        .current_dir(repo_root())
        .output()
        .expect("run gs with an environment effect file")
}

#[test]
fn native_system_commands_are_self_contained() {
    let version = run(&["version"]);
    assert!(version.status.success());
    assert!(stdout(&version).contains("6.0.0"));

    let help = run(&["help"]);
    assert!(help.status.success());
    assert!(stdout(&help).contains("Global Scripts 6.0 development CLI"));

    let status = run(&["status"]);
    assert!(status.status.success());
    assert!(stdout(&status).contains("GS 6.0 状态"));

    let doctor = run(&["doctor"]);
    assert!(doctor.status.success());
    assert!(stdout(&doctor).contains("结果:          通过"));

    let refresh = run(&["refresh"]);
    assert!(refresh.status.success());
    assert!(stdout(&refresh).contains("GS 6.0 refresh"));
}

#[test]
fn completion_scripts_bind_to_the_requested_command_name() {
    let cases = [
        ("bash", "_gs6_complete", "complete -F _gs6_complete gs6"),
        ("zsh", "_gs6_complete", "compdef _gs6_complete gs6"),
        ("fish", "__gs6_complete", "complete -c gs6 "),
        ("nushell", "== \"gs6\"", "(^gs6 __complete"),
        ("powershell", "-CommandName gs6", "(gs6 __complete"),
    ];
    for (shell, function, binding) in cases {
        let result = run_as("gs6", &["completions", shell]);
        assert!(result.status.success(), "{shell}: {}", stderr(&result));
        let text = stdout(&result);
        assert!(text.contains(function), "{shell} function binding missing");
        assert!(text.contains(binding), "{shell} command binding missing");
    }
}

#[test]
fn powershell_shell_init_supports_cd_and_environment_effects() {
    let result = run_as("gs6", &["shell-init", "powershell"]);
    assert!(result.status.success(), "{}", stderr(&result));
    let text = stdout(&result);
    assert!(text.contains("function global:gs6"));
    assert!(text.contains("GS_CD_FILE"));
    assert!(text.contains("GS_ENV_FILE"));
    assert!(text.contains("Set-Location -LiteralPath"));
    assert!(text.contains("SetEnvironmentVariable"));
}

#[test]
fn bare_plugin_command_lists_manifests() {
    let result = run(&["plugin"]);
    assert!(result.status.success());
    assert!(stdout(&result).contains("插件"));
    assert!(stdout(&result).contains("android"));
}

#[test]
fn unknown_plugin_management_commands_never_fall_back_to_python() {
    let unknown = run(&["plugin", "android"]);
    assert_eq!(unknown.status.code(), Some(1));
    assert!(stderr(&unknown).contains("plugin 没有命令 'android'"));
    assert!(!stderr(&unknown).contains("ModuleNotFoundError"));

    for args in [
        ["plugin", "info", "not-a-gs6-plugin"],
        ["plugin", "enable", "not-a-gs6-plugin"],
        ["plugin", "disable", "not-a-gs6-plugin"],
    ] {
        let missing = run(&args);
        assert_eq!(missing.status.code(), Some(1));
        assert!(stderr(&missing).contains("不存在或尚未迁移"));
        assert!(!stderr(&missing).contains("ModuleNotFoundError"));
    }
}

#[test]
fn plugin_info_can_focus_a_command_group() {
    let result = run(&["plugin", "info", "android", "winscope"]);
    assert!(result.status.success());
    let text = stdout(&result);
    assert!(text.contains("android / winscope"));
    assert!(text.contains("winscope start"));
    assert!(!text.contains("device devices"));

    let missing = run(&["plugin", "info", "android", "does-not-exist"]);
    assert_eq!(missing.status.code(), Some(1));

    // A complete command path under `plugin info` is an execution shortcut,
    // not another information view. Use the deterministic demo plugin here so
    // the test does not depend on an attached Android device.
    let command = run(&["plugin", "info", "demo", "greet", "frontdoor"]);
    assert!(command.status.success());
    let command_text = stdout(&command);
    assert!(command_text.contains("Hello, frontdoor!"));
    assert!(!command_text.contains("命令详情"));
}

#[cfg(unix)]
#[test]
fn wasm_tier_invokes_through_wasmtime_stdio() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!("gs-wasm-{}", std::process::id()));
    let plugin = root.join("plugins/wasm-demo");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        r#"name="wasm-demo"
version="6.0.0-dev"
tier="wasm"
entry="plugin.wasm"
describe_cache="static"
[[commands]]
name="hello"
summary={en="Hello"}
"#,
    )
    .unwrap();
    fs::write(plugin.join("plugin.wasm"), b"fixture").unwrap();
    let body = r#"{"jsonrpc":"2.0","id":1,"result":{"exit_code":0,"stdout":"hello from wasm\n"}}"#;
    let runner = root.join("fake-wasmtime.sh");
    fs::write(
        &runner,
        format!(
            "#!/bin/sh\ncat >/dev/null\nprintf 'Content-Length: {}\\r\\n\\r\\n%s' '{}'\n",
            body.len(),
            body
        ),
    )
    .unwrap();
    fs::set_permissions(&runner, fs::Permissions::from_mode(0o755)).unwrap();
    let output = Command::new(gs_bin())
        .args(["wasm-demo", "hello"])
        .env("GS_ROOT", &root)
        .env("GS_WASMTIME_BIN", &runner)
        .env("GS_CACHE_DIR", root.join("cache"))
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(stdout(&output).contains("hello from wasm"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn examples_are_not_part_of_the_default_plugin_surface() {
    let list = run_without_examples(&["plugin", "list"]);
    assert!(list.status.success());
    let text = stdout(&list);
    assert!(!text.contains("demo"));
    assert!(!text.contains("json-simple"));
    assert!(!text.contains("json-with-subplugins"));
    assert!(text.contains("system"));
    assert!(text.contains("android"));
    assert!(text.contains("6.0.0"));
}

#[test]
fn gs_root_isolates_user_plugins_and_legacy_router() {
    let home =
        std::env::temp_dir().join(format!("gs-frontdoor-isolated-home-{}", std::process::id()));
    let plugin = home.join(".config/global-scripts/plugins/user-only");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        "name=\"user-only\"\nversion=\"1.0.0\"\ntier=\"declarative\"\n",
    )
    .unwrap();
    let external = home.join("external-plugins/user-path");
    fs::create_dir_all(&external).unwrap();
    fs::write(
        external.join("plugin.toml"),
        "name=\"user-path\"\nversion=\"1.0.0\"\ntier=\"declarative\"\n",
    )
    .unwrap();
    let list = Command::new(gs_bin())
        .args(["plugin", "list"])
        .env("GS_ROOT", repo_root())
        .env("HOME", &home)
        .env("GS_PLUGIN_PATH", home.join("external-plugins"))
        .env_remove("GS_ALLOW_LEGACY")
        .output()
        .unwrap();
    assert!(list.status.success());
    let text = stdout(&list);
    assert!(!text.contains("user-only"));
    assert!(!text.contains("user-path"));

    let router = home.join("router.json");
    fs::write(&router, r#"{"schema_version":"2.0","plugins":{}}"#).unwrap();
    let status = Command::new(gs_bin())
        .arg("status")
        .env("GS_ROOT", repo_root())
        .env("ROUTER_INDEX", &router)
        .env_remove("GS_ALLOW_LEGACY")
        .output()
        .unwrap();
    assert!(status.status.success());
    assert!(stdout(&status).contains("router.json:   未发现"));
}

#[test]
fn explicit_legacy_opt_in_keeps_external_plugin_discovery() {
    let root = std::env::temp_dir().join(format!("gs-frontdoor-legacy-{}", std::process::id()));
    let external = root.join("external").join("legacy-only");
    fs::create_dir_all(&external).unwrap();
    fs::write(
        external.join("plugin.toml"),
        "name=\"legacy-only\"\nversion=\"1.0.0\"\ntier=\"declarative\"\n",
    )
    .unwrap();
    let list = Command::new(gs_bin())
        .args(["plugin", "list"])
        .env("GS_ROOT", repo_root())
        .env("GS_ALLOW_LEGACY", "1")
        .env("GS_PLUGIN_PATH", root.join("external"))
        .env("GS_CACHE_DIR", root.join("cache"))
        .output()
        .unwrap();
    assert!(list.status.success());
    assert!(stdout(&list).contains("legacy-only"));
}

#[test]
fn explicit_legacy_opt_in_keeps_router_fallback() {
    let root = std::env::temp_dir().join(format!("gs-frontdoor-router-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let router = root.join("router.json");
    fs::write(
        &router,
        r#"{"version":"2.0","plugins":{"legacy-only":{"enabled":true,"description":{"zh":"legacy"}}}}"#,
    )
    .unwrap();
    let status = Command::new(gs_bin())
        .arg("status")
        .env("GS_ROOT", repo_root())
        .env("GS_ALLOW_LEGACY", "1")
        .env("ROUTER_INDEX", &router)
        .env("GS_CACHE_DIR", root.join("cache"))
        .output()
        .unwrap();
    assert!(status.status.success());
    assert!(stdout(&status).contains("legacy 插件:   1 个"));
}

#[test]
fn t2_invoke_and_dynamic_completion_use_rust_frontdoor() {
    let invoke = run(&["demo", "greet", "frontdoor"]);
    assert!(invoke.status.success());
    assert!(stdout(&invoke).contains("Hello, frontdoor!"));

    let complete = run(&["__complete", "demo", "paint", "--color"]);
    assert!(complete.status.success());
    let text = stdout(&complete);
    assert!(text.contains("red\twarm"));
    assert!(text.contains("green\tgo"));
    assert!(text.contains(":4"));

    let info = run(&["plugin", "info", "demo"]);
    assert!(info.status.success());
    assert!(stdout(&info).contains("demo"));
    assert!(stdout(&info).contains("greet"));
}

#[test]
fn flyme_legacy_example_is_available_through_the_gs6_protocol() {
    let info = run(&["flyme", "info"]);
    assert!(info.status.success());
    assert!(stdout(&info).contains("FlymeOS Development Plugin"));

    let build = run(&["flyme", "build", "m1892"]);
    assert!(build.status.success());
    assert!(stdout(&build).contains("目标设备: m1892"));

    let flash = run(&["flyme", "flash", "flyme_build.zip"]);
    assert!(flash.status.success());
    assert!(stdout(&flash).contains("不会写入设备"));
}

#[test]
fn system_safe_migration_commands_work_in_place() {
    let info = run(&["plugin", "info", "system"]);
    assert!(info.status.success());
    assert!(stdout(&info).contains("system"));
    assert!(stdout(&info).contains("prompt set"));

    let proxy = run(&["system", "proxy", "status"]);
    assert!(proxy.status.success());
    assert!(stdout(&proxy).contains("代理状态"));

    let repo = run(&["system", "repo", "status"]);
    assert!(repo.status.success());
    assert!(stdout(&repo).contains("REPO_URL") || stdout(&repo).contains("默认源"));

    let themes = run(&["system", "prompt", "themes"]);
    assert!(themes.status.success());
    assert!(stdout(&themes).contains("minimalist"));

    let current = run(&["system", "prompt", "current"]);
    assert!(current.status.success());
    assert!(!stdout(&current).trim().is_empty());

    let complete = run(&["__complete", "system", "prompt", "set"]);
    assert!(complete.status.success());
    assert!(stdout(&complete).contains("minimalist"));
}

#[test]
fn system_environment_switches_emit_validated_shell_effects() {
    let root = std::env::temp_dir().join(format!("gs-env-effects-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();

    let proxy_file = root.join("proxy");
    fs::write(&proxy_file, "").unwrap();
    let proxy = run_with_env_file(&["system", "proxy", "on", "--yes"], &proxy_file);
    assert!(proxy.status.success(), "{}", stderr(&proxy));
    let proxy_effects = fs::read_to_string(proxy_file).unwrap();
    assert!(proxy_effects.contains("S\thttp_proxy\thttp://127.0.0.1:7890"));
    assert!(proxy_effects.contains("S\tNO_PROXY\t127.0.0.1,localhost"));

    let repo_file = root.join("repo");
    fs::write(&repo_file, "").unwrap();
    let repo = run_with_env_file(&["system", "repo", "google", "--yes"], &repo_file);
    assert!(repo.status.success(), "{}", stderr(&repo));
    assert_eq!(
        fs::read_to_string(repo_file).unwrap(),
        "S\tREPO_URL\thttps://gerrit.googlesource.com/git-repo\n"
    );
}

#[test]
fn grep_searches_without_shell_option_injection() {
    let search = run(&["grep", "python", "def _search"]);
    assert!(search.status.success());
    assert!(stdout(&search).contains("plugins/grep/grep.py:"));

    let files = run(&["grep", "rust", "pub fn", "-l"]);
    assert!(files.status.success());
    assert!(stdout(&files).contains("rust/crates/gs-core/src/lib.rs"));

    let bad = run(&["grep", "python", "["]);
    assert_eq!(bad.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad.stderr).contains("无效正则表达式"));
}

#[test]
fn spider_validates_targets_and_output_boundaries() {
    let info = run(&["plugin", "info", "spider"]);
    assert!(info.status.success());
    assert!(stdout(&info).contains("spider"));

    let classify = run(&["spider", "classify", "https://www.jianshu.com/p/abc123"]);
    assert!(classify.status.success());
    assert!(stdout(&classify).contains("平台: 简书"));

    let username = run(&["spider", "crawl", "example-user"]);
    assert_eq!(username.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&username.stderr).contains("完整 URL"));

    let invalid = run(&["spider", "classify", "https://evil.example.com/x"]);
    assert_eq!(invalid.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("不支持"));

    let outside = run(&[
        "spider",
        "crawl",
        "https://www.jianshu.com/p/abc123",
        "../outside",
    ]);
    assert_eq!(outside.status.code(), Some(2));
}

#[test]
fn multirepo_inspects_builtin_manifest_without_network() {
    let info = run(&["plugin", "info", "multirepo"]);
    assert!(info.status.success());
    assert!(stdout(&info).contains("multirepo"));

    let manifests = run(&["multirepo", "list"]);
    assert!(manifests.status.success());
    assert!(stdout(&manifests).contains("mini-aosp"));

    let manifest = run(&["multirepo", "manifest", "mini-aosp"]);
    assert!(manifest.status.success());
    assert!(stdout(&manifest).contains("Projects:"));
    assert!(stdout(&manifest).contains("platform/art"));

    let status = run(&["multirepo", "status"]);
    assert!(status.status.success());
    assert!(stdout(&status).contains("MultiRepo 状态"));

    let projects = run(&["multirepo", "projects", "mini-aosp"]);
    assert!(projects.status.success());
    assert!(stdout(&projects).contains("汇总:"));

    let diff = run(&["multirepo", "diff", "mini-aosp"]);
    assert!(diff.status.success() || diff.status.code() == Some(1));
    assert!(stdout(&diff).contains("Manifest/工作区差异"));

    let plan = run(&[
        "multirepo",
        "init",
        "mini-aosp",
        "--backend=git",
        "--dry-run",
    ]);
    assert!(plan.status.success());
    assert!(stdout(&plan).contains("dry-run"));
    assert!(stdout(&plan).contains("不会执行"));

    let unsafe_init = run(&["multirepo", "init", "mini-aosp"]);
    assert_eq!(unsafe_init.status.code(), Some(2));

    let repo_plan = run(&[
        "multirepo",
        "init",
        "mini-aosp",
        "--backend=repo",
        "--dry-run",
    ]);
    assert!(repo_plan.status.success());
    assert!(stdout(&repo_plan).contains("repo init"));

    let bad_option = run(&["multirepo", "init", "mini-aosp", "--dry-run", "--force"]);
    assert_eq!(bad_option.status.code(), Some(2));

    let options_first = run(&["multirepo", "init", "--dry-run", "mini-aosp"]);
    assert!(options_first.status.success());
    assert!(stdout(&options_first).contains("Manifest:"));

    let json_plan = run(&[
        "multirepo",
        "init",
        "mini-aosp",
        "--backend=git",
        "--dry-run",
        "--format=json",
    ]);
    assert!(json_plan.status.success());
    let value: serde_json::Value = serde_json::from_slice(&json_plan.stdout).unwrap();
    assert_eq!(value["mode"], "dry-run");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["plan_id"].as_str().unwrap().len(), 16);
    assert!(value["generated_at"].as_str().unwrap().ends_with("+00:00"));
    assert_eq!(value["backend"], "git");
    assert_eq!(value["check"]["ok"], true);
    assert!(value["summary"]["project_count"].as_u64().unwrap() > 0);
    assert_eq!(value["summary"]["network_required"], true);

    let alias_plan = run(&["multirepo", "plan", "mini-aosp", "--backend=git"]);
    assert!(alias_plan.status.success());
    let alias_value: serde_json::Value = serde_json::from_slice(&alias_plan.stdout).unwrap();
    assert_eq!(alias_value["schema_version"], 1);
    let plan_file = std::env::temp_dir().join(format!("gs-plan-{}.json", std::process::id()));
    fs::write(&plan_file, &json_plan.stdout).unwrap();
    let verified = run(&["multirepo", "verify-plan", plan_file.to_str().unwrap()]);
    assert!(verified.status.success());
    assert!(stdout(&verified).contains("计划有效"));
    let mut tampered: serde_json::Value = serde_json::from_slice(&json_plan.stdout).unwrap();
    tampered["backend"] = serde_json::Value::String("repo".into());
    fs::write(&plan_file, serde_json::to_vec(&tampered).unwrap()).unwrap();
    let rejected = run(&["multirepo", "verify-plan", plan_file.to_str().unwrap()]);
    assert_eq!(rejected.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("不匹配"));
    let _ = fs::remove_file(plan_file);

    let mismatch = run(&["multirepo", "verify-plan", "/tmp/does-not-exist-plan.json"]);
    assert_eq!(mismatch.status.code(), Some(2));

    let checked = run(&[
        "multirepo",
        "init",
        "mini-aosp",
        "--backend=git",
        "--dry-run",
        "--check",
    ]);
    assert!(checked.status.success());

    let bad_format = run(&[
        "multirepo",
        "init",
        "mini-aosp",
        "--dry-run",
        "--format=text",
    ]);
    assert_eq!(bad_format.status.code(), Some(2));

    let root = std::env::temp_dir().join(format!("gs-bad-manifest-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let bad = root.join("bad.xml");
    fs::write(
        &bad,
        r#"<manifest><project name="evil" path="../outside"/></manifest>"#,
    )
    .unwrap();
    let bad_path = bad.to_string_lossy().into_owned();
    let bad_manifest = run(&["multirepo", "manifest", &bad_path]);
    assert_eq!(bad_manifest.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad_manifest.stderr).contains("不安全"));
    let _ = fs::remove_dir_all(root);
}

#[test]
fn vscode_inspects_environment_and_only_plans_launch() {
    let info = run(&["plugin", "info", "vscode"]);
    assert!(info.status.success());
    assert!(stdout(&info).contains("vscode"));

    let paths = run(&["vscode", "paths"]);
    assert!(paths.status.success());
    assert!(stdout(&paths).contains("extensions:"));

    let profiles = run(&["vscode", "list"]);
    assert!(profiles.status.success());
    assert!(stdout(&profiles).contains("VS Code Profiles"));

    let missing_profile = run(&["vscode", "info", "does-not-exist"]);
    assert_eq!(missing_profile.status.code(), Some(1));

    let plan = run(&["vscode", "start", "default", "--dry-run"]);
    assert!(plan.status.success());
    assert!(stdout(&plan).contains("不会执行"));

    let unsafe_start = run(&["vscode", "start", "default"]);
    assert_eq!(unsafe_start.status.code(), Some(2));

    let json_start = run(&["vscode", "start", "default", "--dry-run", "--format=json"]);
    assert!(json_start.status.success());
    let start_plan: serde_json::Value = serde_json::from_slice(&json_start.stdout).unwrap();
    assert_eq!(start_plan["schema_version"], 1);
    assert_eq!(start_plan["mode"], "dry-run");
    assert_eq!(start_plan["writes_required"], false);
}

#[test]
fn android_uses_formal_plugin_name_after_in_place_merge() {
    let info = run(&["plugin", "info", "android"]);
    assert!(info.status.success());
    assert!(stdout(&info).contains("android"));
    assert!(stdout(&info).contains("命令 ("));

    let devices = run(&["android", "device", "devices"]);
    assert!(
        devices.status.code() == Some(0)
            || devices.status.code() == Some(1)
            || devices.status.code() == Some(127)
    );

    let current = run(&["android", "device", "current"]);
    assert!(current.status.code() == Some(0) || current.status.code() == Some(1));

    let completion = run(&["__complete", "android", "device", "select"]);
    assert!(completion.status.success());
    assert!(stdout(&completion).contains(":4"));
    let fs_completion = run(&["__complete", "android", "fs", "exists"]);
    assert!(fs_completion.status.success());
    assert!(stdout(&fs_completion).contains(":0"));
    let app_completion = run(&["__complete", "android", "app", "version"]);
    assert!(app_completion.status.success());
    assert!(stdout(&app_completion).contains(":4"));

    let doctor = run(&["android", "doctor"]);
    assert!(matches!(doctor.status.code(), Some(0) | Some(1)));
    assert!(stdout(&doctor).contains("Android GS 6.0 doctor"));

    let bad_connect = run(&["android", "device", "connect", "host;id"]);
    assert_eq!(bad_connect.status.code(), Some(2));
    let bad_fs_path = run(&["android", "fs", "ls", "/system/bin;id"]);
    assert_eq!(bad_fs_path.status.code(), Some(2));
    let bad_package = run(&["android", "proc", "am-anr", "pkg;id"]);
    assert_eq!(bad_package.status.code(), Some(2));
    for args in [
        &["android", "dump", "meminfo", "pkg;id"][..],
        &["android", "dump", "appops", "pkg;id"][..],
        &["android", "fs", "find_apk", "pkg;id"][..],
        &["android", "app", "version", "pkg;id"][..],
        &["android", "app", "log", "pkg;id"][..],
    ] {
        assert_eq!(run(args).status.code(), Some(2));
    }
    let bad_frida = run(&[
        "android",
        "frida",
        "inject",
        "-p",
        "bad;id",
        "-f",
        "test.js",
        "--dry-run",
    ]);
    assert_eq!(bad_frida.status.code(), Some(2));
    let perfetto_bad = run(&[
        "android",
        "perfetto",
        "default",
        "../outside.trace",
        "--dry-run",
    ]);
    assert_eq!(perfetto_bad.status.code(), Some(2));

    let dump_info = run(&["plugin", "info", "android"]);
    assert!(dump_info.status.success());
    assert!(stdout(&dump_info).contains("dump"));
    assert!(stdout(&dump_info).contains("battery"));

    let appops_missing = run(&["android", "dump", "appops"]);
    assert_eq!(appops_missing.status.code(), Some(2));

    let bad_top = run(&["android", "dump", "top", "not-a-number"]);
    assert_eq!(bad_top.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&bad_top.stderr).contains("整数"));

    for args in [
        &["android", "emulator", "path"][..],
        &["android", "emulator", "status"][..],
        &["android", "emulator", "list"][..],
    ] {
        let result = run(args);
        assert!(matches!(result.status.code(), Some(0) | Some(1)));
    }
    let start_plan = run(&["android", "emulator", "start", "--dry-run"]);
    assert!(start_plan.status.success());
    assert!(stdout(&start_plan).contains("不会启动进程"));
    let unsafe_start = run(&["android", "emulator", "start"]);
    assert_eq!(unsafe_start.status.code(), Some(2));
    let stop_plan = run(&["android", "emulator", "stop", "--dry-run"]);
    assert!(stop_plan.status.success());
    assert!(stdout(&stop_plan).contains("不会停止进程"));

    let input = run(&["android", "input", "tap", "100", "200", "--dry-run"]);
    assert!(input.status.success());
    assert!(stdout(&input).contains("不会向设备发送事件"));
    let real_input = run(&["android", "input", "tap", "100", "200"]);
    assert!(matches!(
        real_input.status.code(),
        Some(0) | Some(1) | Some(127)
    ));

    let swipe = run(&["android", "input", "swipe", "1", "2", "3", "4", "--dry-run"]);
    assert!(swipe.status.success());
    assert!(stdout(&swipe).contains("不会向设备发送事件"));
    let record = run(&["android", "input", "screenrecord", "demo", "--dry-run"]);
    assert!(record.status.success());
    assert!(stdout(&record).contains("不会启动录屏"));

    let push = run(&[
        "android",
        "fs",
        "push",
        "missing.file",
        "/sdcard/x",
        "--dry-run",
    ]);
    assert_eq!(push.status.code(), Some(1));
    let pull = run(&["android", "fs", "pull", "/sdcard/x", "./x", "--dry-run"]);
    assert!(pull.status.success());
    assert!(stdout(&pull).contains("不会传输文件"));

    for unsafe_args in [
        &["android", "winscope", "start"][..],
        &["android", "winscope", "proxy"][..],
        &["android", "device", "connect", "192.0.2.1:5555"][..],
        &["android", "device", "disconnect", "192.0.2.1:5555"][..],
        &["android", "device", "screencap", "screen.png"][..],
    ] {
        assert_eq!(run(unsafe_args).status.code(), Some(2));
    }
    for dry_run_args in [
        &["android", "frida", "server", "start", "--dry-run"][..],
        &["android", "winscope", "start", "--dry-run"][..],
        &["android", "winscope", "proxy", "--dry-run"][..],
        &[
            "android",
            "device",
            "connect",
            "192.0.2.1:5555",
            "--dry-run",
        ][..],
        &[
            "android",
            "device",
            "disconnect",
            "192.0.2.1:5555",
            "--dry-run",
        ][..],
        &["android", "device", "screencap", "screen.png", "--dry-run"][..],
    ] {
        let plan = run(dry_run_args);
        assert!(plan.status.success());
        assert!(stdout(&plan).contains("不会"));
    }
    let perfetto_plan = run(&["android", "perfetto", "default", "--dry-run"]);
    assert!(perfetto_plan.status.success());
    assert!(stdout(&perfetto_plan).contains("Duration: 20s"));
    let frida_status = run(&["android", "frida", "server", "status"]);
    assert!(frida_status.status.success());
    let frida_bad = run(&[
        "android",
        "frida",
        "inject",
        "-p",
        "bad;id",
        "-f",
        "test.js",
        "--dry-run",
    ]);
    assert_eq!(frida_bad.status.code(), Some(2));
}

#[test]
fn gs6_excludes_legacy_menubar_plugin() {
    let list = run(&["plugin", "list"]);
    assert!(list.status.success());
    let text = stdout(&list);
    assert!(text.contains("menubar 已移除"));
    assert!(!text.lines().any(|line| line.contains("│ menubar")));
}

#[test]
fn alias_inspection_is_read_only_and_detects_sources() {
    let info = run(&["plugin", "info", "alias"]);
    assert!(info.status.success());
    assert!(stdout(&info).contains("alias"));

    let sources = run(&["alias", "sources", "bash"]);
    assert!(sources.status.success());
    assert!(stdout(&sources).contains("plugins/alias/common/aliases.sh"));

    let list = run(&["alias", "list", "bash"]);
    assert!(list.status.success());
    assert!(stdout(&list).contains("rm"));

    let show = run(&["alias", "show", "l", "bash"]);
    assert!(show.status.success());
    assert!(stdout(&show).contains("l="));

    let doctor = run(&["alias", "doctor", "bash"]);
    assert!(doctor.status.success() || doctor.status.code() == Some(1));
    assert!(stdout(&doctor).contains("Alias 体检"));
}

#[test]
fn navigator_and_devenv_are_offline_safe() {
    let nav = run(&["navigator", "list"]);
    assert!(nav.status.success());
    assert!(stdout(&nav).contains("/code/github/global_scripts"));
    assert!(!stdout(&nav).contains("$HOME"));

    let nav_status = run(&["navigator", "status"]);
    assert!(nav_status.status.success());
    assert!(stdout(&nav_status).contains("当前位置:"));

    let validate = run(&["devenv", "validate"]);
    assert!(validate.status.success());
    assert!(stdout(&validate).contains("验证通过"));

    let unsafe_install = run(&["devenv", "install", "definitely-missing-tool"]);
    assert_eq!(unsafe_install.status.code(), Some(2));

    let plan = run(&["devenv", "install", "definitely-missing-tool", "--dry-run"]);
    assert_eq!(plan.status.code(), Some(1));

    let nav_complete = run(&["__complete", "navigator"]);
    assert!(nav_complete.status.success());
    assert!(stdout(&nav_complete).contains("global-scripts"));

    let devenv_complete = run(&["__complete", "devenv", "install"]);
    assert!(devenv_complete.status.success());
    assert!(stdout(&devenv_complete).contains("--dry-run"));
}

#[test]
fn cd_output_requires_preexisting_target_file() {
    let valid = std::env::temp_dir().join(format!("gs-cd-valid-{}", std::process::id()));
    fs::write(&valid, "").unwrap();
    let ok = Command::new(gs_bin())
        .args(["navigator", "global-scripts"])
        .env("GS_ROOT", repo_root())
        .env("GS_CD_FILE", &valid)
        .output()
        .unwrap();
    assert!(ok.status.success());

    let result = Command::new(gs_bin())
        .args(["navigator", "global-scripts"])
        .env("GS_ROOT", repo_root())
        .env(
            "GS_CD_FILE",
            std::env::temp_dir().join("gs-missing-cd-file"),
        )
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
}

#[test]
fn dotfiles_inspects_and_plans_without_writing_home() {
    let info = run(&["plugin", "info", "dotfiles"]);
    assert!(info.status.success());
    assert!(stdout(&info).contains("dotfiles"));

    let status = run(&["dotfiles", "status", "zsh"]);
    assert!(status.status.success());
    assert!(stdout(&status).contains("plugins/dotfiles/zsh/.zshrc"));

    let plan = run(&["dotfiles", "plan", "zsh", "install", "--dry-run"]);
    assert!(plan.status.success());
    assert!(stdout(&plan).contains("不会执行复制、覆盖或删除"));

    let unsafe_plan = run(&["dotfiles", "plan", "zsh", "install"]);
    assert_eq!(unsafe_plan.status.code(), Some(2));

    let doctor = run(&["dotfiles", "doctor"]);
    assert!(doctor.status.success());
    assert!(stdout(&doctor).contains("越界目标: 无"));

    let json_plan = run(&[
        "dotfiles",
        "plan",
        "zsh",
        "install",
        "--dry-run",
        "--format=json",
    ]);
    assert!(json_plan.status.success());
    let plan: serde_json::Value = serde_json::from_slice(&json_plan.stdout).unwrap();
    assert_eq!(plan["schema_version"], 1);
    assert_eq!(plan["mode"], "dry-run");
    assert_eq!(plan["check"]["ok"], true);

    let plan_file =
        std::env::temp_dir().join(format!("gs-dotfiles-plan-{}.json", std::process::id()));
    fs::write(&plan_file, &json_plan.stdout).unwrap();
    let verified = run(&["dotfiles", "verify-plan", plan_file.to_str().unwrap()]);
    assert!(verified.status.success());
    assert!(stdout(&verified).contains("计划有效"));
    let _ = fs::remove_file(plan_file);
}

#[test]
fn enable_disable_isolated_manifest_and_dispatch() {
    let root = std::env::temp_dir().join(format!(
        "gs-frontdoor-toggle-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let plugins = root.join("plugins");
    let plugin_dir = plugins.join("toggle");
    fs::create_dir_all(&plugin_dir).unwrap();
    fs::write(
        plugin_dir.join("plugin.toml"),
        r#"name="toggle"
version="1.0.0"
tier="declarative"
enabled=true
[capabilities]
exec=["echo"]
[[commands]]
name="hello"
run="echo toggle-ok"
"#,
    )
    .unwrap();
    let config = root.join("gs.json");
    fs::write(&config, r#"{"system_plugins":{},"custom_plugins":{}}"#).unwrap();

    let base = |args: &[&str]| {
        Command::new(gs_bin())
            .args(args)
            .env("GS_ROOT", repo_root())
            .env("GS_ALLOW_LEGACY", "1")
            .env("GS_PLUGIN_PATH", &plugins)
            .env("GS_CONFIG_FILE", &config)
            .output()
            .expect("run isolated gs")
    };

    let disable = base(&["plugin", "disable", "toggle"]);
    assert!(disable.status.success());
    assert!(fs::read_to_string(plugin_dir.join("plugin.toml"))
        .unwrap()
        .contains("enabled = false"));
    let blocked = base(&["toggle", "hello"]);
    assert_eq!(blocked.status.code(), Some(1));

    let enable = base(&["plugin", "enable", "toggle"]);
    assert!(enable.status.success());
    let executed = base(&["toggle", "hello"]);
    assert!(executed.status.success());
    assert!(stdout(&executed).contains("toggle-ok"));

    let _ = fs::remove_dir_all(root);
}
