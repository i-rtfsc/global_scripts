//! Tab completion and shell integration (`gs __complete`, `gs completions`,
//! `gs shell-init`) — the shell scripts are embedded verbatim below.

use crate::{command_name, detect_locale, engine_roots, run, ui};
use gs_core::index::Registry;
use std::path::PathBuf;

pub(crate) fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

pub(crate) fn powershell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// Fish single-quote escaping: inside `'…'` only `\` and `'` need escaping.
pub(crate) fn fish_quote(s: &str) -> String {
    format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'"))
}

pub(crate) const SYSTEM_CMDS: &[(&str, &str, &[&str])] = &[
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

/// `gs __complete <completed words…>` — the completion engine. Prints one
/// candidate per line as `value` or `value\tdescription` (locale-picked), then a
/// final Cobra-style directive line `:<bits>` controlling file/dir fallback.
/// Candidates come from the front door's own commands and the plugin manifests
/// (including dynamic arg rules). Quiet and best-effort.
pub(crate) fn cmd_complete(completed: &[String]) -> i32 {
    use gs_core::engine;
    let locale = detect_locale();
    let registry = Registry::discover(&engine_roots());

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
pub(crate) fn cmd_completions(args: &[String]) -> i32 {
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
pub(crate) fn completion_install_path(shell: &str, name: &str) -> Option<PathBuf> {
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

pub(crate) fn render_completion_script(shell: &str, script: &str, requested_name: &str) -> String {
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
pub(crate) fn cmd_shell_init(args: &[String]) -> i32 {
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

// Fish's `command` is a builtin, so it cannot sit behind `env` (an external
// program) — that mismatch made every `gs` call fail with
// "env: 'command': No such file or directory". Export through `env` and exec
// the binary directly instead; `command` is still used where it is a builtin.
pub(crate) const SHELLINIT_FISH: &str = r#"# gs fish 外壳集成（cd 支持）。启用：gs shell-init fish > ~/.config/fish/conf.d/gs.fish
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

pub(crate) const SHELLINIT_POSIX: &str = r#"# gs bash/zsh 外壳集成（cd 支持）。
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

pub(crate) const SHELLINIT_POWERSHELL: &str = r#"# gs PowerShell shell integration (cd + environment effects).
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

pub(crate) const COMP_BASH: &str = r#"# gs bash completion.  Enable: source <(gs completions bash)
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

pub(crate) const COMP_ZSH: &str = r#"# gs zsh completion.  Enable (after compinit): source <(gs completions zsh)
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

pub(crate) const COMP_FISH: &str = r#"# gs fish completion.  Enable: gs completions fish > ~/.config/fish/completions/gs.fish
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

pub(crate) const COMP_NUSHELL: &str = r#"# gs nushell completion (experimental).  Add to your config.nu.
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

pub(crate) const COMP_POWERSHELL: &str = r#"# gs PowerShell completion (experimental).  Add to your $PROFILE.
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
