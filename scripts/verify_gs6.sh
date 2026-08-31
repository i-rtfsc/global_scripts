#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/rust/target/debug/gs"
EXPECTED_VERSION="${GS6_EXPECT_VERSION:-6.0.0-dev}"

if [[ ! -x "$BIN" ]]; then
  echo "GS 6.0 开发版尚未构建，先执行：" >&2
  echo "  cargo build --manifest-path '$ROOT/rust/Cargo.toml' -p gs" >&2
  exit 2
fi

export GS_ROOT="$ROOT"
export GS_VERIFY_BIN="$BIN"
unset GS_ALLOW_LEGACY
export GS_INCLUDE_EXAMPLES=1
VERIFY_CACHE="$(mktemp -d "${TMPDIR:-/tmp}/gs6-verify.XXXXXX")"
trap 'rm -rf "$VERIFY_CACHE"' EXIT
export GS_CACHE_DIR="$VERIFY_CACHE"
export GS6_ANDROID_STATE_DIR="$VERIFY_CACHE/android-state"

python3 "$ROOT/scripts/prepare_gs6_release.py" --version "$EXPECTED_VERSION"

test ! -e "$ROOT/plugins/menubar/plugin.toml"
formal_count=0
for manifest in "$ROOT"/plugins/*/plugin.toml; do
  [[ -f "$manifest" ]] || continue
  dir_name="$(basename "$(dirname "$manifest")")"
  manifest_name="$(sed -n 's/^name[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest" | head -1)"
  manifest_version="$(sed -n 's/^version[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' "$manifest" | head -1)"
  test "$dir_name" = "$manifest_name"
  test "$manifest_version" = "$EXPECTED_VERSION"
  formal_count=$((formal_count + 1))
done
test "$formal_count" -eq 15
python3 - <<'PY'
import ast
import os
from pathlib import Path

root = Path(os.environ["GS_ROOT"])
entries = []
for manifest in sorted((root / "plugins").glob("*/plugin.toml")):
    text = manifest.read_text(encoding="utf-8")
    runtime = next((line.split("=", 1)[1].strip().strip('"') for line in text.splitlines()
                    if line.startswith("runtime")), None)
    entry = next((line.split("=", 1)[1].strip().strip('"') for line in text.splitlines()
                  if line.startswith("entry")), None)
    if runtime == "python" and entry:
        entries.append(manifest.parent / entry)
for path in entries:
    ast.parse(path.read_text(encoding="utf-8"), filename=str(path), feature_version=(3, 8))
print("Python 3.8 AST compatibility: {} entries".format(len(entries)))
PY
# The source front door is now authoritative: all 15 retained plugins are formal
# manifests and no legacy inventory remains.
default_plugins="$(env -u GS_INCLUDE_EXAMPLES "$BIN" plugin list)"
grep -q 'android' <<<"$default_plugins"
grep -q "$EXPECTED_VERSION" <<<"$default_plugins"
grep -q '插件库存' <<<"$default_plugins"
grep -q '正式 15' <<<"$default_plugins"
grep -q 'legacy 0' <<<"$default_plugins"
grep -q 'GS5.2 命令基线' <<<"$default_plugins"
if grep -qE 'demo|json-simple|json-with-subplugins' <<<"$default_plugins"; then
  echo 'example plugins leaked into default GS6 plugin surface' >&2
  exit 1
fi

echo '== GS 6.0 development verification =='
"$BIN" version
"$BIN" doctor
"$BIN" status
"$BIN" refresh
"$BIN" plugin info demo >/dev/null
if plugin_unknown="$("$BIN" plugin android 2>&1)"; then
  echo "plugin android unexpectedly succeeded" >&2
  exit 1
fi
grep -q "plugin 没有命令 'android'" <<<"$plugin_unknown"
! grep -q 'ModuleNotFoundError' <<<"$plugin_unknown"
test "$("$BIN" demo greet verify)" = 'Hello, verify!'
"$BIN" __complete demo paint --color | grep -q $'red\twarm'
"$BIN" plugin info system >/dev/null
"$BIN" plugin info android >/dev/null
for contract in \
  'alias:sources' 'devenv:validate' 'dotfiles:verify-plan' 'identity:ssh status' \
  'flyme:info' \
  'grep:python' 'multirepo:verify-plan' 'navigator:global-scripts' \
  'sgm:build list' 'spider:classify' 'sync:status' 'system:proxy status' 'vps:status' 'vscode:start'; do
  plugin="${contract%%:*}"
  command="${contract#*:}"
  info_output="$("$BIN" plugin info "$plugin")"
  grep -q "$command" <<<"$info_output"
done
"$BIN" alias sources bash >/dev/null
"$BIN" devenv validate >/dev/null
"$BIN" dotfiles doctor >/dev/null
"$BIN" flyme info | grep -q 'FlymeOS Development Plugin'
"$BIN" grep python 'def _search' >/dev/null
"$BIN" multirepo list >/dev/null
"$BIN" navigator status >/dev/null
"$BIN" spider classify 'https://www.jianshu.com/p/verify' >/dev/null
"$BIN" system proxy status >/dev/null
"$BIN" system proxy on --dry-run | grep -q '不会修改当前 shell'
"$BIN" system proxy off --dry-run | grep -q '不会修改当前 shell'
for source in google intel tsinghua; do
  "$BIN" system repo "$source" --dry-run | grep -q '不会修改当前 shell'
done
for source in github ustc tsinghua aliyun; do
  "$BIN" system brew "$source" --dry-run | grep -q '不会修改 Git remote'
done
"$BIN" vscode paths >/dev/null
"$BIN" vps help | grep -q 'VPS commands'
"$BIN" vps status | grep -q 'VPS 状态'
for command in ssh tunnel stop mount unmount remount; do
  "$BIN" vps "$command" --dry-run | grep -q '不会'
done

# Identity uses generated private fixtures. No real account JSON, SSH key, or
# Git identity asset is read by this verification.
identity_assets="$VERIFY_CACHE/identity-assets"
identity_home="$VERIFY_CACHE/identity-home"
mkdir -p "$identity_assets/ssh" "$identity_assets/git/hooks" "$identity_home"
cat > "$identity_assets/config.json" <<'JSON'
{
  "defaults": {"router": "anyrouter", "model": "claude", "account": "outlook"},
  "routers": {
    "anyrouter": {
      "name": "Fixture Router",
      "default_node": "main",
      "supports": ["claude", "gemini"],
      "base_urls": {"main": "https://fixture.invalid/main", "backup": "https://fixture.invalid/backup"}
    },
    "agentrouter": {
      "name": "Fixture Agent Router",
      "default_node": "main",
      "supports": ["claude", "gpt"],
      "base_urls": {"main": "https://agent.fixture.invalid"}
    },
    "codemirror": {
      "name": "Fixture CodeMirror",
      "default_node": "main",
      "supports": ["claude", "gpt"],
      "base_urls": {"main": "https://codemirror.fixture.invalid"}
    }
  },
  "accounts": {
    "claude": {"outlook": {"email": "fixture@example.invalid", "api_keys": {"anyrouter": "fixture-secret-token"}}},
    "gpt": {"outlook": {"email": "fixture@example.invalid", "api_keys": {"agentrouter": "fixture-gpt-token"}}},
    "gemini": {"outlook": {"email": "fixture@example.invalid", "api_keys": {"anyrouter": "fixture-gemini-token"}}}
  }
}
JSON
printf 'fixture-private-key\n' > "$identity_assets/ssh/id_ed25519"
printf 'fixture-public-key\n' > "$identity_assets/ssh/id_ed25519.pub"
printf 'Host fixture\n' > "$identity_assets/ssh/config"
printf 'fixture-host ssh-ed25519 AAAA\n' > "$identity_assets/ssh/known_hosts"
printf '[user]\n  name = Fixture\n' > "$identity_assets/git/.gitconfig-user"
printf '[user]\n  email = fixture@example.invalid\n' > "$identity_assets/git/.gitconfig-work"
printf 'Fixture commit\n' > "$identity_assets/git/work-commit-template.git"
printf '[include]\n  path = ~/.config/global-scripts/git/.gitconfig-user\n' > "$identity_assets/git/.gitconfig"
printf '#!/bin/sh\nexit 0\n' > "$identity_assets/git/hooks/commit-msg"
identity_show="$(HOME="$identity_home" GS_IDENTITY_DIR="$identity_assets" "$BIN" identity claude show)"
grep -q 'fixture@example.invalid' <<<"$identity_show"
! grep -q 'fixture-secret-token' <<<"$identity_show"
identity_effect="$VERIFY_CACHE/identity-effect"
: > "$identity_effect"
HOME="$identity_home" GS_IDENTITY_DIR="$identity_assets" GS_ENV_FILE="$identity_effect" \
  "$BIN" identity claude outlook anyrouter:backup | grep -q 'API key: 已加载（未显示）'
grep -q $'S\tANTHROPIC_BASE_URL\thttps://fixture.invalid/backup' "$identity_effect"
grep -q $'S\tANTHROPIC_AUTH_TOKEN\tfixture-secret-token' "$identity_effect"
HOME="$identity_home" GS_IDENTITY_DIR="$identity_assets" "$BIN" identity git install --dry-run | grep -q '不会写入配置'
HOME="$identity_home" GS_IDENTITY_DIR="$identity_assets" "$BIN" identity git install --yes | grep -q '已安装'
HOME="$identity_home" GS_IDENTITY_DIR="$identity_assets" "$BIN" identity ssh install --dry-run | grep -q '不会复制密钥'
HOME="$identity_home" GS_IDENTITY_DIR="$identity_assets" "$BIN" identity ssh install --yes | grep -q '已安装'
IDENTITY_HOME="$identity_home" python3 - <<'PY'
import os
import stat
from pathlib import Path

home = Path(os.environ["IDENTITY_HOME"])
expected = {
    home / ".config/global-scripts/identity_state.json": 0o600,
    home / ".ssh": 0o700,
    home / ".ssh/id_ed25519": 0o600,
    home / ".ssh/id_ed25519.pub": 0o644,
}
for path, mode in expected.items():
    assert stat.S_IMODE(path.stat().st_mode) == mode, (path, oct(stat.S_IMODE(path.stat().st_mode)))
PY

# SGM uses generated private fixtures and fake local executors. No company
# network, real ADB device, or real RSA key is touched.
sgm_assets="$VERIFY_CACHE/sgm-assets"
sgm_home="$VERIFY_CACHE/sgm-home"
sgm_project="$sgm_assets/build/project"
sgm_exec="$VERIFY_CACHE/sgm-exec"
mkdir -p "$sgm_assets/build" "$sgm_assets/ssh" "$sgm_project/build/outputs" "$sgm_home" "$sgm_exec"
cat > "$sgm_assets/build/config.json" <<JSON
{
  "apps": {
    "fixture": {
      "project_path": "$sgm_project",
      "gradle_task": "assembleFixture",
      "apk_path": "build/outputs/fixture.apk",
      "target_path": "/system/app/Fixture.apk",
      "package_name": "com.example.fixture"
    }
  }
}
JSON
printf 'fixture-apk\n' > "$sgm_project/build/outputs/fixture.apk"
cat > "$sgm_project/gradlew" <<SH
#!/bin/sh
printf '%s\n' "\$@" > "$sgm_exec/gradle.log"
SH
cat > "$sgm_exec/adb" <<SH
#!/bin/sh
printf '%s\n' "\$@" >> "$sgm_exec/adb.log"
SH
cat > "$sgm_exec/ssh" <<SH
#!/bin/sh
printf '%s\n' "\$@" > "$sgm_exec/ssh.log"
SH
cat > "$sgm_exec/sshfs" <<SH
#!/bin/sh
printf '%s\n' "\$@" > "$sgm_exec/sshfs.log"
SH
chmod +x "$sgm_project/gradlew" "$sgm_exec/adb" "$sgm_exec/ssh" "$sgm_exec/sshfs"
printf 'fixture-sgm-private\n' > "$sgm_assets/ssh/id_rsa"
printf 'fixture-sgm-public\n' > "$sgm_assets/ssh/id_rsa.pub"
printf 'Host fixture-sgm\n  IdentityFile ~/.ssh/id_rsa_sgm\n' > "$sgm_assets/ssh/config"
HOME="$sgm_home" GS_SGM_DIR="$sgm_assets" "$BIN" sgm build list | grep -q fixture
for action in compile push restart run; do
  HOME="$sgm_home" GS_SGM_DIR="$sgm_assets" GS_SGM_ADB_BIN="$sgm_exec/adb" \
    "$BIN" sgm build "$action" fixture --dry-run | grep -q '不会编译、写入设备或重启进程'
done
HOME="$sgm_home" GS_SGM_DIR="$sgm_assets" "$BIN" sgm build compile fixture --yes | grep -q 'compile 完成'
grep -q '^assembleFixture$' "$sgm_exec/gradle.log"
HOME="$sgm_home" GS_SGM_DIR="$sgm_assets" GS_SGM_ADB_BIN="$sgm_exec/adb" \
  "$BIN" sgm build run fixture --yes | grep -q 'run 完成'
grep -q '^push$' "$sgm_exec/adb.log"
grep -q '^force-stop$' "$sgm_exec/adb.log"
HOME="$sgm_home" GS_SGM_DIR="$sgm_assets" GS_SGM_SSH_BIN="$sgm_exec/ssh" \
  "$BIN" sgm connect server --dry-run | grep -q '不会建立公司网络连接'
HOME="$sgm_home" GS_SGM_DIR="$sgm_assets" GS_SGM_SSH_BIN="$sgm_exec/ssh" \
  "$BIN" sgm connect server --yes >/dev/null
grep -q '^22222$' "$sgm_exec/ssh.log"
HOME="$sgm_home" GS_SGM_DIR="$sgm_assets" GS_SGM_SSHFS_BIN="$sgm_exec/sshfs" \
  "$BIN" sgm connect mount --mount="$sgm_home/vm" --dry-run | grep -q '不会创建挂载或连接公司网络'
HOME="$sgm_home" GS_SGM_DIR="$sgm_assets" "$BIN" sgm ssh install --dry-run | grep -q '不会复制密钥'
HOME="$sgm_home" GS_SGM_DIR="$sgm_assets" "$BIN" sgm ssh install --yes | grep -q '已安装'
SGM_HOME="$sgm_home" python3 - <<'PY'
import os
import stat
from pathlib import Path

home = Path(os.environ["SGM_HOME"])
expected = {
    home / ".ssh": 0o700,
    home / ".ssh/id_rsa_sgm": 0o600,
    home / ".ssh/id_rsa_sgm.pub": 0o644,
    home / ".ssh/config": 0o644,
}
for path, mode in expected.items():
    assert stat.S_IMODE(path.stat().st_mode) == mode, (path, oct(stat.S_IMODE(path.stat().st_mode)))
PY
sgm_git="$VERIFY_CACHE/sgm-git"
git init -q "$sgm_git"
git -C "$sgm_git" config user.email gs6@example.invalid
git -C "$sgm_git" config user.name GS6
printf 'fixture\n' > "$sgm_git/file.txt"
git -C "$sgm_git" add file.txt
git -C "$sgm_git" -c core.hooksPath=/dev/null commit -qm initial
(cd "$sgm_git" && HOME="$sgm_home" GS_SGM_DIR="$sgm_assets" \
  "$BIN" sgm git push --dry-run) | grep -q '不会联网或推送代码'
for shell in bash zsh fish; do
  completion="$($BIN completions "$shell")"
  grep -q '__complete' <<<"$completion"
  ! grep -q 'python\|router.json' <<<"$completion"
  named_completion="$(GS_COMMAND_NAME=gs6 "$BIN" completions "$shell")"
  grep -q 'gs6' <<<"$named_completion"
  ! grep -qE 'compdef _gs_complete gs$|complete -F _gs_complete gs$|complete -c gs ' <<<"$named_completion"
done
for shell in bash zsh fish powershell; do
  init="$($BIN shell-init "$shell")"
  grep -q 'GS_CD_FILE' <<<"$init"
  grep -q 'GS_ENV_FILE' <<<"$init"
  grep -q '__complete' <<<"$init"
  ! grep -q 'python\|router.json' <<<"$init"
done
"$BIN" android doctor >/dev/null 2>&1 || test $? -eq 1
for action in ninja-clean make build qssi vendor; do
  "$BIN" android build "$action" --dry-run | grep -q '不会执行构建'
done
"$BIN" android input tap 10 20 --dry-run | grep -q '不会向设备发送事件'
"$BIN" android logcat clear --dry-run | grep -q '不会修改设备'
"$BIN" android device screencap verify.png --dry-run | grep -q 'Output:'
"$BIN" android perfetto default --dry-run | grep -q 'Duration: 20s'
"$BIN" android device connect 192.0.2.1:5555 --dry-run | grep -q '不会修改设备'
"$BIN" android device disconnect 192.0.2.1:5555 --dry-run | grep -q '不会修改设备'
"$BIN" android input screenrecord verify 2 --dry-run | grep -q '不会启动录屏'
"$BIN" android winscope start --dry-run | grep -q '不会启动浏览器'
"$BIN" android frida inject -p system_server -f android-trace.js --dry-run | grep -q 'Device script:'
"$BIN" android frida server status >/dev/null
"$BIN" android emulator status >/dev/null 2>&1 || test $? -eq 1
"$BIN" system proxy status >/dev/null
"$BIN" system prompt themes | grep -q minimalist
"$BIN" grep python 'def _search' | grep -q 'plugins/grep/grep.py:'
"$BIN" spider classify 'https://www.jianshu.com/p/verify' | grep -q '平台: 简书'
"$BIN" spider install-deps --dry-run | grep -q '不会修改 Python 环境'
if "$BIN" spider classify 'https://invalid.example/verify' >/dev/null 2>&1; then
  echo 'spider invalid URL unexpectedly succeeded' >&2
  exit 1
fi
"$BIN" multirepo manifest mini-aosp | grep -q 'Projects:'
plan_json="$("$BIN" multirepo plan mini-aosp --backend=git)"
PLAN_JSON="$plan_json" python3 - <<'PY'
import json
import os

plan = json.loads(os.environ["PLAN_JSON"])
assert plan["schema_version"] == 1
assert len(plan["plan_id"]) == 16
assert plan["generated_at"].endswith("+00:00")
assert plan["mode"] == "dry-run"
assert plan["backend"] == "git"
assert plan["check"]["ok"] is True
assert plan["summary"]["project_count"] > 0
assert plan["summary"]["risk"] in {"medium", "high"}
PY
"$BIN" vscode paths | grep -q 'extensions:'
"$BIN" vscode start default --dry-run | grep -q '不会执行'
vscode_plan="$("$BIN" vscode start default --dry-run --format=json)"
VSCODE_PLAN="$vscode_plan" python3 - <<'PY'
import json, os
plan = json.loads(os.environ["VSCODE_PLAN"])
assert plan["schema_version"] == 1
assert plan["mode"] == "dry-run"
assert plan["writes_required"] is False
PY
"$BIN" alias sources bash | grep -q 'plugins/alias/common/aliases.sh'
"$BIN" alias show l bash | grep -q 'l='
"$BIN" dotfiles status zsh | grep -q 'plugins/dotfiles/zsh/.zshrc'
"$BIN" dotfiles plan zsh install --dry-run | grep -q '不会执行'
"$BIN" dotfiles doctor | grep -q '越界目标: 无'
"$BIN" dotfiles status nvim | grep -q 'missing=0, extra=0, changed=0'
nav_output="$("$BIN" navigator list)"
grep -q "$HOME/code/github/global_scripts" <<<"$nav_output"
"$BIN" devenv validate | grep -q '验证通过'
if "$BIN" devenv install definitely-missing-tool >/dev/null 2>&1; then
  echo 'devenv install without --dry-run unexpectedly succeeded' >&2
  exit 1
fi
dotfiles_plan_json="$("$BIN" dotfiles plan zsh install --dry-run --format=json)"
DOTFILES_PLAN_JSON="$dotfiles_plan_json" python3 - <<'PY'
import json
import os
plan = json.loads(os.environ["DOTFILES_PLAN_JSON"])
assert plan["schema_version"] == 1
assert plan["mode"] == "dry-run"
assert plan["check"]["ok"] is True
PY
dotfiles_json="$($BIN dotfiles plan zsh install --dry-run --format=json)"
dotfiles_file="$(mktemp "$VERIFY_CACHE/dotfiles-plan.XXXXXX")"
printf '%s\n' "$dotfiles_json" > "$dotfiles_file"
"$BIN" dotfiles verify-plan "$dotfiles_file" | grep -q '计划有效'

# Real apply paths are verified only inside an isolated temporary HOME.
dot_home="$VERIFY_CACHE/dot-home"
mkdir -p "$dot_home/.config/nvim"
printf 'old\n' > "$dot_home/.config/nvim/init.vim"
dot_apply="$VERIFY_CACHE/dot-apply.json"
HOME="$dot_home" "$BIN" dotfiles plan nvim install --dry-run --format=json > "$dot_apply"
HOME="$dot_home" "$BIN" dotfiles apply-plan "$dot_apply" --yes | grep -q '计划已应用'
cmp "$ROOT/plugins/dotfiles/nvim/init.vim" "$dot_home/.config/nvim/init.vim"
printf 'custom backup marker\n' > "$dot_home/.config/nvim/init.vim"
HOME="$dot_home" "$BIN" dotfiles backup nvim --yes | grep -q '配置已备份'
printf 'newer value\n' > "$dot_home/.config/nvim/init.vim"
HOME="$dot_home" "$BIN" dotfiles restore nvim --dry-run | grep -q '不会覆盖当前配置'
HOME="$dot_home" "$BIN" dotfiles restore nvim --yes | grep -q '配置已恢复'
grep -q 'custom backup marker' "$dot_home/.config/nvim/init.vim"
HOME="$dot_home" "$BIN" dotfiles plan nvim uninstall --dry-run --format=json > "$dot_apply"
HOME="$dot_home" "$BIN" dotfiles apply-plan "$dot_apply" --yes >/dev/null
test ! -e "$dot_home/.config/nvim"

# MultiRepo apply uses an empty local bare repository: real clone, no network.
multi="$VERIFY_CACHE/multirepo"
mkdir -p "$multi/work"
git init --bare "$multi/origin.git" >/dev/null
cat > "$multi/work/local.xml" <<XML
<manifest>
  <remote name="local" fetch="file://$multi" />
  <default remote="local" />
  <project name="origin.git" path="project-one" />
</manifest>
XML
(cd "$multi/work" && "$BIN" multirepo plan local.xml --backend=git) > "$multi/work/plan.json"
(cd "$multi/work" && "$BIN" multirepo apply-plan plan.json --yes) | grep -q '已克隆'
test -d "$multi/work/project-one/.git"
(cd "$multi/work" && "$BIN" multirepo sync local.xml --dry-run) | grep -q '不会联网或修改仓库'
(cd "$multi/work/project-one" && "$BIN" multirepo push --dry-run) | grep -q '不会联网或推送提交'
mkdir -p "$multi/work/.repo"
printf 'project-one\n' > "$multi/work/.repo/project.list"
(cd "$multi/work" && "$BIN" multirepo checkout --dry-run) | grep -q '不会创建或切换分支'

# Sync performs a real copy in an isolated local Git repository. Environment
# overrides keep the legacy /home/solo defaults out of the test.
sync_root="$VERIFY_CACHE/sync"
sync_source="$sync_root/source"
sync_target="$sync_root/target"
sync_repo="$sync_source/repo"
mkdir -p "$sync_repo" "$sync_target"
git -C "$sync_repo" init -q
git -C "$sync_repo" config user.email gs6@example.invalid
git -C "$sync_repo" config user.name GS6
printf 'base\n' > "$sync_repo/tracked.txt"
git -C "$sync_repo" add tracked.txt
git -C "$sync_repo" -c core.hooksPath=/dev/null commit -qm initial
printf 'changed\n' > "$sync_repo/tracked.txt"
printf 'new\n' > "$sync_repo/new.txt"
(cd "$sync_repo" && GS_SYNC_SOURCE_BASE="$sync_source" GS_SYNC_TARGET_BASE="$sync_target" \
  "$BIN" sync check) | grep -q '同步环境检查'
(cd "$sync_repo" && GS_SYNC_SOURCE_BASE="$sync_source" GS_SYNC_TARGET_BASE="$sync_target" \
  "$BIN" sync all --dry-run) | grep -q '不会复制或删除文件'
(cd "$sync_repo" && GS_SYNC_SOURCE_BASE="$sync_source" GS_SYNC_TARGET_BASE="$sync_target" \
  "$BIN" sync all --yes) | grep -q 'untracked new.txt'
cmp "$sync_repo/tracked.txt" "$sync_target/repo/tracked.txt"
cmp "$sync_repo/new.txt" "$sync_target/repo/new.txt"

# VS Code/DevEnv execution paths use fake executors, so the test performs real
# process spawning without opening a GUI or installing packages.
fake_code="$VERIFY_CACHE/fake-code.sh"
fake_brew="$VERIFY_CACHE/fake-brew.sh"
exec_log="$VERIFY_CACHE/executor.log"
vscode_log="$VERIFY_CACHE/vscode.log"
brew_log="$VERIFY_CACHE/brew.log"
cat > "$fake_code" <<SH
#!/bin/sh
printf '%s\n' "\$@" > "$vscode_log"
SH
cat > "$fake_brew" <<SH
#!/bin/sh
printf '%s\n' "\$@" > "$brew_log"
SH
chmod +x "$fake_code" "$fake_brew"
vscode_output="$(GS_VSCODE_BIN="$fake_code" "$BIN" vscode start default --yes)"
grep -q -- '--user-data-dir' <<<"$vscode_output"
GS_DEVENV_SKIP_CHECK=1 GS_DEVENV_BREW_BIN="$fake_brew" \
  "$BIN" devenv install wget --yes >/dev/null
grep -q '^install$' "$brew_log"
grep -q '^wget$' "$brew_log"

# Every formal plugin must expose an info view. Every real dotted command group
# must also be independently inspectable through `plugin info <plugin> <group>`.
# Leaf paths under `plugin info` are execution shortcuts, so they are tested by
# the command execution checks above rather than invoked in this metadata loop.
python3 - <<'PY'
import json
import os
import subprocess
import tomllib
from pathlib import Path

root = Path(os.environ["GS_ROOT"])
bin_path = Path(os.environ.get("GS_VERIFY_BIN", root / "rust/target/debug/gs"))
cache = Path(os.environ["GS_CACHE_DIR"])
for manifest_path in sorted((root / "plugins").glob("*/plugin.toml")):
    manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    name = manifest["name"]
    subprocess.run([str(bin_path), "plugin", "info", name], check=True,
                   stdout=subprocess.DEVNULL)
    commands = manifest.get("commands", [])
    cached = cache / "describe" / (name + ".json")
    if cached.is_file():
        commands = json.loads(cached.read_text(encoding="utf-8"))["result"]["commands"]
    groups = sorted({c["name"].split(".", 1)[0] for c in commands
                     if "." in c["name"] and not c.get("hidden")})
    for group in groups:
        subprocess.run([str(bin_path), "plugin", "info", name, group], check=True,
                       stdout=subprocess.DEVNULL)
print("Plugin info matrix: PASS")
PY

# Command parity must remain complete for every retained GS5.2 command.
parity_json="$(uv run python "$ROOT/scripts/audit_gs6_command_parity.py" --gs6-bin "$BIN" --json)"
PARITY_JSON="$parity_json" python3 - <<'PY'
import json
import os

value = json.loads(os.environ["PARITY_JSON"])
missing = value["missing"]
plugins = {item[0] for item in missing}
assert missing == [], missing
assert plugins == set(), plugins
print("Command parity: complete")
PY

GS6_BIN="$BIN" bash "$ROOT/scripts/verify_gs6_shells.sh"
bash "$ROOT/scripts/verify_gs6_install_cycle.sh"

echo 'GS 6.0 development verification: PASS'
