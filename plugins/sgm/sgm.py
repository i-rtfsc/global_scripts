#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SGM work helpers with explicit execution confirmation and private assets."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_SDK = _ROOT / "sdk" / "python"
if _SDK.is_dir():
    sys.path.insert(0, str(_SDK))

from gs_plugin import Plugin  # noqa: E402


plugin = Plugin(name="sgm")
SSH_MARKER_START = "# >>> GS6 SGM SSH Configuration >>>"
SSH_MARKER_END = "# <<< GS6 SGM SSH Configuration <<<"
PACKAGE_RE = re.compile(r"^[A-Za-z0-9_.$-]+$")
SSH_FILES = {"id_rsa": ("id_rsa_sgm", 0o600), "id_rsa.pub": ("id_rsa_sgm.pub", 0o644)}


def _home(ctx):
    return Path(str(ctx.env.get("HOME") or Path.home())).expanduser()


def _asset_root(ctx):
    explicit = str(ctx.env.get("GS_SGM_DIR") or "").strip()
    candidates = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    candidates.append(_home(ctx) / ".config" / "global-scripts" / "sgm")
    root = str(ctx.env.get("GS_ROOT") or "").strip()
    if root:
        candidates.append(Path(root) / "custom" / "userspace" / "sgm")
    candidates.append(_ROOT / "custom" / "userspace" / "sgm")
    for candidate in candidates:
        if (candidate / "build" / "config.json").is_file() or (candidate / "ssh").is_dir():
            return candidate.resolve()
    return candidates[0].resolve(strict=False)


def _env(ctx, name, default):
    return str(ctx.env.get(name) or default)


def _mode(values, label, allowed_prefixes=None):
    values = [str(value) for value in (values or [])]
    dry_run = "--dry-run" in values
    execute = "--yes" in values
    prefixes = tuple(allowed_prefixes or [])
    unknown = [value for value in values if value not in {"--dry-run", "--yes"} and not value.startswith(prefixes)]
    if dry_run == execute or unknown:
        return None, "{} 必须且只能指定 --dry-run 或 --yes".format(label)
    return ("dry-run" if dry_run else "execute"), None


def _load_build_config(ctx):
    path = _asset_root(ctx) / "build" / "config.json"
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return path, {}, "无法读取构建配置: {}".format(exc)
    apps = value.get("apps") if isinstance(value, dict) else None
    return path, apps if isinstance(apps, dict) else {}, None


def _app(ctx):
    return str(ctx.args.get("app") or "")


def _app_config(ctx):
    path, apps, error = _load_build_config(ctx)
    name = _app(ctx)
    if error:
        return None, None, error
    if not name or name not in apps:
        return None, None, "未找到 App 配置 '{}'; 可用: {}".format(name, ", ".join(sorted(apps)) or "无")
    config = apps[name]
    project_value = str(config.get("project_path") or "")
    if project_value:
        project = Path(project_value).expanduser()
        if not project.is_absolute():
            project = (_asset_root(ctx) / "build" / project).resolve()
    else:
        project = Path(ctx.cwd or os.getcwd()).resolve()
    return project, config, None


def _adb(ctx):
    return _env(ctx, "GS_SGM_ADB_BIN", "adb")


def _adb_base(ctx):
    command = [_adb(ctx)]
    serial = str(ctx.env.get("ANDROID_SERIAL") or "").strip()
    if serial:
        command += ["-s", serial]
    return command


def _run(command, cwd=None, timeout=300):
    try:
        result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:
        return 127, "", "命令不存在: {}".format(exc.filename)
    except subprocess.TimeoutExpired:
        return 124, "", "命令超时: {}".format(" ".join(map(str, command)))
    return result.returncode, result.stdout, result.stderr


def _build_plan(ctx, action):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    mode, error = _mode(options, "sgm build {}".format(action))
    if error:
        return None, None, None, {"exit_code": 2, "stderr": error + "\n"}
    project, config, config_error = _app_config(ctx)
    if config_error:
        return None, None, None, {"exit_code": 1, "stderr": config_error + "\n"}
    gradlew = project / "gradlew"
    task = str(config.get("gradle_task") or "assembleRelease")
    apk = (project / str(config.get("apk_path") or "")).resolve()
    target = str(config.get("target_path") or "")
    package = str(config.get("package_name") or "")
    if package and not PACKAGE_RE.fullmatch(package):
        return None, None, None, {"exit_code": 2, "stderr": "包名包含非法字符\n"}
    plan = {
        "project": project,
        "gradlew": gradlew,
        "task": task,
        "apk": apk,
        "target": target,
        "package": package,
    }
    return mode, plan, options, None


def _compile(plan):
    if not plan["gradlew"].is_file():
        return 1, "", "未找到 gradlew: {}".format(plan["gradlew"])
    return _run([str(plan["gradlew"]), plan["task"]], cwd=plan["project"], timeout=1800)


def _push(ctx, plan):
    if not plan["apk"].is_file():
        return 1, "", "APK 不存在: {}".format(plan["apk"])
    if not plan["target"]:
        return 2, "", "target_path 为空"
    for args in (["root"], ["remount"]):
        _run(_adb_base(ctx) + args, timeout=30)
    return _run(_adb_base(ctx) + ["push", str(plan["apk"]), plan["target"]], timeout=300)


def _restart(ctx, plan):
    if not plan["package"]:
        return 2, "", "package_name 为空"
    return _run(_adb_base(ctx) + ["shell", "am", "force-stop", plan["package"]], timeout=30)


def _build_action(ctx, action):
    mode, plan, _, error = _build_plan(ctx, action)
    if error:
        return error
    lines = [
        "SGM build {} 计划 ({})".format(action, mode),
        "App: {}".format(_app(ctx)),
        "Project: {}".format(plan["project"]),
        "Gradle: {} {}".format(plan["gradlew"], plan["task"]),
        "APK: {}".format(plan["apk"]),
        "Target: {}".format(plan["target"]),
        "Package: {}".format(plan["package"]),
    ]
    if mode == "dry-run":
        lines.append("不会编译、写入设备或重启进程")
        return {"stdout": "\n".join(lines) + "\n"}
    steps = []
    if action in {"compile", "run"}:
        steps.append(("compile", lambda: _compile(plan)))
    if action in {"push", "run"}:
        steps.append(("push", lambda: _push(ctx, plan)))
    if action in {"restart", "run"}:
        steps.append(("restart", lambda: _restart(ctx, plan)))
    output = []
    for name, operation in steps:
        rc, stdout, stderr = operation()
        if stdout:
            output.append(stdout.strip())
        if rc != 0:
            return {"exit_code": rc, "stdout": "\n".join(output) + ("\n" if output else ""), "stderr": "{} 失败: {}\n".format(name, (stderr or stdout).strip())}
    output.append("{} 完成: {}".format(action, _app(ctx)))
    return {"stdout": "\n".join(output) + "\n"}


@plugin.command(name="build.list", summary={"zh": "列出配置的 App", "en": "List configured apps"}, usage="gs sgm build list")
def build_list(ctx):
    path, apps, error = _load_build_config(ctx)
    if error:
        return {"exit_code": 1, "stderr": error + "\n"}
    lines = ["SGM Apps", "Config: {}".format(path)]
    for name, config in apps.items():
        lines.append("  {}: task={} apk={} target={} package={}".format(name, config.get("gradle_task", ""), config.get("apk_path", ""), config.get("target_path", ""), config.get("package_name", "")))
    return {"stdout": "\n".join(lines) + "\n"}


_BUILD_ARGS = [
    {"name": "app", "type": "string", "required": True},
    {"name": "options", "type": "string", "variadic": True},
]


for _action in ("compile", "push", "restart", "run"):
    def _register_build(action):
        @plugin.command(name="build.{}".format(action), summary={"zh": "SGM App {}".format(action), "en": "SGM app {}".format(action)}, usage="gs sgm build {} <app> <--dry-run|--yes>".format(action), args=_BUILD_ARGS)
        def handler(ctx, selected=action):
            return _build_action(ctx, selected)
        return handler
    _register_build(_action)


def _parse_connect_options(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    mode, error = _mode(options, "sgm connect", ["--server=", "--remote=", "--mount="])
    return mode, options, error


@plugin.command(name="connect.server", summary={"zh": "SSH 连接 SGM 服务器", "en": "Connect to the SGM server"}, usage="gs sgm connect server [--server=USER@HOST] <--dry-run|--yes>", args=[{"name": "options", "type": "string", "variadic": True}])
def connect_server(ctx):
    mode, options, error = _parse_connect_options(ctx)
    if error:
        return {"exit_code": 2, "stderr": error + "\n"}
    server = next((value.split("=", 1)[1] for value in options if value.startswith("--server=")), _env(ctx, "GS_SGM_SERVER", "sipgnd@sgm.shanghaigm.com@localhost"))
    port = _env(ctx, "GS_SGM_SSH_PORT", "22222")
    command = [_env(ctx, "GS_SGM_SSH_BIN", "ssh"), "-p", port, server]
    if mode == "dry-run":
        return {"stdout": "SGM server 计划（dry-run）\nCommand: {}\n不会建立公司网络连接\n".format(" ".join(command))}
    return {"exec": command, "stdout": "连接 SGM server: {}\n".format(server)}


@plugin.command(name="connect.mount", summary={"zh": "挂载 SGM 远程文件系统", "en": "Mount the SGM remote filesystem"}, usage="gs sgm connect mount [--remote=PATH] [--mount=PATH] <--dry-run|--yes>", args=[{"name": "options", "type": "string", "variadic": True}])
def connect_mount(ctx):
    mode, options, error = _parse_connect_options(ctx)
    if error:
        return {"exit_code": 2, "stderr": error + "\n"}
    remote = next((value.split("=", 1)[1] for value in options if value.startswith("--remote=")), _env(ctx, "GS_SGM_REMOTE_PATH", "/home/SGM/sipgnd/code/557/qcom_la/lagvm/LINUX/android/"))
    mount = Path(next((value.split("=", 1)[1] for value in options if value.startswith("--mount=")), _env(ctx, "GS_SGM_MOUNT_POINT", str(_home(ctx) / "vm")))).expanduser()
    server = _env(ctx, "GS_SGM_SERVER", "sipgnd@sgm.shanghaigm.com@localhost")
    port = _env(ctx, "GS_SGM_SSH_PORT", "22222")
    command = [_env(ctx, "GS_SGM_SSHFS_BIN", "sshfs"), "-o", "allow_other,port={}".format(port), "{}:{}".format(server, remote), str(mount)]
    if mode == "dry-run":
        return {"stdout": "SGM mount 计划（dry-run）\nCommand: {}\n不会创建挂载或连接公司网络\n".format(" ".join(command))}
    mount.mkdir(parents=True, exist_ok=True)
    rc, stdout, stderr = _run(command, timeout=120)
    return {"exit_code": rc, "stdout": stdout or ("挂载完成: {}\n".format(mount) if rc == 0 else ""), "stderr": stderr}


@plugin.command(name="git.push", summary={"zh": "推送到 SGM Gerrit", "en": "Push to SGM Gerrit"}, usage="gs sgm git push [--branch=NAME] <--dry-run|--yes>", args=[{"name": "options", "type": "string", "variadic": True}])
def git_push(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    mode, error = _mode(options, "sgm git push", ["--branch="])
    if error:
        return {"exit_code": 2, "stderr": error + "\n"}
    root = Path(ctx.cwd or os.getcwd()).resolve()
    branch = next((value.split("=", 1)[1] for value in options if value.startswith("--branch=")), "")
    if not branch:
        rc, stdout, stderr = _run(["git", "-C", str(root), "branch", "--show-current"], timeout=15)
        if rc != 0 or not stdout.strip():
            return {"exit_code": 1, "stderr": "无法确定当前分支: {}\n".format(stderr.strip())}
        branch = stdout.strip()
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", branch):
        return {"exit_code": 2, "stderr": "分支名包含非法字符\n"}
    command = ["git", "push", "origin", "HEAD:refs/for/{}".format(branch)]
    if mode == "dry-run":
        return {"stdout": "SGM Gerrit push 计划（dry-run）\nCommand: {}\n不会联网或推送代码\n".format(" ".join(command))}
    rc, stdout, stderr = _run(command, cwd=root, timeout=600)
    return {"exit_code": rc, "stdout": stdout, "stderr": stderr}


def _ssh_paths(ctx):
    return _asset_root(ctx) / "ssh", _home(ctx) / ".ssh"


def _backup_root(ctx):
    return _home(ctx) / ".config" / "global-scripts" / "backups" / "sgm" / "ssh"


def _timestamp():
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")


def _backup_ssh(ctx):
    _, target = _ssh_paths(ctx)
    destination = _backup_root(ctx) / _timestamp()
    destination.mkdir(parents=True, exist_ok=True)
    copied = []
    for name in ("id_rsa_sgm", "id_rsa_sgm.pub", "config"):
        path = target / name
        if path.is_file():
            shutil.copy2(path, destination / name)
            copied.append(name)
    backups = sorted([path for path in destination.parent.iterdir() if path.is_dir()], key=lambda path: path.name, reverse=True)
    for old in backups[3:]:
        shutil.rmtree(old)
    return destination, copied


def _backups(ctx):
    root = _backup_root(ctx)
    return sorted([path for path in root.iterdir() if path.is_dir()], key=lambda path: path.name, reverse=True) if root.is_dir() else []


def _remove_sgm_config(text):
    start = text.find(SSH_MARKER_START)
    if start < 0:
        return text
    end = text.find(SSH_MARKER_END, start)
    if end < 0:
        return text
    return (text[:start].rstrip() + "\n" + text[end + len(SSH_MARKER_END):].lstrip()).rstrip() + "\n"


def _ssh_action(ctx, action):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    mode, error = _mode(options, "sgm ssh {}".format(action), ["--backup="])
    if error:
        return {"exit_code": 2, "stderr": error + "\n"}
    source, target = _ssh_paths(ctx)
    targets = [target / "id_rsa_sgm", target / "id_rsa_sgm.pub", target / "config"]
    if action == "backup":
        if mode == "dry-run":
            return {"stdout": "SGM SSH backup 计划（dry-run）\n不会复制密钥\n"}
        destination, copied = _backup_ssh(ctx)
        return {"exit_code": 0 if copied else 1, "stdout": "SGM SSH 已备份: {}\n文件: {}\n".format(destination, ", ".join(copied) or "无")}
    if action == "restore":
        requested = next((value.split("=", 1)[1] for value in options if value.startswith("--backup=")), "")
        candidates = [path for path in _backups(ctx) if not requested or path.name == requested]
        if not candidates:
            return {"exit_code": 1, "stderr": "没有可用的 SGM SSH 备份\n"}
        backup = candidates[0]
        if mode == "dry-run":
            return {"stdout": "SGM SSH restore 计划（dry-run）\nBackup: {}\n不会覆盖密钥\n".format(backup)}
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(target, 0o700)
        for name, permission in (("id_rsa_sgm", 0o600), ("id_rsa_sgm.pub", 0o644), ("config", 0o644)):
            if (backup / name).is_file():
                shutil.copy2(backup / name, target / name)
                os.chmod(target / name, permission)
        return {"stdout": "SGM SSH 已恢复: {}\n".format(backup.name)}
    if action == "install":
        available = [name for name in SSH_FILES if (source / name).is_file()]
        if not available:
            return {"exit_code": 1, "stderr": "SGM SSH 私有资产缺失: {}\n".format(source)}
        if mode == "dry-run":
            return {"stdout": "SGM SSH install 计划（dry-run）\nSource: {}\n不会复制密钥或修改 config\n".format(source)}
        if any(path.exists() for path in targets):
            _backup_ssh(ctx)
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(target, 0o700)
        for source_name in available:
            target_name, permission = SSH_FILES[source_name]
            shutil.copy2(source / source_name, target / target_name)
            os.chmod(target / target_name, permission)
        fragment = (source / "config").read_text(encoding="utf-8") if (source / "config").is_file() else ""
        config_path = target / "config"
        text = config_path.read_text(encoding="utf-8") if config_path.is_file() else ""
        text = _remove_sgm_config(text)
        text += "\n{}\n{}\n{}\n".format(SSH_MARKER_START, fragment.rstrip(), SSH_MARKER_END)
        config_path.write_text(text.lstrip(), encoding="utf-8")
        os.chmod(config_path, 0o644)
        return {"stdout": "SGM SSH 配置已安装\n"}
    if mode == "dry-run":
        return {"stdout": "SGM SSH uninstall 计划（dry-run）\n不会删除密钥或修改 config\n"}
    if any(path.exists() for path in targets):
        _backup_ssh(ctx)
    for name in ("id_rsa_sgm", "id_rsa_sgm.pub"):
        path = target / name
        if path.exists():
            path.unlink()
    config_path = target / "config"
    if config_path.is_file():
        config_path.write_text(_remove_sgm_config(config_path.read_text(encoding="utf-8")), encoding="utf-8")
    return {"stdout": "SGM SSH 配置已卸载\n"}


_SSH_ARGS = [{"name": "options", "type": "string", "variadic": True}]
for _action in ("install", "uninstall", "backup", "restore"):
    def _register_ssh(action):
        @plugin.command(name="ssh.{}".format(action), summary={"zh": "{} SGM SSH 配置".format(action), "en": "{} SGM SSH config".format(action)}, usage="gs sgm ssh {} <--dry-run|--yes>".format(action), args=_SSH_ARGS)
        def handler(ctx, selected=action):
            return _ssh_action(ctx, selected)
        return handler
    _register_ssh(_action)


@plugin.command(name="ssh.status", summary={"zh": "查看 SGM SSH 状态", "en": "Show SGM SSH status"}, usage="gs sgm ssh status")
def ssh_status(ctx):
    source, target = _ssh_paths(ctx)
    lines = ["SGM SSH 状态", "Private source: {}".format(source)]
    for name, permission in (("id_rsa_sgm", 0o600), ("id_rsa_sgm.pub", 0o644), ("config", 0o644)):
        path = target / name
        actual = path.stat().st_mode & 0o777 if path.exists() else None
        lines.append("  {}: {}{}".format(name, "installed" if actual is not None else "missing", " mode={:o}".format(actual) if actual is not None else ""))
    lines.append("  backups: {}".format(len(_backups(ctx))))
    return {"stdout": "\n".join(lines) + "\n"}


@plugin.command(name="ssh.permissions", summary={"zh": "修复 SGM SSH 权限", "en": "Fix SGM SSH permissions"}, usage="gs sgm ssh permissions <--dry-run|--yes>", args=_SSH_ARGS)
def ssh_permissions(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    mode, error = _mode(options, "sgm ssh permissions")
    if error:
        return {"exit_code": 2, "stderr": error + "\n"}
    _, target = _ssh_paths(ctx)
    if mode == "dry-run":
        return {"stdout": "SGM SSH permissions 计划（dry-run）\n不会修改权限\n"}
    if target.is_dir():
        os.chmod(target, 0o700)
    fixed = []
    for name, permission in (("id_rsa_sgm", 0o600), ("id_rsa_sgm.pub", 0o644), ("config", 0o644)):
        path = target / name
        if path.exists():
            os.chmod(path, permission)
            fixed.append("{}={:o}".format(name, permission))
    return {"exit_code": 0 if fixed else 1, "stdout": "SGM SSH 权限已修复: {}\n".format(", ".join(fixed) or "无文件")}


if __name__ == "__main__":
    raise SystemExit(plugin.run())
