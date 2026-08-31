#!/usr/bin/env python3
"""Read-only VS Code profile inspection for GS 6.0."""
from __future__ import annotations

import json
import hashlib
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SDK = ROOT / "sdk" / "python"
if SDK.is_dir():
    sys.path.insert(0, str(SDK))
from gs_plugin import Plugin  # noqa: E402

plugin = Plugin(name="vscode")


def _home(ctx) -> Path:
    return Path(str(ctx.env.get("HOME") or Path.home())).expanduser()


def _paths(ctx):
    home = _home(ctx)
    system = platform.system()
    if system == "Darwin":
        user_data = home / "Library" / "Application Support" / "Code"
    elif system == "Windows":
        user_data = home / "AppData" / "Roaming" / "Code"
    else:
        user_data = home / ".config" / "Code"
    return {
        "user_data": user_data,
        "extensions": home / ".vscode" / "extensions",
        "profiles": home / ".vscode-profiles",
    }


def _code_binary():
    candidates = [
        os.getenv("GS_VSCODE_BIN"),
        shutil.which("code"),
        "/Applications/Visual Studio Code.app/Contents/Resources/app/bin/code",
        "/usr/local/bin/code",
        "/usr/bin/code",
    ]
    return next((Path(p) for p in candidates if p and Path(p).exists()), None)


def _load_profiles(directory: Path):
    metadata = directory / "profiles.json"
    if not metadata.is_file():
        return {"default_profile": "default", "profiles": {}}
    value = json.loads(metadata.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("profiles.json root must be an object")
    return value


@plugin.command(name="doctor", summary={"zh": "检查 VS Code 环境", "en": "Check VS Code environment"}, usage="gs vscode doctor")
def doctor(ctx):
    paths = _paths(ctx)
    binary = _code_binary()
    lines = [
        "VS Code 体检",
        "code: {}".format(binary or "未发现"),
        "user data: {} [{}]".format(paths["user_data"], "存在" if paths["user_data"].is_dir() else "不存在"),
        "extensions: {} [{}]".format(paths["extensions"], "存在" if paths["extensions"].is_dir() else "不存在"),
        "profiles: {} [{}]".format(paths["profiles"], "存在" if paths["profiles"].is_dir() else "不存在"),
    ]
    return {"exit_code": 0 if binary else 1, "stdout": "\n".join(lines) + "\n"}


@plugin.command(name="paths", summary={"zh": "显示 VS Code 相关路径", "en": "Show VS Code paths"}, usage="gs vscode paths")
def paths(ctx):
    value = _paths(ctx)
    return {"stdout": "user_data: {}\nextensions: {}\nprofiles: {}\n".format(value["user_data"], value["extensions"], value["profiles"])}


@plugin.command(name="list", summary={"zh": "列出本地配置", "en": "List local profiles"}, usage="gs vscode list")
def list_profiles(ctx):
    directory = _paths(ctx)["profiles"]
    try:
        value = _load_profiles(directory)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return {"exit_code": 1, "stderr": "读取 profiles.json 失败: {}\n".format(exc)}
    profiles = value.get("profiles") or {}
    if not isinstance(profiles, dict):
        return {"exit_code": 1, "stderr": "profiles 字段不是对象\n"}
    lines = ["VS Code Profiles", "默认: {}".format(value.get("default_profile", "default"))]
    lines.extend("  {}".format(name) for name in sorted(profiles))
    if not profiles:
        lines.append("  （没有自定义 profile）")
    return {"stdout": "\n".join(lines) + "\n"}


@plugin.command(name="info", summary={"zh": "查看 profile 详情", "en": "Show profile details"}, usage="gs vscode info <name>", args=[{"name": "name", "type": "string", "required": True, "description": {"zh": "配置名称", "en": "Profile name"}}])
def profile_info(ctx):
    name = str(ctx.args.get("name") or "")
    if not name or Path(name).name != name:
        return {"exit_code": 2, "stderr": "profile 名称无效\n"}
    directory = _paths(ctx)["profiles"]
    try:
        value = _load_profiles(directory)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        return {"exit_code": 1, "stderr": "读取 profiles.json 失败: {}\n".format(exc)}
    profiles = value.get("profiles") or {}
    if name != value.get("default_profile", "default") and name not in profiles:
        return {"exit_code": 1, "stderr": "profile 不存在: {}\n".format(name)}
    metadata = profiles.get(name, {}) if isinstance(profiles, dict) else {}
    if not isinstance(metadata, dict):
        return {"exit_code": 1, "stderr": "profile 元数据无效: {}\n".format(name)}
    return {"stdout": "Profile: {}\n默认: {}\n目录: {}\n描述: {}\n".format(name, "是" if name == value.get("default_profile", "default") else "否", directory / name, metadata.get("description", ""))}


@plugin.command(name="start", summary={"zh": "计划或启动 VS Code profile", "en": "Plan or launch a VS Code profile"}, usage="gs vscode start [profile] [--folder PATH] <--dry-run|--yes>", args=[{"name": "profile", "type": "string", "description": {"zh": "配置名称", "en": "Profile name"}}, {"name": "options", "type": "string", "variadic": True, "description": {"zh": "启动选项", "en": "Launch options"}}])
def start_plan(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    execute = "--yes" in options
    dry_run = "--dry-run" in options
    if execute == dry_run:
        return {"exit_code": 2, "stderr": "必须且只能指定 --dry-run 或 --yes\n"}
    formats = [value for value in options if value.startswith("--format=")]
    if formats and formats != ["--format=json"]:
        return {"exit_code": 2, "stderr": "仅支持 --format=json\n"}
    profile = str(ctx.args.get("profile") or "default")
    if Path(profile).name != profile:
        return {"exit_code": 2, "stderr": "profile 名称无效\n"}
    binary = _code_binary()
    if binary is None:
        return {"exit_code": 127, "stderr": "未找到 code\n"}
    paths = _paths(ctx)
    user_data = paths["profiles"] / profile / "user-data"
    command = [str(binary), "--user-data-dir", str(user_data), "--extensions-dir", str(paths["extensions"])]
    folder = None
    for index, value in enumerate(options):
        if value == "--folder":
            if index + 1 >= len(options):
                return {"exit_code": 2, "stderr": "--folder 缺少路径\n"}
            folder = options[index + 1]
        elif value.startswith("--folder="):
            folder = value.split("=", 1)[1]
    if folder:
        folder_path = Path(folder).expanduser().resolve()
        if not folder_path.is_dir():
            return {"exit_code": 2, "stderr": "folder 不存在: {}\n".format(folder_path)}
        command.append(str(folder_path))
    plan = {"schema_version": 1, "plan_id": hashlib.sha256("{}\n{}".format(profile, " ".join(command)).encode()).hexdigest()[:16], "mode": "dry-run", "profile": profile, "command": command, "writes_required": False, "check": {"ok": True, "errors": []}}
    if "--format=json" in options:
        if execute:
            return {"exit_code": 2, "stderr": "--format=json 仅适用于 --dry-run\n"}
        return {"stdout": json.dumps(plan, ensure_ascii=False, indent=2) + "\n"}
    if dry_run:
        return {"stdout": "VS Code 启动计划（dry-run）\nProfile: {}\nCommand: {}\n不会执行\n".format(profile, " ".join(command))}
    try:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    except OSError as exc:
        return {"exit_code": 1, "stderr": "启动 VS Code 失败: {}\n".format(exc)}
    return {"stdout": "VS Code 已启动\nProfile: {}\nPID: {}\nCommand: {}\n".format(profile, process.pid, " ".join(command))}


if __name__ == "__main__":
    raise SystemExit(plugin.run())
