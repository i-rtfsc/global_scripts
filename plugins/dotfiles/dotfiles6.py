#!/usr/bin/env python3
"""Read-only dotfiles inspection and dry-run planning for GS 6.0."""
from __future__ import annotations

import json
import hashlib
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SDK = ROOT / "sdk" / "python"
if SDK.is_dir():
    sys.path.insert(0, str(SDK))
from gs_plugin import Plugin  # noqa: E402

plugin = Plugin(name="dotfiles")
TOOLS = {
    "fish": ("fish/config.fish", "~/.config/fish/config.fish"),
    "zsh": ("zsh/.zshrc", "~/.zshrc"),
    "vim": ("vim/.vimrc", "~/.vimrc"),
    "nvim": ("nvim/init.vim", "~/.config/nvim/init.vim"),
    "tmux": ("tmux/.tmux.conf", "~/.tmux.conf"),
    "git": ("git/.gitconfig", "~/.gitconfig"),
}


def _root(ctx):
    value = ctx.env.get("GS_ROOT")
    return Path(str(value)).expanduser() if value else ROOT


def _home(ctx):
    return Path(str(ctx.env.get("HOME") or Path.home())).expanduser()


def _tool(ctx):
    return str(ctx.args.get("tool") or "")


def _details(ctx, tool):
    if tool not in TOOLS:
        return None
    source_rel, target = TOOLS[tool]
    source = _root(ctx) / "plugins" / "dotfiles" / source_rel
    return source, _home(ctx) / (target[2:] if target.startswith("~/") else target)


def _action_paths(ctx, tool):
    details = _details(ctx, tool)
    if details is None:
        return None
    if tool == "nvim":
        return _root(ctx) / "plugins" / "dotfiles" / "nvim", _home(ctx) / ".config" / "nvim"
    return details


def _backup_root(ctx):
    return _home(ctx) / ".config" / "global-scripts" / "backups" / "dotfiles"


def _backup_candidates(ctx, tool):
    root = _backup_root(ctx)
    candidates = []
    legacy_tool_root = root / tool
    if legacy_tool_root.is_dir():
        candidates.extend(path for path in legacy_tool_root.iterdir() if path.exists())
    if root.is_dir():
        candidates.extend(
            stamp / tool
            for stamp in root.iterdir()
            if stamp.is_dir() and stamp.name != tool and (stamp / tool).exists()
        )
    unique = {str(path.resolve()): path for path in candidates}
    def backup_stamp(path):
        return path.parent.name if path.name == tool else path.name
    return sorted(unique.values(), key=backup_stamp, reverse=True)


def _create_backup(ctx, tool, target):
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    destination = _backup_root(ctx) / tool / stamp
    destination.parent.mkdir(parents=True, exist_ok=True)
    if target.is_dir():
        shutil.copytree(target, destination)
    else:
        destination.mkdir(parents=True)
        shutil.copy2(target, destination / target.name)
    backups = _backup_candidates(ctx, tool)
    for old in backups[3:]:
        if old.parent == destination.parent:
            if old.is_dir():
                shutil.rmtree(old)
            else:
                old.unlink()
    return destination


def _restore_payload(candidate, target):
    if target.suffix or target.name.startswith("."):
        if candidate.is_file():
            return candidate
        named = candidate / target.name
        if named.is_file():
            return named
        files = [path for path in candidate.iterdir() if path.is_file()]
        return files[0] if len(files) == 1 else None
    return candidate if candidate.is_dir() else None


def _validate_plan(value):
    required = {"schema_version", "plan_id", "mode", "tool", "action", "source", "target", "check", "writes_required"}
    missing = sorted(required - set(value)) if isinstance(value, dict) else sorted(required)
    if missing:
        return ["计划缺少字段: {}".format(", ".join(missing))]
    errors = []
    if value["schema_version"] != 1 or value["mode"] != "dry-run":
        errors.append("schema 或 mode 无效")
    if value["action"] not in {"install", "uninstall"}:
        errors.append("action 无效")
    if not isinstance(value["plan_id"], str) or len(value["plan_id"]) != 16:
        errors.append("plan_id 无效")
    expected = hashlib.sha256("{}\n{}\n{}\n{}".format(value["tool"], value["action"], value["source"], value["target"]).encode()).hexdigest()[:16]
    if value["plan_id"] != expected:
        errors.append("plan_id 与计划内容不匹配")
    if value["check"].get("ok") is not True or value["writes_required"] is not True:
        errors.append("计划 check/writes_required 无效")
    return errors


def _nvim_tree_status(ctx):
    source_root = _root(ctx) / "plugins" / "dotfiles" / "nvim"
    target_root = _home(ctx) / ".config" / "nvim"
    ignored = {".git", "__pycache__", "cache", "shada", "swap", "undo", "backup", "plugin.py"}
    def files(root):
        if not root.is_dir():
            return {}
        result = {}
        for path in root.rglob("*"):
            if not path.is_file() or any(part in ignored for part in path.relative_to(root).parts):
                continue
            result[str(path.relative_to(root))] = hashlib.sha256(path.read_bytes()).hexdigest()
        return result
    source, target = files(source_root), files(target_root)
    missing = sorted(set(source) - set(target))
    extra = sorted(set(target) - set(source))
    changed = sorted(name for name in set(source) & set(target) if source[name] != target[name])
    return source_root, target_root, source, missing, extra, changed


@plugin.command(name="list", summary={"zh": "列出配置工具", "en": "List dotfile tools"}, usage="gs dotfiles list")
def list_tools(ctx):
    lines = ["Dotfiles 工具"]
    lines.extend("  {} -> {}".format(name, target) for name, (_, target) in sorted(TOOLS.items()))
    return {"stdout": "\n".join(lines) + "\n"}


@plugin.command(name="status", summary={"zh": "查看配置文件状态", "en": "Show dotfile status"}, usage="gs dotfiles status [tool]", args=[{"name": "tool", "type": "enum", "complete": {"kind": "enum", "values": sorted(TOOLS)}}])
def status(ctx):
    selected = [_tool(ctx)] if _tool(ctx) else sorted(TOOLS)
    lines = ["Dotfiles 状态"]
    for tool in selected:
        details = _details(ctx, tool)
        if details is None:
            return {"exit_code": 2, "stderr": "未知工具: {}\n".format(tool)}
        source, target = details
        lines.append("  {}: source={} [{}], target={} [{}]".format(tool, source, "存在" if source.is_file() else "缺失", target, "已安装" if target.exists() else "未安装"))
        if tool == "nvim":
            _, _, source_files, missing, extra, changed = _nvim_tree_status(ctx)
            lines.append("    nvim tree: source={} files, missing={}, extra={}, changed={}".format(
                len(source_files), len(missing), len(extra), len(changed)))
    return {"stdout": "\n".join(lines) + "\n"}


@plugin.command(name="doctor", summary={"zh": "检查配置源和目标路径", "en": "Validate dotfile sources and targets"}, usage="gs dotfiles doctor")
def doctor(ctx):
    home = _home(ctx).resolve()
    missing = []
    unsafe = []
    lines = ["Dotfiles 体检"]
    for tool in sorted(TOOLS):
        source, target = _details(ctx, tool)
        if not source.is_file():
            missing.append(tool)
        try:
            target.resolve(strict=False).relative_to(home)
        except ValueError:
            unsafe.append(tool)
        lines.append("  {}: source={} target={}".format(tool, "ok" if source.is_file() else "missing", target))
        if tool == "nvim":
            _, _, source_files, missing_files, _, changed_files = _nvim_tree_status(ctx)
            if missing_files or changed_files:
                missing.append("nvim-tree")
            lines.append("    nvim tree: source={} files, missing={}, changed={}".format(
                len(source_files), len(missing_files), len(changed_files)))
    lines.append("缺失源: {}".format(", ".join(missing) if missing else "无"))
    lines.append("越界目标: {}".format(", ".join(unsafe) if unsafe else "无"))
    return {"exit_code": 1 if missing or unsafe else 0, "stdout": "\n".join(lines) + "\n"}


@plugin.command(name="backups", summary={"zh": "列出配置备份", "en": "List dotfile backups"}, usage="gs dotfiles backups <tool>", args=[{"name": "tool", "type": "enum", "required": True, "complete": {"kind": "enum", "values": sorted(TOOLS)}}])
def backups(ctx):
    tool = _tool(ctx)
    if _details(ctx, tool) is None:
        return {"exit_code": 2, "stderr": "未知工具: {}\n".format(tool)}
    values = _backup_candidates(ctx, tool)
    lines = ["{} 备份 ({} 个)".format(tool, len(values))]
    lines.extend("  {}".format(path) for path in values)
    return {"stdout": "\n".join(lines) + "\n"}


@plugin.command(name="backup", summary={"zh": "备份当前配置", "en": "Back up the current dotfile"}, usage="gs dotfiles backup <tool> --yes", args=[{"name": "tool", "type": "enum", "required": True, "complete": {"kind": "enum", "values": sorted(TOOLS)}}, {"name": "options", "type": "string", "variadic": True}])
def backup(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    if options != ["--yes"]:
        return {"exit_code": 2, "stderr": "备份配置必须显式指定 --yes\n"}
    tool = _tool(ctx)
    paths = _action_paths(ctx, tool)
    if paths is None:
        return {"exit_code": 2, "stderr": "未知工具: {}\n".format(tool)}
    _, target = paths
    if not target.exists():
        return {"exit_code": 1, "stderr": "配置未安装，无需备份: {}\n".format(target)}
    destination = _create_backup(ctx, tool, target)
    return {"stdout": "配置已备份\nTool: {}\nBackup: {}\n".format(tool, destination)}


@plugin.command(name="restore", summary={"zh": "恢复配置备份", "en": "Restore a dotfile backup"}, usage="gs dotfiles restore <tool> [--backup=NAME] <--dry-run|--yes>", args=[{"name": "tool", "type": "enum", "required": True, "complete": {"kind": "enum", "values": sorted(TOOLS)}}, {"name": "options", "type": "string", "variadic": True}])
def restore(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    dry_run = "--dry-run" in options
    execute = "--yes" in options
    if dry_run == execute:
        return {"exit_code": 2, "stderr": "恢复配置必须且只能指定 --dry-run 或 --yes\n"}
    allowed = {"--dry-run", "--yes"}
    unknown = [value for value in options if value not in allowed and not value.startswith("--backup=")]
    if unknown:
        return {"exit_code": 2, "stderr": "不支持的恢复选项: {}\n".format(" ".join(unknown))}
    tool = _tool(ctx)
    paths = _action_paths(ctx, tool)
    if paths is None:
        return {"exit_code": 2, "stderr": "未知工具: {}\n".format(tool)}
    _, target = paths
    candidates = _backup_candidates(ctx, tool)
    requested = next((value.split("=", 1)[1] for value in options if value.startswith("--backup=")), "")
    if requested:
        candidates = [path for path in candidates if path.name == requested]
    if not candidates:
        return {"exit_code": 1, "stderr": "没有可用的 {} 备份\n".format(tool)}
    candidate = candidates[0]
    payload = _restore_payload(candidate, target)
    if payload is None or not payload.exists():
        return {"exit_code": 1, "stderr": "备份内容无效: {}\n".format(candidate)}
    if dry_run:
        return {"stdout": "Dotfiles 恢复计划（dry-run）\nTool: {}\nBackup: {}\nTarget: {}\n不会覆盖当前配置\n".format(tool, candidate, target)}
    safety_backup = _create_backup(ctx, tool, target) if target.exists() else None
    if target.exists():
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
    target.parent.mkdir(parents=True, exist_ok=True)
    if payload.is_dir():
        shutil.copytree(payload, target)
    else:
        shutil.copy2(payload, target)
    return {"stdout": "配置已恢复\nTool: {}\nBackup: {}\nTarget: {}\nSafety backup: {}\n".format(tool, candidate, target, safety_backup or "无")}


@plugin.command(name="plan", summary={"zh": "生成配置变更计划", "en": "Plan dotfile changes"}, usage="gs dotfiles plan <tool> <install|uninstall> --dry-run", args=[{"name": "tool", "type": "enum", "required": True, "complete": {"kind": "enum", "values": sorted(TOOLS)}}, {"name": "action", "type": "enum", "required": True, "complete": {"kind": "enum", "values": ["install", "uninstall"]}}, {"name": "options", "type": "string", "variadic": True}])
def plan(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    if "--dry-run" not in options:
        return {"exit_code": 2, "stderr": "GS 6.0 当前仅支持 dotfiles plan --dry-run\n"}
    tool = _tool(ctx)
    action = str(ctx.args.get("action") or "")
    details = _details(ctx, tool)
    if details is None or action not in {"install", "uninstall"}:
        return {"exit_code": 2, "stderr": "工具或操作无效\n"}
    source, target = _action_paths(ctx, tool)
    if action == "install" and not source.exists():
        return {"exit_code": 1, "stderr": "源配置不存在: {}\n".format(source)}
    try:
        target.resolve(strict=False).relative_to(_home(ctx).resolve())
    except ValueError:
        return {"exit_code": 1, "stderr": "目标路径越出 HOME: {}\n".format(target)}
    plan = {
        "schema_version": 1,
        "plan_id": hashlib.sha256("{}\n{}\n{}\n{}".format(tool, action, source, target).encode()).hexdigest()[:16],
        "mode": "dry-run",
        "tool": tool,
        "action": action,
        "source": str(source),
        "target": str(target),
        "check": {"ok": True, "errors": []},
        "writes_required": True,
    }
    if "--format=json" in options:
        return {"stdout": json.dumps(plan, ensure_ascii=False, indent=2) + "\n"}
    return {"stdout": "Dotfiles 计划（dry-run）\nTool: {}\nAction: {}\nSource: {}\nTarget: {}\n不会执行复制、覆盖或删除\n".format(tool, action, source, target)}


@plugin.command(name="verify-plan", summary={"zh": "校验 dotfiles JSON 计划", "en": "Verify dotfiles JSON plan"}, usage="gs dotfiles verify-plan <plan.json>", args=[{"name": "file", "type": "path", "required": True}])
def verify_plan(ctx):
    filename = str(ctx.args.get("file") or "")
    if not filename:
        return {"exit_code": 2, "stderr": "缺少计划文件\n"}
    try:
        path = Path(filename).expanduser()
        if not path.is_absolute():
            path = Path(ctx.cwd or Path.cwd()) / path
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"exit_code": 2, "stderr": "计划读取失败: {}\n".format(exc)}
    errors = _validate_plan(value)
    if errors:
        return {"exit_code": 1, "stderr": "计划校验失败: {}\n".format("; ".join(errors))}
    return {"stdout": "计划有效\nTool: {}\nAction: {}\n".format(value["tool"], value["action"])}


@plugin.command(name="apply-plan", summary={"zh": "应用已验证的 dotfiles 计划", "en": "Apply a verified dotfiles plan"}, usage="gs dotfiles apply-plan <plan.json> --yes", args=[{"name": "file", "type": "path", "required": True}, {"name": "options", "type": "string", "variadic": True}])
def apply_plan(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    if options != ["--yes"]:
        return {"exit_code": 2, "stderr": "应用计划必须显式指定 --yes\n"}
    filename = str(ctx.args.get("file") or "")
    path = Path(filename).expanduser()
    if not path.is_absolute():
        path = Path(ctx.cwd or Path.cwd()) / path
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"exit_code": 2, "stderr": "计划读取失败: {}\n".format(exc)}
    errors = _validate_plan(value)
    if errors:
        return {"exit_code": 1, "stderr": "计划校验失败: {}\n".format("; ".join(errors))}
    home = _home(ctx).resolve()
    source = Path(value["source"]).expanduser().resolve()
    target = Path(value["target"]).expanduser().resolve(strict=False)
    try:
        target.relative_to(home)
    except ValueError:
        return {"exit_code": 1, "stderr": "目标路径越出 HOME: {}\n".format(target)}
    if value["action"] == "install" and not source.exists():
        return {"exit_code": 1, "stderr": "源配置不存在: {}\n".format(source)}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")
    backup_root = home / ".config" / "global-scripts" / "backups" / "dotfiles" / stamp
    backup = backup_root / value["tool"]
    suffix = 1
    while backup.exists():
        backup = home / ".config" / "global-scripts" / "backups" / (stamp + "-{}".format(suffix)) / value["tool"]
        suffix += 1
    if target.exists():
        backup.parent.mkdir(parents=True, exist_ok=True)
        if target.is_dir():
            shutil.copytree(target, backup)
            shutil.rmtree(target)
        else:
            shutil.copy2(target, backup)
            target.unlink()
    if value["action"] == "install":
        target.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, target, ignore=shutil.ignore_patterns(".git", "__pycache__", "cache", "shada", "swap", "undo", "backup", "plugin.py"))
        else:
            shutil.copy2(source, target)
    return {"stdout": "计划已应用\nTool: {}\nAction: {}\nTarget: {}\nBackup: {}\n".format(value["tool"], value["action"], target, backup if backup.exists() else "无")}


@plugin.command(name="show", summary={"zh": "查看源配置内容", "en": "Show source configuration"}, usage="gs dotfiles show <tool>", args=[{"name": "tool", "type": "enum", "required": True, "complete": {"kind": "enum", "values": sorted(TOOLS)}}])
def show(ctx):
    details = _details(ctx, _tool(ctx))
    if details is None:
        return {"exit_code": 2, "stderr": "未知工具\n"}
    source, _ = details
    if not source.is_file():
        return {"exit_code": 1, "stderr": "源配置不存在: {}\n".format(source)}
    return {"stdout": source.read_text(encoding="utf-8", errors="replace")}


if __name__ == "__main__":
    raise SystemExit(plugin.run())
