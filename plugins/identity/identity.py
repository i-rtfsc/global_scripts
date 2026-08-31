#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Private identity management without bundling private assets in GS6."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_SDK = _ROOT / "sdk" / "python"
if _SDK.is_dir():
    sys.path.insert(0, str(_SDK))

from gs_plugin import Plugin  # noqa: E402


plugin = Plugin(name="identity")
SSH_FILES = {
    "id_ed25519": 0o600,
    "id_ed25519.pub": 0o644,
    "config": 0o644,
    "known_hosts": 0o644,
}
GIT_FILES = [".gitconfig-user", ".gitconfig-work", "work-commit-template.git"]
MODEL_ENVS = {
    "claude": {
        "base": "ANTHROPIC_BASE_URL",
        "key": ["ANTHROPIC_AUTH_TOKEN"],
        "extra": {
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "DISABLE_TELEMETRY": "1",
            "API_TIMEOUT_MS": "300000000",
        },
    },
    "gpt": {
        "base": "OPENAI_BASE_URL",
        "key": ["OPENAI_API_KEY", "AGENT_ROUTER_TOKEN"],
        "extra": {},
    },
    "gemini": {
        "base": "GOOGLE_GEMINI_BASE_URL",
        "key": ["GEMINI_API_KEY"],
        "extra": {},
    },
}
SECTION_START = "# >>> GS6 identity personal configuration >>>"
SECTION_END = "# <<< GS6 identity personal configuration <<<"


def _home(ctx):
    return Path(str(ctx.env.get("HOME") or Path.home())).expanduser()


def _asset_root(ctx):
    explicit = str(ctx.env.get("GS_IDENTITY_DIR") or "").strip()
    candidates = []
    if explicit:
        candidates.append(Path(explicit).expanduser())
    candidates.append(_home(ctx) / ".config" / "global-scripts" / "identity")
    root = str(ctx.env.get("GS_ROOT") or "").strip()
    if root:
        candidates.append(Path(root) / "custom" / "userspace" / "identity")
    candidates.append(_ROOT / "custom" / "userspace" / "identity")
    for candidate in candidates:
        if (candidate / "config.json").is_file() or (candidate / "ssh").is_dir() or (candidate / "git").is_dir():
            return candidate.resolve()
    return candidates[0].resolve(strict=False)


def _config_path(ctx):
    return _asset_root(ctx) / "config.json"


def _state_path(ctx):
    return _home(ctx) / ".config" / "global-scripts" / "identity_state.json"


def _backup_root(ctx, kind):
    return _home(ctx) / ".config" / "global-scripts" / "backups" / "identity" / kind


def _load_json(path, required=True):
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        if required:
            raise ValueError("无法读取 {}: {}".format(path, exc))
        return {}
    if not isinstance(value, dict):
        raise ValueError("JSON 根节点必须是对象: {}".format(path))
    return value


def _write_json(path, value, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".gs6-identity-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _mode(ctx, label, allowed_extra=None):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    allowed = {"--dry-run", "--yes"} | set(allowed_extra or [])
    dry_run = "--dry-run" in options
    execute = "--yes" in options
    unknown = [value for value in options if value not in allowed and not value.startswith("--backup=")]
    if dry_run == execute or unknown:
        return None, options, {"exit_code": 2, "stderr": "{} 必须且只能指定 --dry-run 或 --yes\n".format(label)}
    return ("dry-run" if dry_run else "execute"), options, None


def _timestamp():
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f")


def _backup_directory(ctx, kind, sources):
    destination = _backup_root(ctx, kind) / _timestamp()
    destination.mkdir(parents=True, exist_ok=True)
    copied = []
    for source in sources:
        if not source.exists():
            continue
        target = destination / source.name
        if source.is_dir():
            shutil.copytree(source, target)
        else:
            shutil.copy2(source, target)
        copied.append(source.name)
    backups = sorted(
        [path for path in destination.parent.iterdir() if path.is_dir()],
        key=lambda path: path.name,
        reverse=True,
    )
    for old in backups[3:]:
        shutil.rmtree(old)
    return destination, copied


def _backups(ctx, kind):
    root = _backup_root(ctx, kind)
    if not root.is_dir():
        return []
    return sorted([path for path in root.iterdir() if path.is_dir()], key=lambda path: path.name, reverse=True)


def _selected_backup(ctx, kind, options):
    requested = next((value.split("=", 1)[1] for value in options if value.startswith("--backup=")), "")
    candidates = _backups(ctx, kind)
    if requested:
        candidates = [path for path in candidates if path.name == requested]
    return candidates[0] if candidates else None


def _model_config(ctx):
    return _load_json(_config_path(ctx))


def _model_show(ctx, model):
    try:
        config = _model_config(ctx)
    except ValueError as exc:
        return {"exit_code": 1, "stderr": str(exc) + "\n"}
    accounts = (config.get("accounts") or {}).get(model) or {}
    routers = config.get("routers") or {}
    state = _load_json(_state_path(ctx), required=False).get("current") or {}
    lines = ["{} 模型信息".format(model.upper()), "账号:"]
    for name, value in accounts.items():
        lines.append("  {}: {}".format(name, value.get("email", "")))
    lines.append("中转站:")
    for name, value in routers.items():
        if model in (value.get("supports") or []):
            lines.append("  {}: {} (默认节点: {})".format(name, value.get("name", name), value.get("default_node", "main")))
    if state.get("model") == model:
        lines.append("当前: {}/{} {}".format(state.get("router"), state.get("node"), state.get("account")))
    return {"stdout": "\n".join(lines) + "\n"}


def _switch_account(ctx, model, account):
    try:
        config = _model_config(ctx)
    except ValueError as exc:
        return {"exit_code": 1, "stderr": str(exc) + "\n"}
    route = str(ctx.args.get("router") or "").strip()
    defaults = config.get("defaults") or {}
    if not route:
        route = str(defaults.get("router") or ("agentrouter" if model == "gpt" else "anyrouter"))
        if model == "gpt" and route == "anyrouter":
            route = "agentrouter"
    router, separator, node = route.partition(":")
    routers = config.get("routers") or {}
    router_config = routers.get(router) or {}
    if not node:
        node = str(router_config.get("default_node") or "main")
    account_config = (((config.get("accounts") or {}).get(model) or {}).get(account) or {})
    email = str(account_config.get("email") or "")
    api_key = str((account_config.get("api_keys") or {}).get(router) or "")
    base_url = str((router_config.get("base_urls") or {}).get(node) or "")
    if not email:
        return {"exit_code": 1, "stderr": "未找到账号 {}/{}\n".format(model, account)}
    if not api_key:
        return {"exit_code": 1, "stderr": "未找到 API Key {}/{}/{}\n".format(model, account, router)}
    if not base_url:
        return {"exit_code": 1, "stderr": "未找到节点 {}/{}\n".format(router, node)}
    env_spec = MODEL_ENVS[model]
    changes = {env_spec["base"]: base_url}
    changes.update({name: api_key for name in env_spec["key"]})
    changes.update(env_spec["extra"])
    current = {
        "router": router,
        "node": node,
        "is_temp_node": bool(separator),
        "model": model,
        "account": account,
        "email": email,
        "base_url": base_url,
    }
    try:
        _write_json(_state_path(ctx), {"current": current})
    except OSError as exc:
        return {"exit_code": 1, "stderr": "写入 identity 状态失败: {}\n".format(exc)}
    return {
        "env": changes,
        "stdout": "已切换到 {}/{} - {}\n节点: {}{}\nBase URL: {}\nAPI key: 已加载（未显示）\n".format(
            router, model, email, node, " (临时)" if separator else " (默认)", base_url
        ),
    }


def _router(ctx, router):
    try:
        config = _model_config(ctx)
    except ValueError as exc:
        return {"exit_code": 1, "stderr": str(exc) + "\n"}
    router_config = (config.get("routers") or {}).get(router) or {}
    nodes = router_config.get("base_urls") or {}
    if not nodes:
        return {"exit_code": 1, "stderr": "未找到中转站 {}\n".format(router)}
    requested = str(ctx.args.get("node") or "").strip()
    state_value = _load_json(_state_path(ctx), required=False)
    current = state_value.get("current") or {}
    if not requested:
        lines = ["{} 可用节点:".format(router)]
        lines.extend("  {}: {}".format(name, url) for name, url in nodes.items())
        lines.append("默认节点: {}".format(router_config.get("default_node", "main")))
        if current.get("router") == router:
            lines.append("当前节点: {}{}".format(current.get("node"), " (临时)" if current.get("is_temp_node") else ""))
        return {"stdout": "\n".join(lines) + "\n"}
    base_url = str(nodes.get(requested) or "")
    if not base_url:
        return {"exit_code": 1, "stderr": "未找到节点 {}/{}\n".format(router, requested)}
    if current.get("router") != router or current.get("model") not in MODEL_ENVS:
        return {"exit_code": 1, "stderr": "当前状态未使用 {}，请先切换账号\n".format(router)}
    env_name = MODEL_ENVS[current["model"]]["base"]
    current.update({"node": requested, "base_url": base_url, "is_temp_node": True})
    _write_json(_state_path(ctx), {"current": current})
    return {"env": {env_name: base_url}, "stdout": "已临时切换 {} 节点: {}\nBase URL: {}\n".format(router, requested, base_url)}


def _git_paths(ctx):
    source = _asset_root(ctx) / "git"
    target = _home(ctx) / ".config" / "global-scripts" / "git"
    return source, target, _home(ctx) / ".gitconfig"


def _ssh_paths(ctx):
    return _asset_root(ctx) / "ssh", _home(ctx) / ".ssh"


def _remove_git_section(text):
    start = text.find(SECTION_START)
    if start < 0:
        return text
    end = text.find(SECTION_END, start)
    if end < 0:
        return text
    end += len(SECTION_END)
    return (text[:start].rstrip() + "\n" + text[end:].lstrip()).rstrip() + "\n"


def _git_action(ctx, action):
    mode, options, error = _mode(ctx, "identity git {}".format(action), {"--force"})
    if error:
        return error
    source, target, main = _git_paths(ctx)
    sources = [target / name for name in GIT_FILES] + [target / "hooks", main]
    if action == "backup":
        if mode == "dry-run":
            return {"stdout": "Identity Git backup 计划（dry-run）\n不会复制配置\n"}
        destination, copied = _backup_directory(ctx, "git", sources)
        return {"exit_code": 0 if copied else 1, "stdout": "Git 配置已备份: {}\n文件: {}\n".format(destination, ", ".join(copied) or "无")}
    if action == "restore":
        backup = _selected_backup(ctx, "git", options)
        if backup is None:
            return {"exit_code": 1, "stderr": "没有可用的 Git 身份备份\n"}
        if mode == "dry-run":
            return {"stdout": "Identity Git restore 计划（dry-run）\nBackup: {}\n不会覆盖配置\n".format(backup)}
        target.mkdir(parents=True, exist_ok=True)
        for name in GIT_FILES:
            if (backup / name).is_file():
                shutil.copy2(backup / name, target / name)
        if (backup / "hooks").is_dir():
            shutil.copytree(backup / "hooks", target / "hooks", dirs_exist_ok=True)
        if (backup / ".gitconfig").is_file():
            shutil.copy2(backup / ".gitconfig", main)
        return {"stdout": "Git 身份配置已恢复: {}\n".format(backup.name)}
    if action == "install":
        missing = [name for name in GIT_FILES if not (source / name).is_file()]
        if missing:
            return {"exit_code": 1, "stderr": "Git 私有资产缺失: {}\n".format(", ".join(missing))}
        if mode == "dry-run":
            return {"stdout": "Identity Git install 计划（dry-run）\nSource: {}\nTarget: {}\n不会写入配置\n".format(source, target)}
        existing = [path for path in sources if path.exists()]
        if existing:
            _backup_directory(ctx, "git", existing)
        target.mkdir(parents=True, exist_ok=True)
        for name in GIT_FILES:
            shutil.copy2(source / name, target / name)
        if (source / "hooks").is_dir():
            shutil.copytree(source / "hooks", target / "hooks", dirs_exist_ok=True)
        fragment = (source / ".gitconfig").read_text(encoding="utf-8") if (source / ".gitconfig").is_file() else ""
        text = main.read_text(encoding="utf-8") if main.is_file() else ""
        text = _remove_git_section(text)
        text += "\n{}\n{}\n{}\n".format(SECTION_START, fragment.rstrip(), SECTION_END)
        main.write_text(text.lstrip(), encoding="utf-8")
        return {"stdout": "Git 身份配置已安装\nTarget: {}\n".format(target)}
    if mode == "dry-run":
        return {"stdout": "Identity Git uninstall 计划（dry-run）\n不会删除配置\n"}
    existing = [path for path in sources if path.exists()]
    if existing:
        _backup_directory(ctx, "git", existing)
    for name in GIT_FILES:
        path = target / name
        if path.exists():
            path.unlink()
    if (target / "hooks").is_dir():
        shutil.rmtree(target / "hooks")
    if main.is_file():
        main.write_text(_remove_git_section(main.read_text(encoding="utf-8")), encoding="utf-8")
    return {"stdout": "Git 身份配置已卸载\n"}


def _ssh_action(ctx, action):
    mode, options, error = _mode(ctx, "identity ssh {}".format(action), {"--force"})
    if error:
        return error
    source, target = _ssh_paths(ctx)
    targets = [target / name for name in SSH_FILES]
    if action == "backup":
        if mode == "dry-run":
            return {"stdout": "Identity SSH backup 计划（dry-run）\n不会复制密钥\n"}
        destination, copied = _backup_directory(ctx, "ssh", targets)
        return {"exit_code": 0 if copied else 1, "stdout": "SSH 配置已备份: {}\n文件: {}\n".format(destination, ", ".join(copied) or "无")}
    if action == "restore":
        backup = _selected_backup(ctx, "ssh", options)
        if backup is None:
            return {"exit_code": 1, "stderr": "没有可用的 SSH 身份备份\n"}
        if mode == "dry-run":
            return {"stdout": "Identity SSH restore 计划（dry-run）\nBackup: {}\n不会覆盖密钥\n".format(backup)}
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(target, 0o700)
        for name, permission in SSH_FILES.items():
            if (backup / name).is_file():
                shutil.copy2(backup / name, target / name)
                os.chmod(target / name, permission)
        return {"stdout": "SSH 身份配置已恢复: {}\n".format(backup.name)}
    if action == "install":
        available = [name for name in SSH_FILES if (source / name).is_file()]
        if not available:
            return {"exit_code": 1, "stderr": "SSH 私有资产目录没有可安装文件: {}\n".format(source)}
        if mode == "dry-run":
            return {"stdout": "Identity SSH install 计划（dry-run）\nSource: {}\nTarget: {}\nFiles: {}\n不会复制密钥\n".format(source, target, ", ".join(available))}
        existing = [path for path in targets if path.exists()]
        if existing:
            _backup_directory(ctx, "ssh", existing)
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(target, 0o700)
        for name in available:
            shutil.copy2(source / name, target / name)
            os.chmod(target / name, SSH_FILES[name])
        return {"stdout": "SSH 身份配置已安装\nTarget: {}\nFiles: {}\n".format(target, ", ".join(available))}
    if mode == "dry-run":
        return {"stdout": "Identity SSH uninstall 计划（dry-run）\n不会删除密钥\n"}
    existing = [path for path in targets if path.exists()]
    if existing:
        _backup_directory(ctx, "ssh", existing)
    for path in existing:
        path.unlink()
    return {"stdout": "SSH 身份配置已卸载\n"}


@plugin.command(name="list", summary={"zh": "列出身份配置能力", "en": "List identity configuration capabilities"}, usage="gs identity list")
def list_configs(ctx):
    root = _asset_root(ctx)
    return {"stdout": "Identity tools: claude, gpt, gemini, router, git, ssh\nPrivate asset root: {}\nConfig: {}\n".format(root, "available" if (root / "config.json").is_file() else "missing")}


@plugin.command(name="help", summary={"zh": "显示 Identity 帮助", "en": "Show Identity help"}, usage="gs identity help")
def help_command(ctx):
    del ctx
    return {"stdout": "Identity commands: model account switching, router nodes, Git config, SSH config\nSet GS_IDENTITY_DIR to a private asset directory. GS6 release packages never contain private identity assets.\n"}


def _register_model_command(model, account):
    @plugin.command(
        name="{}.{}".format(model, account),
        summary={"zh": "切换 {} 账号 {}".format(model, account), "en": "Switch {} account {}".format(model, account)},
        usage="gs identity {} {} [router[:node]]".format(model, account),
        args=[{"name": "router", "type": "string", "description": {"zh": "中转站或中转站:节点", "en": "Router or router:node"}}],
    )
    def handler(ctx, selected_model=model, selected_account=account):
        return _switch_account(ctx, selected_model, selected_account)
    return handler


for _model, _accounts in {"claude": ["outlook", "icloud", "163", "qq"], "gpt": ["outlook", "icloud", "163", "qq"], "gemini": ["outlook"]}.items():
    for _account in _accounts:
        _register_model_command(_model, _account)


def _register_show(model):
    @plugin.command(name="{}.show".format(model), summary={"zh": "显示 {} 账号与中转站".format(model), "en": "Show {} accounts and routers".format(model)}, usage="gs identity {} show".format(model))
    def handler(ctx, selected_model=model):
        return _model_show(ctx, selected_model)
    return handler


for _model in ("claude", "gpt", "gemini"):
    _register_show(_model)


def _register_router(name):
    @plugin.command(name="router.{}".format(name), summary={"zh": "显示或切换 {} 节点".format(name), "en": "Show or switch {} nodes".format(name)}, usage="gs identity router {} [node]".format(name), args=[{"name": "node", "type": "string", "description": {"zh": "临时节点", "en": "Temporary node"}}])
    def handler(ctx, selected=name):
        return _router(ctx, selected)
    return handler


for _router_name in ("anyrouter", "agentrouter", "codemirror"):
    _register_router(_router_name)


_WRITE_ARGS = [{"name": "options", "type": "string", "variadic": True}]


for _action in ("install", "uninstall", "backup", "restore"):
    def _register_git(action):
        @plugin.command(name="git.{}".format(action), summary={"zh": "{} Git 身份配置".format(action), "en": "{} Git identity config".format(action)}, usage="gs identity git {} <--dry-run|--yes>".format(action), args=_WRITE_ARGS)
        def handler(ctx, selected=action):
            return _git_action(ctx, selected)
        return handler
    _register_git(_action)


@plugin.command(name="git.status", summary={"zh": "查看 Git 身份配置状态", "en": "Show Git identity status"}, usage="gs identity git status")
def git_status(ctx):
    source, target, main = _git_paths(ctx)
    lines = ["Git 身份配置状态", "Private source: {}".format(source)]
    lines.extend("  {}: {}".format(name, "installed" if (target / name).is_file() else "missing") for name in GIT_FILES)
    lines.append("  main .gitconfig: {}".format("present" if main.is_file() else "missing"))
    lines.append("  backups: {}".format(len(_backups(ctx, "git"))))
    return {"stdout": "\n".join(lines) + "\n"}


for _action in ("install", "uninstall", "backup", "restore"):
    def _register_ssh(action):
        @plugin.command(name="ssh.{}".format(action), summary={"zh": "{} SSH 身份配置".format(action), "en": "{} SSH identity config".format(action)}, usage="gs identity ssh {} <--dry-run|--yes>".format(action), args=_WRITE_ARGS)
        def handler(ctx, selected=action):
            return _ssh_action(ctx, selected)
        return handler
    _register_ssh(_action)


@plugin.command(name="ssh.status", summary={"zh": "查看 SSH 身份配置状态", "en": "Show SSH identity status"}, usage="gs identity ssh status")
def ssh_status(ctx):
    source, target = _ssh_paths(ctx)
    lines = ["SSH 身份配置状态", "Private source: {}".format(source)]
    for name, permission in SSH_FILES.items():
        path = target / name
        actual = (path.stat().st_mode & 0o777) if path.exists() else None
        lines.append("  {}: {}{}".format(name, "installed" if actual is not None else "missing", " mode={:o}".format(actual) if actual is not None else ""))
    lines.append("  backups: {}".format(len(_backups(ctx, "ssh"))))
    return {"stdout": "\n".join(lines) + "\n"}


@plugin.command(name="ssh.permissions", summary={"zh": "修复 SSH 文件权限", "en": "Fix SSH file permissions"}, usage="gs identity ssh permissions <--dry-run|--yes>", args=_WRITE_ARGS)
def ssh_permissions(ctx):
    mode, _, error = _mode(ctx, "identity ssh permissions")
    if error:
        return error
    _, target = _ssh_paths(ctx)
    if mode == "dry-run":
        return {"stdout": "Identity SSH permissions 计划（dry-run）\nDirectory: 700\nPrivate key: 600\n不会修改权限\n"}
    if target.is_dir():
        os.chmod(target, 0o700)
    fixed = []
    for name, permission in SSH_FILES.items():
        path = target / name
        if path.exists():
            os.chmod(path, permission)
            fixed.append("{}={:o}".format(name, permission))
    return {"exit_code": 0 if fixed else 1, "stdout": "SSH 权限已修复: {}\n".format(", ".join(fixed) or "无文件")}


if __name__ == "__main__":
    raise SystemExit(plugin.run())
