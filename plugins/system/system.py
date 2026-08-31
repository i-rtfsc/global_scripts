#!/usr/bin/env python3
"""GS 6.0 system utilities.

Only commands with well-defined cross-process semantics are exposed here.
Environment-mutating proxy/repo switches and Homebrew mirror writes remain on
the legacy ``system`` plugin until the GS 6.0 shell-effects protocol exists.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import List

_ROOT = Path(__file__).resolve().parents[2]
_SDK = _ROOT / "sdk" / "python"
if _SDK.is_dir():
    sys.path.insert(0, str(_SDK))

from gs_plugin import Plugin  # noqa: E402

plugin = Plugin(name="system")

PROXY_URL = "http://127.0.0.1:7890"
NO_PROXY = "127.0.0.1,localhost"
REPO_SOURCES = {
    "google": ("Google 官方源", "https://gerrit.googlesource.com/git-repo"),
    "intel": ("Intel 镜像源", "https://gerrit.intel.com/git-repo"),
    "tsinghua": ("清华大学镜像源", "https://mirrors.tuna.tsinghua.edu.cn/git/git-repo"),
}
BREW_MIRRORS = {
    "github": {
        "name": "GitHub 官方源",
        "brew": "https://github.com/Homebrew/brew.git",
        "core": "https://github.com/Homebrew/homebrew-core.git",
        "cask": "https://github.com/Homebrew/homebrew-cask.git",
        "bottles": None,
    },
    "ustc": {
        "name": "中科大镜像源",
        "brew": "https://mirrors.ustc.edu.cn/brew.git",
        "core": "https://mirrors.ustc.edu.cn/homebrew-core.git",
        "cask": "https://mirrors.ustc.edu.cn/homebrew-cask.git",
        "bottles": "https://mirrors.ustc.edu.cn/homebrew-bottles",
    },
    "tsinghua": {
        "name": "清华大学镜像源",
        "brew": "https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/brew.git",
        "core": "https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/homebrew-core.git",
        "cask": "https://mirrors.tuna.tsinghua.edu.cn/git/homebrew/homebrew-cask.git",
        "bottles": "https://mirrors.tuna.tsinghua.edu.cn/homebrew-bottles",
    },
    "aliyun": {
        "name": "阿里云镜像源",
        "brew": "https://mirrors.aliyun.com/homebrew/brew.git",
        "core": "https://mirrors.aliyun.com/homebrew/homebrew-core.git",
        "cask": "https://mirrors.aliyun.com/homebrew/homebrew-cask.git",
        "bottles": "https://mirrors.aliyun.com/homebrew/homebrew-bottles",
    },
}


def _env(ctx, name: str) -> str:
    value = ctx.env.get(name)
    return str(value) if value is not None else ""


def _themes_dir(ctx) -> Path:
    root = _env(ctx, "GS_ROOT")
    return (Path(root) if root else _ROOT) / "themes" / "prompt"


def _theme_names(ctx) -> List[str]:
    directory = _themes_dir(ctx)
    if not directory.is_dir():
        return []
    return sorted(
        path.stem
        for path in directory.glob("*.sh")
        if path.name not in {"_lib.sh", "load.sh"}
    )


def _config_path(ctx) -> Path:
    explicit = _env(ctx, "GS_CONFIG_FILE")
    if explicit:
        return Path(explicit).expanduser()
    home = _env(ctx, "HOME")
    if home:
        user = Path(home) / ".config" / "global-scripts" / "config" / "gs.json"
        if user.is_file():
            return user
    root = _env(ctx, "GS_ROOT")
    return (Path(root) if root else _ROOT) / "config" / "gs.json"


def _write_config(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".gs6-", suffix=".json", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.replace(tmp_name, path)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _mode(ctx, label):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    dry_run = "--dry-run" in options
    execute = "--yes" in options
    if dry_run == execute or any(value not in {"--dry-run", "--yes"} for value in options):
        return None, {"exit_code": 2, "stderr": "{} 必须且只能指定 --dry-run 或 --yes\n".format(label)}
    return ("dry-run" if dry_run else "execute"), None


def _proxy_change(ctx, enabled):
    mode, error = _mode(ctx, "system proxy")
    if error:
        return error
    changes = {
        "http_proxy": PROXY_URL,
        "https_proxy": PROXY_URL,
        "no_proxy": NO_PROXY,
        "HTTP_PROXY": PROXY_URL,
        "HTTPS_PROXY": PROXY_URL,
        "NO_PROXY": NO_PROXY,
    }
    if not enabled:
        changes = {name: None for name in changes}
    if mode == "dry-run":
        return {"stdout": "代理变更计划（dry-run）\nAction: {}\n不会修改当前 shell\n".format("on" if enabled else "off")}
    return {
        "env": changes,
        "stdout": ("✅ 已开启代理: {}\n".format(PROXY_URL) if enabled else "❌ 已关闭代理\n"),
    }


def _repo_change(ctx, source):
    mode, error = _mode(ctx, "system repo")
    if error:
        return error
    name, url = REPO_SOURCES[source]
    if mode == "dry-run":
        return {"stdout": "Repo 源变更计划（dry-run）\nSource: {}\nREPO_URL: {}\n不会修改当前 shell\n".format(name, url)}
    return {"env": {"REPO_URL": url}, "stdout": "✅ 已切换到 {}\n🔗 REPO_URL: {}\n".format(name, url)}


def _brew_change(ctx, source):
    mode, error = _mode(ctx, "system brew")
    if error:
        return error
    mirror = BREW_MIRRORS[source]
    lines = ["Homebrew 镜像变更计划", "Source: {}".format(mirror["name"])]
    for component in ("brew", "core", "cask"):
        lines.append("  {}: {}".format(component, mirror[component]))
    lines.append("  bottles: {}".format(mirror["bottles"] or "默认"))
    if mode == "dry-run":
        lines.append("不会修改 Git remote，也不会执行 brew update")
        return {"stdout": "\n".join(lines) + "\n"}
    brew = _env(ctx, "GS_SYSTEM_BREW_BIN") or "brew"
    git = _env(ctx, "GS_SYSTEM_GIT_BIN") or "git"
    try:
        repositories = {}
        for component, args in {
            "brew": ["--repo"],
            "core": ["--repo", "homebrew/core"],
            "cask": ["--repo", "homebrew/cask"],
        }.items():
            repositories[component] = subprocess.run(
                [brew] + args, capture_output=True, text=True, timeout=15, check=True
            ).stdout.strip()
        for component, repository in repositories.items():
            subprocess.run(
                [git, "-C", repository, "remote", "set-url", "origin", mirror[component]],
                capture_output=True, text=True, timeout=15, check=True,
            )
        child_env = os.environ.copy()
        if mirror["bottles"]:
            child_env["HOMEBREW_BOTTLE_DOMAIN"] = mirror["bottles"]
        else:
            child_env.pop("HOMEBREW_BOTTLE_DOMAIN", None)
        subprocess.run([brew, "update"], env=child_env, timeout=300, check=True)
    except FileNotFoundError as exc:
        return {"exit_code": 127, "stderr": "命令不存在: {}\n".format(exc.filename)}
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        return {"exit_code": 1, "stderr": "切换 Homebrew 镜像失败: {}\n".format(exc)}
    return {
        "env": {"HOMEBREW_BOTTLE_DOMAIN": mirror["bottles"]},
        "stdout": "✅ 已切换到 {}\n".format(mirror["name"]),
    }


_MODE_ARG = [{"name": "options", "type": "string", "variadic": True}]


@plugin.command(name="proxy.on", summary={"zh": "开启系统代理", "en": "Enable proxy variables"}, usage="gs system proxy on <--dry-run|--yes>", args=_MODE_ARG)
def proxy_on(ctx):
    return _proxy_change(ctx, True)


@plugin.command(name="proxy.off", summary={"zh": "关闭系统代理", "en": "Disable proxy variables"}, usage="gs system proxy off <--dry-run|--yes>", args=_MODE_ARG)
def proxy_off(ctx):
    return _proxy_change(ctx, False)


@plugin.command(
    name="proxy.status",
    summary={"zh": "查看代理环境变量状态", "en": "Show proxy environment status"},
    usage="gs system proxy status",
)
def proxy_status(ctx):
    names = [
        "http_proxy", "https_proxy", "no_proxy",
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
    ]
    active = [(name, _env(ctx, name)) for name in names if _env(ctx, name)]
    if not active:
        return {"stdout": "🚫 当前代理状态: 已禁用\n"}
    lines = ["🌐 当前代理状态: 已启用"]
    lines.extend("  {}: {}".format(name, value) for name, value in active)
    return {"stdout": "\n".join(lines) + "\n"}


@plugin.command(
    name="proxy.config",
    summary={"zh": "查看默认代理配置", "en": "Show default proxy configuration"},
    usage="gs system proxy config",
)
def proxy_config(ctx):
    del ctx
    return {
        "stdout": (
            "⚙️  代理配置信息:\n"
            "  代理地址: 127.0.0.1\n"
            "  代理端口: 7890\n"
            "  代理URL:  http://127.0.0.1:7890\n"
        )
    }


@plugin.command(
    name="brew.remote",
    summary={"zh": "查看当前 Homebrew 镜像源", "en": "Show Homebrew remotes"},
    usage="gs system brew remote",
)
def brew_remote(ctx):
    del ctx
    try:
        brew_root = subprocess.run(
            ["brew", "--repo"], capture_output=True, text=True, timeout=5, check=True
        ).stdout.strip()
        remote = subprocess.run(
            ["git", "-C", brew_root, "remote", "-v"],
            capture_output=True, text=True, timeout=5, check=True,
        ).stdout.strip()
        return {"stdout": "📦 brew.git:\n{}\n".format(remote or "  未配置 remote")}
    except FileNotFoundError as exc:
        return {"exit_code": 127, "stderr": "命令不存在: {}\n".format(exc.filename)}
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        return {"exit_code": 1, "stderr": "读取 Homebrew remote 失败: {}\n".format(exc)}


@plugin.command(name="brew.github", summary={"zh": "切换到 GitHub 官方源", "en": "Switch to GitHub Homebrew remotes"}, usage="gs system brew github <--dry-run|--yes>", args=_MODE_ARG)
def brew_github(ctx):
    return _brew_change(ctx, "github")


@plugin.command(name="brew.ustc", summary={"zh": "切换到中科大镜像源", "en": "Switch to USTC Homebrew mirrors"}, usage="gs system brew ustc <--dry-run|--yes>", args=_MODE_ARG)
def brew_ustc(ctx):
    return _brew_change(ctx, "ustc")


@plugin.command(name="brew.tsinghua", summary={"zh": "切换到清华镜像源", "en": "Switch to Tsinghua Homebrew mirrors"}, usage="gs system brew tsinghua <--dry-run|--yes>", args=_MODE_ARG)
def brew_tsinghua(ctx):
    return _brew_change(ctx, "tsinghua")


@plugin.command(name="brew.aliyun", summary={"zh": "切换到阿里云镜像源", "en": "Switch to Aliyun Homebrew mirrors"}, usage="gs system brew aliyun <--dry-run|--yes>", args=_MODE_ARG)
def brew_aliyun(ctx):
    return _brew_change(ctx, "aliyun")


@plugin.command(
    name="repo.status",
    summary={"zh": "查看当前 Repo 源配置", "en": "Show current repo source"},
    usage="gs system repo status",
)
def repo_status(ctx):
    url = _env(ctx, "REPO_URL")
    if not url:
        return {"stdout": "🚫 未设置 REPO_URL，将使用默认源\n"}
    known = {
        "https://gerrit.googlesource.com/git-repo": "Google 官方源",
        "https://gerrit.intel.com/git-repo": "Intel 镜像源",
        "https://mirrors.tuna.tsinghua.edu.cn/git/git-repo": "清华大学镜像源",
    }
    return {"stdout": "🌐 当前Repo源: {}\n🔗 REPO_URL: {}\n".format(known.get(url, "自定义源"), url)}


@plugin.command(name="repo.google", summary={"zh": "切换到 Google 官方源", "en": "Switch to the Google repo source"}, usage="gs system repo google <--dry-run|--yes>", args=_MODE_ARG)
def repo_google(ctx):
    return _repo_change(ctx, "google")


@plugin.command(name="repo.intel", summary={"zh": "切换到 Intel 镜像源", "en": "Switch to the Intel repo source"}, usage="gs system repo intel <--dry-run|--yes>", args=_MODE_ARG)
def repo_intel(ctx):
    return _repo_change(ctx, "intel")


@plugin.command(name="repo.tsinghua", summary={"zh": "切换到清华镜像源", "en": "Switch to the Tsinghua repo source"}, usage="gs system repo tsinghua <--dry-run|--yes>", args=_MODE_ARG)
def repo_tsinghua(ctx):
    return _repo_change(ctx, "tsinghua")


@plugin.command(
    name="prompt.themes",
    summary={"zh": "列出可用提示符主题", "en": "List prompt themes"},
    usage="gs system prompt themes",
)
def prompt_themes(ctx):
    names = _theme_names(ctx)
    return {"stdout": ("\n".join(names) if names else "No themes found") + "\n"}


@plugin.command(
    name="prompt.current",
    summary={"zh": "显示当前提示符主题", "en": "Show current prompt theme"},
    usage="gs system prompt current",
)
def prompt_current(ctx):
    return {"stdout": (_env(ctx, "GS_PROMPT_THEME") or "minimalist") + "\n"}


@plugin.command(
    name="prompt.set",
    summary={"zh": "设置并持久化提示符主题", "en": "Set and persist prompt theme"},
    usage="gs system prompt set <theme>",
    args=[{
        "name": "theme", "type": "string", "required": True,
        "description": {"zh": "主题名称", "en": "Theme name"},
        "complete": {"kind": "dynamic", "source": "prompt-themes"},
    }],
)
def prompt_set(ctx):
    theme = str(ctx.args.get("theme") or "")
    names = _theme_names(ctx)
    if theme not in names:
        return {"exit_code": 2, "stderr": "Theme not found: {}\n".format(theme)}
    path = _config_path(ctx)
    try:
        value = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
        if not isinstance(value, dict):
            raise ValueError("configuration root must be an object")
        value["prompt_theme"] = theme
        _write_config(path, value)
    except Exception as exc:
        return {"exit_code": 1, "stderr": "Failed to update config: {}\n".format(exc)}
    return {"stdout": "Theme set to: {}\n".format(theme)}


@plugin.completer(source="prompt-themes")
def prompt_theme_completion(params):
    class Context:
        env = params.get("env") or os.environ

    return {"values": _theme_names(Context()), "ttl": 30}


if __name__ == "__main__":
    raise SystemExit(plugin.run())
