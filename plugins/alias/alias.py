#!/usr/bin/env python3
"""Read-only alias source inspection for GS 6.0."""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SDK = ROOT / "sdk" / "python"
if SDK.is_dir():
    sys.path.insert(0, str(SDK))
from gs_plugin import Plugin  # noqa: E402

plugin = Plugin(name="alias")
PLUGIN_DIR = Path(__file__).resolve().parent
ALIAS_RE = re.compile(r"^\s*alias\s+([^=\s]+)=(['\"])(.*?)\2\s*(?:#.*)?$")


def _shell(ctx):
    requested = str(ctx.args.get("shell") or "").lower()
    if requested:
        return requested
    return "fish" if str(ctx.env.get("SHELL") or "").endswith("fish") else "bash"


def _sources(shell: str):
    suffix = "fish" if shell == "fish" else "sh"
    platform = "darwin" if sys.platform == "darwin" else "linux"
    return [PLUGIN_DIR / "common" / ("aliases." + suffix), PLUGIN_DIR / platform / ("aliases." + suffix)]


def _parse(shell: str):
    aliases = []
    for source in _sources(shell):
        if not source.is_file():
            continue
        for line_no, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            match = ALIAS_RE.match(line)
            if match:
                aliases.append({"name": match.group(1), "command": match.group(3), "source": str(source), "line": line_no})
    return aliases


@plugin.command(name="sources", summary={"zh": "显示将加载的别名脚本", "en": "Show alias source files"}, usage="gs alias sources [shell]", args=[{"name": "shell", "type": "enum", "complete": {"kind": "enum", "values": ["bash", "zsh", "fish"]}}])
def sources(ctx):
    shell = _shell(ctx)
    if shell not in {"bash", "zsh", "fish"}:
        return {"exit_code": 2, "stderr": "不支持的 shell: {}\n".format(shell)}
    return {"stdout": "\n".join(str(path) for path in _sources(shell)) + "\n"}


@plugin.command(name="list", summary={"zh": "列出别名", "en": "List aliases"}, usage="gs alias list [shell]", args=[{"name": "shell", "type": "enum", "complete": {"kind": "enum", "values": ["bash", "zsh", "fish"]}}])
def list_aliases(ctx):
    shell = _shell(ctx)
    aliases = _parse(shell)
    return {"stdout": "\n".join("{}\t{}".format(item["name"], item["command"]) for item in aliases) + ("\n" if aliases else "")}


@plugin.command(name="show", summary={"zh": "查询单个别名", "en": "Show one alias"}, usage="gs alias show <name> [shell]", args=[{"name": "name", "type": "string", "required": True}, {"name": "shell", "type": "enum", "complete": {"kind": "enum", "values": ["bash", "zsh", "fish"]}}])
def show_alias(ctx):
    name = str(ctx.args.get("name") or "")
    found = [item for item in _parse(_shell(ctx)) if item["name"] == name]
    if not found:
        return {"exit_code": 1, "stderr": "alias 不存在: {}\n".format(name)}
    return {"stdout": "\n".join("{}={} ({}:{})".format(item["name"], item["command"], item["source"], item["line"]) for item in found) + "\n"}


@plugin.command(name="doctor", summary={"zh": "检查别名冲突和危险定义", "en": "Check alias conflicts and risky definitions"}, usage="gs alias doctor [shell]", args=[{"name": "shell", "type": "enum", "complete": {"kind": "enum", "values": ["bash", "zsh", "fish"]}}])
def doctor(ctx):
    aliases = _parse(_shell(ctx))
    by_name = {}
    for item in aliases:
        by_name.setdefault(item["name"], []).append(item)
    duplicates = sorted(name for name, items in by_name.items() if len(items) > 1)
    risky = sorted(item["name"] for item in aliases if "rm -rf" in item["command"] or item["command"].startswith("sudo "))
    lines = ["Alias 体检", "别名数量: {}".format(len(aliases)), "重复别名: {}".format(", ".join(duplicates) if duplicates else "无"), "高风险定义: {}".format(", ".join(risky) if risky else "无")]
    return {"exit_code": 1 if risky else 0, "stdout": "\n".join(lines) + "\n"}


if __name__ == "__main__":
    raise SystemExit(plugin.run())
