#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DevEnv plugin — GS 6.0 native port (T2 / script tier).

A faithful re-implementation of the legacy ``plugin.py`` on the new
``gs_plugin`` SDK: same ``config/tools.json`` + ``config/presets.json``, same
commands (list / status / check / presets / install / validate), but speaking
JSON-RPC over stdio instead of the old ``gscripts`` framework. No third-party
deps — stdlib only.

This is the reference for migrating the remaining Python builtins: declare
commands with ``@plugin.command``, stream output via ``ctx.emit_output``, return
an exit code, and expose dynamic completions with ``@plugin.completer``.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import unicodedata

# Make the SDK importable in-tree (repo layout) or from PYTHONPATH.
_SDK = os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python")
if os.path.isdir(_SDK):
    sys.path.insert(0, os.path.abspath(_SDK))

from gs_plugin import Plugin  # noqa: E402

plugin = Plugin(name="devenv")

_DIR = os.path.dirname(os.path.abspath(__file__))
_CONFIG = os.path.join(_DIR, "config")


# ---- config + platform -----------------------------------------------------

def _load_json(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _tools():
    """Merged tool map (tools_required + tools_optional → one dict)."""
    raw = _load_json(os.path.join(_CONFIG, "tools.json"))
    if "tools_required" in raw or "tools_optional" in raw:
        merged = {}
        merged.update(raw.get("tools_required", {}))
        merged.update(raw.get("tools_optional", {}))
        return merged
    return raw.get("tools", {})


def _presets():
    return _load_json(os.path.join(_CONFIG, "presets.json")).get("presets", {})


def _platform():
    """(os, package-manager) — mirrors the legacy detection."""
    system = platform.system()
    if system == "Darwin":
        return "macos", "brew"
    if system == "Linux":
        if os.path.exists("/etc/debian_version"):
            return "linux", "apt"
        if os.path.exists("/etc/redhat-release"):
            return "linux", "yum"
        return "linux", "unknown"
    return "unknown", "unknown"


def _check_installed(tool):
    """Run a tool's platform ``check`` command; True if it exits 0."""
    osname, _ = _platform()
    pconf = (tool or {}).get(osname)
    check = (pconf or {}).get("check")
    if not check:
        return False
    try:
        r = subprocess.run(
            check, shell=True, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=10,
        )
        return r.returncode == 0
    except Exception:
        return False


# ---- tiny text table (CJK-width aware, no deps) ----------------------------

def _w(s):
    return sum(2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in str(s))


def _pad(s, width):
    return str(s) + " " * max(0, width - _w(s))


def _table(headers, rows):
    cols = len(headers)
    widths = [_w(headers[i]) for i in range(cols)]
    for r in rows:
        for i in range(cols):
            widths[i] = max(widths[i], _w(r[i]))
    fmt = lambda cells: "  ".join(_pad(cells[i], widths[i]) for i in range(cols))
    lines = [fmt(headers), "  ".join("-" * widths[i] for i in range(cols))]
    lines += [fmt(r) for r in rows]
    return "\n".join(lines)


def _flag(ctx, name):
    return bool(ctx.args.get(name))


def _desc(d, default=""):
    d = d or {}
    return d.get("zh", d.get("en", default))


# ---- commands --------------------------------------------------------------

@plugin.command(
    name="list",
    summary={"zh": "列出所有可安装工具", "en": "List all available tools"},
    usage="gs devenv list [--required|--optional]",
    examples=["gs devenv list", "gs devenv list --required"],
    args=[
        {"name": "required", "type": "bool", "flag": "--required",
         "description": {"zh": "仅必选", "en": "Required only"}},
        {"name": "optional", "type": "bool", "flag": "--optional",
         "description": {"zh": "仅可选", "en": "Optional only"}},
    ],
)
def list_tools(ctx):
    req_only, opt_only = _flag(ctx, "required"), _flag(ctx, "optional")
    rows = []
    for name, t in sorted(_tools().items()):
        is_req = t.get("required", False)
        if (req_only and not is_req) or (opt_only and is_req):
            continue
        rows.append([
            "✅ 必选" if is_req else "⭐ 可选", name,
            t.get("name", name), t.get("category", ""), _desc(t.get("description")),
        ])
    out = _table(["类型", "工具ID", "名称", "分类", "描述"], rows)
    ctx.emit_output("stdout", out + "\n")
    return 0


@plugin.command(
    name="status",
    summary={"zh": "查看工具安装状态", "en": "Check tool installation status"},
    usage="gs devenv status [tool] [--required|--optional]",
    examples=["gs devenv status", "gs devenv status jdk"],
    args=[
        {"name": "tool", "type": "string", "description": {"zh": "工具ID", "en": "Tool id"},
         "complete": {"kind": "dynamic", "source": "tools"}},
        {"name": "required", "type": "bool", "flag": "--required"},
        {"name": "optional", "type": "bool", "flag": "--optional"},
    ],
)
def status(ctx):
    tools = _tools()
    one = ctx.args.get("tool")
    if one:
        t = tools.get(one)
        if not t:
            ctx.emit_output("stderr", "未找到工具: {}\n".format(one))
            return 1
        ok = _check_installed(t)
        ctx.emit_output("stdout", "{} {} - {}\n".format(
            "✅" if ok else "❌", t.get("name", one), "已安装" if ok else "未安装"))
        return 0
    req_only, opt_only = _flag(ctx, "required"), _flag(ctx, "optional")
    rows = []
    for name, t in sorted(tools.items()):
        is_req = t.get("required", False)
        if (req_only and not is_req) or (opt_only and is_req):
            continue
        ok = _check_installed(t)
        rows.append(["✅ 必选" if is_req else "⭐ 可选", "✅" if ok else "❌",
                     name, t.get("name", name), "已安装" if ok else "未安装"])
    ctx.emit_output("stdout", _table(["类型", "状态", "工具ID", "名称", "安装状态"], rows) + "\n")
    return 0


@plugin.command(
    name="check",
    summary={"zh": "环境检查", "en": "Environment check"},
    usage="gs devenv check [--all]",
    examples=["gs devenv check", "gs devenv check --all"],
    args=[{"name": "all", "type": "bool", "flag": "--all",
           "description": {"zh": "含可选工具", "en": "Include optional"}}],
)
def check(ctx):
    osname, pm = _platform()
    tools = _tools()
    miss_req, ok_req, miss_opt, ok_opt = [], [], [], []
    for name, t in tools.items():
        installed = _check_installed(t)
        is_req = t.get("required", False)
        (ok_req if is_req else ok_opt).append(name) if installed else (miss_req if is_req else miss_opt).append(name)
    parts = ["📍 平台: {}".format(osname), "📦 包管理器: {}".format(pm), ""]
    if ok_req or miss_req:
        rows = [["✅", t, "已安装"] for t in sorted(ok_req)] + [["❌", t, "未安装"] for t in sorted(miss_req)]
        parts.append("✅ 必选工具状态:")
        parts.append(_table(["状态", "工具ID", "备注"], rows))
        parts.append("")
    parts.append("📊 必选工具: {}/{} 已安装".format(len(ok_req), len(ok_req) + len(miss_req)))
    if _flag(ctx, "all") and (ok_opt or miss_opt):
        rows = [["✅", t, "已安装"] for t in sorted(ok_opt)] + [["❌", t, "未安装"] for t in sorted(miss_opt)]
        parts += ["", "⭐ 可选工具状态:", _table(["状态", "工具ID", "备注"], rows), ""]
        parts.append("📊 可选工具: {}/{} 已安装".format(len(ok_opt), len(ok_opt) + len(miss_opt)))
    ctx.emit_output("stdout", "\n".join(parts) + "\n")
    return 0 if not miss_req else 1


@plugin.command(
    name="presets",
    summary={"zh": "列出所有预设环境", "en": "List all presets"},
    usage="gs devenv presets",
    examples=["gs devenv presets"],
)
def presets(ctx):
    rows = []
    for name, p in sorted(_presets().items()):
        if "includes" in p:
            content = "预设: " + ", ".join(p["includes"])
        elif "tools" in p:
            content = "{}个工具".format(len(p["tools"]))
        else:
            content = "N/A"
        rows.append(["✅ 必选" if p.get("required") else "⭐ 可选", name,
                     p.get("name", name), _desc(p.get("description")), content])
    ctx.emit_output("stdout", _table(["类型", "预设名称", "显示名称", "描述", "包含内容"], rows) + "\n")
    return 0


def _install_tool(ctx, name):
    tools = _tools()
    t = tools.get(name)
    if not t:
        ctx.emit_output("stderr", "工具 '{}' 不存在\n".format(name))
        return 1
    if _check_installed(t):
        ctx.emit_output("stdout", "✅ {} 已安装\n".format(t.get("name", name)))
        return 0
    osname, _ = _platform()
    pconf = t.get(osname)
    if not pconf:
        ctx.emit_output("stderr", "工具 '{}' 不支持当前平台 {}\n".format(name, osname))
        return 1
    method = pconf.get("method")
    if method == "preinstalled":
        ctx.emit_output("stdout", "⚠️  {} 为系统自带工具\n".format(t.get("name", name)))
        return 0
    if method == "brew":
        cmd = "brew install {}{}".format("--cask " if pconf.get("cask") else "", pconf.get("package", ""))
    elif method == "apt":
        cmd = "sudo apt-get update && sudo apt-get install -y {}".format(pconf.get("package", ""))
    elif method == "script":
        cmd = pconf.get("install_script", "")
    else:
        ctx.emit_output("stderr", "不支持的安装方式: {}\n".format(method))
        return 1
    ctx.emit_progress(message="installing {}".format(name), stage="install")
    ctx.emit_output("stdout", "▶ {}\n".format(cmd))
    try:
        r = subprocess.run(cmd, shell=True, timeout=600)
    except Exception as e:
        ctx.emit_output("stderr", "安装异常: {}\n".format(e))
        return 1
    if r.returncode == 0 and _check_installed(t):
        ctx.emit_output("stdout", "✅ {} 安装成功\n".format(t.get("name", name)))
        return 0
    ctx.emit_output("stderr", "❌ {} 安装失败\n".format(name))
    return 1


@plugin.command(
    name="install",
    summary={"zh": "安装工具或预设环境", "en": "Install a tool or preset"},
    usage="gs devenv install <tool|preset> [--required-only]",
    examples=["gs devenv install jdk", "gs devenv install essential"],
    args=[
        {"name": "target", "type": "string", "required": True,
         "description": {"zh": "工具或预设名", "en": "Tool or preset name"},
         "complete": {"kind": "dynamic", "source": "tools"}},
        {"name": "required_only", "type": "bool", "flag": "--required-only",
         "description": {"zh": "预设仅装必选", "en": "Preset: required only"}},
    ],
)
def install(ctx):
    target = ctx.args.get("target")
    if not target:
        ctx.emit_output("stderr", "请指定要安装的工具或预设（见 `gs devenv list`）\n")
        return 2
    presets_map, tools = _presets(), _tools()
    if target in presets_map:
        skip_optional = _flag(ctx, "required_only")
        return _install_preset(ctx, target, skip_optional, set())
    if target in tools:
        return _install_tool(ctx, target)
    ctx.emit_output("stderr", "未找到工具或预设: {}\n".format(target))
    return 1


def _install_preset(ctx, name, skip_optional, seen):
    if name in seen:
        return 0
    seen.add(name)
    preset = _presets().get(name, {})
    tools = _tools()
    rc = 0
    for sub in preset.get("includes", []):
        rc |= _install_preset(ctx, sub, skip_optional, seen)
    for tool_name in preset.get("tools", []):
        if skip_optional and not tools.get(tool_name, {}).get("required", False):
            continue
        rc |= _install_tool(ctx, tool_name)
    return 1 if rc else 0


@plugin.command(
    name="validate",
    summary={"zh": "验证工具/预设配置", "en": "Validate tool & preset config"},
    usage="gs devenv validate [--verbose]",
    examples=["gs devenv validate", "gs devenv validate --verbose"],
    args=[{"name": "verbose", "type": "bool", "flag": "--verbose"}],
)
def validate(ctx):
    tools, presets_map = _tools(), _presets()
    errors, warnings = [], []
    for name, t in tools.items():
        if "name" not in t:
            errors.append("❌ {}: 缺少 'name'".format(name))
        if "description" not in t:
            errors.append("❌ {}: 缺少 'description'".format(name))
        if "category" not in t:
            warnings.append("⚠️  {}: 缺少 'category'".format(name))
        has_platform = False
        for osname in ("macos", "linux"):
            if osname not in t:
                continue
            has_platform = True
            pconf = t[osname]
            method = pconf.get("method")
            if method not in ("brew", "apt", "script", "preinstalled"):
                errors.append("❌ {}.{}: 非法 method '{}'".format(name, osname, method))
            if "check" not in pconf:
                errors.append("❌ {}.{}: 缺少 'check'".format(name, osname))
            if method in ("brew", "apt") and "package" not in pconf:
                errors.append("❌ {}.{}: {} 缺少 'package'".format(name, osname, method))
            if method == "script" and "install_script" not in pconf:
                errors.append("❌ {}.{}: script 缺少 'install_script'".format(name, osname))
        if not has_platform:
            errors.append("❌ {}: 无任何平台配置".format(name))
    for name, p in presets_map.items():
        if "name" not in p:
            errors.append("❌ preset '{}': 缺少 'name'".format(name))
        for tool_name in p.get("tools", []):
            if tool_name not in tools:
                errors.append("❌ preset '{}': 引用不存在的工具 '{}'".format(name, tool_name))
        for sub in p.get("includes", []):
            if sub not in presets_map:
                errors.append("❌ preset '{}': 引用不存在的预设 '{}'".format(name, sub))
        if "tools" not in p and "includes" not in p:
            errors.append("❌ preset '{}': 无 'tools' 或 'includes'".format(name))
    parts = ["🔍 配置验证报告", "=" * 40, "",
             "📦 已验证工具: {} 个".format(len(tools)),
             "🎨 已验证预设: {} 个".format(len(presets_map)),
             "🔴 错误: {}".format(len(errors)), "🟡 警告: {}".format(len(warnings)), ""]
    if errors:
        parts += ["🔴 错误列表:"] + errors + [""]
    if warnings and (_flag(ctx, "verbose") or not errors):
        parts += ["🟡 警告列表:"] + warnings + [""]
    parts.append("✅ 验证通过！" if not errors else "❌ 验证失败：{} 个错误".format(len(errors)))
    ctx.emit_output("stdout", "\n".join(parts) + "\n")
    return 0 if not errors else 1


# ---- dynamic completion: tool + preset names -------------------------------

@plugin.completer(source="tools")
def complete_tools(params):
    out = []
    for name, t in sorted(_tools().items()):
        out.append({"value": name, "description": _desc(t.get("description"), t.get("name", name))})
    for name, p in sorted(_presets().items()):
        out.append({"value": name, "description": "[预设] " + _desc(p.get("description"), name)})
    # Tool/preset sets change rarely — let the core cache for a minute.
    return {"values": out, "ttl": 60}


if __name__ == "__main__":
    raise SystemExit(plugin.run())
