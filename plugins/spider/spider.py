#!/usr/bin/env python3
"""GS 6.0 spider: platform classification and bounded article crawling."""
from __future__ import annotations

import importlib.util
import html
import re
import subprocess
import sys
import urllib.error
import urllib.request
from hashlib import sha256
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SDK = ROOT / "sdk" / "python"
if SDK.is_dir():
    sys.path.insert(0, str(SDK))
from gs_plugin import Plugin  # noqa: E402

plugin = Plugin(name="spider")

PLATFORMS = {
    "jianshu": ("简书", re.compile(r"^https?://(?:www\.)?jianshu\.com/(?:u/[^/]+|p/[^/]+)(?:/.*)?$")),
    "csdn": ("CSDN", re.compile(r"^https?://(?:blog\.)?csdn\.net/[^/]+(?:/article/details/\d+)?/?$")),
    "cnblogs": ("博客园", re.compile(r"^https?://(?:www\.)?cnblogs\.com/[^/]+(?:/p/\d+\.html)?/?$")),
}
DEPS = {"requests": "requests", "beautifulsoup4": "bs4", "markdownify": "markdownify", "selenium": "selenium", "parsel": "parsel"}


def _target(ctx):
    return str(ctx.args.get("target") or "")


def _classify(target: str):
    if not target:
        return {"kind": "missing", "message": "请提供用户名或 URL"}
    if not target.startswith(("http://", "https://")):
        return {"kind": "username", "message": "用户名/标识符", "target": target}
    for key, (label, pattern) in PLATFORMS.items():
        if pattern.match(target):
            return {"kind": "url", "platform": key, "label": label, "target": target}
    return {"kind": "invalid", "message": "不支持或格式无效的 URL", "target": target}


@plugin.command(
    name="info",
    summary={"zh": "显示爬虫能力信息", "en": "Show spider capabilities"},
    usage="gs spider info",
)
def info(ctx):
    del ctx
    return {"stdout": "🕷️ Spider6\n平台: 简书、博客园、CSDN\n抓取: 受控联网，20 秒超时，5 MiB 上限\n"}


@plugin.command(
    name="list",
    summary={"zh": "列出支持的平台", "en": "List supported platforms"},
    usage="gs spider list",
)
def list_platforms(ctx):
    del ctx
    return {"stdout": "\n".join("{}\t{}".format(k, v[0]) for k, v in PLATFORMS.items()) + "\n"}


@plugin.command(
    name="classify",
    summary={"zh": "识别目标平台和 URL 类型", "en": "Classify a target URL"},
    usage="gs spider classify <target>",
    args=[{"name": "target", "type": "string", "required": True, "description": {"zh": "用户名或 URL", "en": "Username or URL"}}],
)
def classify(ctx):
    result = _classify(_target(ctx))
    if result["kind"] == "missing":
        return {"exit_code": 2, "stderr": result["message"] + "\n"}
    if result["kind"] == "invalid":
        return {"exit_code": 2, "stderr": "{}: {}\n".format(result["message"], result["target"])}
    if result["kind"] == "username":
        return {"stdout": "类型: 用户名/标识符\n目标: {}\n".format(result["target"])}
    return {"stdout": "平台: {}\n类型: URL\n目标: {}\n".format(result["label"], result["target"])}


@plugin.command(
    name="check-deps",
    summary={"zh": "检查可选爬虫依赖", "en": "Check optional spider dependencies"},
    usage="gs spider check-deps",
)
def check_deps(ctx):
    del ctx
    missing = []
    lines = []
    for package, module in DEPS.items():
        ok = importlib.util.find_spec(module) is not None
        lines.append("{} {}".format("✅" if ok else "❌", package))
        if not ok:
            missing.append(package)
    lines.append("\n缺少依赖: " + ", ".join(missing) if missing else "\n所有可选依赖均已安装")
    return {"exit_code": 1 if missing else 0, "stdout": "\n".join(lines) + "\n"}


@plugin.command(
    name="install-deps",
    summary={"zh": "安装可选爬虫依赖", "en": "Install optional spider dependencies"},
    usage="gs spider install-deps <--dry-run|--yes>",
    args=[{"name": "options", "type": "string", "variadic": True}],
)
def install_deps(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    dry_run = "--dry-run" in options
    execute = "--yes" in options
    if dry_run == execute or any(value not in {"--dry-run", "--yes"} for value in options):
        return {"exit_code": 2, "stderr": "spider install-deps 必须且只能指定 --dry-run 或 --yes\n"}
    dependencies = [
        "requests>=2.25.0",
        "beautifulsoup4>=4.9.0",
        "markdownify>=0.9.0",
        "selenium>=4.0.0",
        "parsel>=1.6.0",
    ]
    command = [sys.executable, "-m", "pip", "install", "--user"] + dependencies
    if dry_run:
        return {"stdout": "Spider 依赖安装计划（dry-run）\nCommand: {}\n不会修改 Python 环境\n".format(" ".join(command))}
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"exit_code": 1, "stderr": "依赖安装失败: {}\n".format(exc)}
    return {
        "exit_code": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


@plugin.command(
    name="crawl",
    summary={"zh": "验证抓取目标（不联网）", "en": "Validate crawl target (offline)"},
    usage="gs spider crawl <target> [output_dir]",
    args=[
        {"name": "target", "type": "string", "required": True, "description": {"zh": "用户名或 URL", "en": "Username or URL"}},
        {"name": "output", "type": "path", "description": {"zh": "输出目录", "en": "Output directory"}},
    ],
)
def crawl(ctx):
    result = _classify(_target(ctx))
    if result["kind"] in {"missing", "invalid"}:
        return {"exit_code": 2, "stderr": result.get("message", "目标无效") + "\n"}
    output = ctx.args.get("output") or "./spider_output"
    output_path = Path(output)
    cwd = Path(getattr(ctx, "cwd", None) or Path.cwd()).resolve()
    resolved = (cwd / output_path).resolve() if not output_path.is_absolute() else output_path.resolve()
    try:
        resolved.relative_to(cwd)
    except ValueError:
        return {"exit_code": 2, "stderr": "输出目录不能越出当前工作目录\n"}
    if result["kind"] != "url":
        return {"exit_code": 2, "stderr": "crawl 需要受支持平台的完整 URL\n"}
    try:
        resolved.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {"exit_code": 1, "stderr": "创建输出目录失败: {}\n".format(exc)}
    request = urllib.request.Request(
        result["target"],
        headers={"User-Agent": "Global-Scripts/6.0 (+https://github.com/i-rtfsc/global_scripts)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            content_type = response.headers.get("Content-Type", "")
            raw = response.read(5 * 1024 * 1024 + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return {"exit_code": 1, "stderr": "抓取失败: {}\n".format(exc)}
    if len(raw) > 5 * 1024 * 1024:
        return {"exit_code": 1, "stderr": "响应超过 5 MiB 限制\n"}
    charset = "utf-8"
    match = re.search(r"charset=([A-Za-z0-9._-]+)", content_type, re.I)
    if match:
        charset = match.group(1)
    text = raw.decode(charset, errors="replace")
    slug = result["platform"] + "-" + sha256(result["target"].encode()).hexdigest()[:12]
    html_file = resolved / (slug + ".html")
    text_file = resolved / (slug + ".txt")
    html_file.write_text(text, encoding="utf-8")
    cleaned = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", text)
    cleaned = re.sub(r"(?s)<[^>]+>", "\n", cleaned)
    cleaned = html.unescape(cleaned)
    cleaned = "\n".join(line.strip() for line in cleaned.splitlines() if line.strip())
    text_file.write_text(cleaned + ("\n" if cleaned else ""), encoding="utf-8")
    return {"stdout": "抓取完成\n平台: {}\nURL: {}\nHTML: {}\nText: {}\nBytes: {}\n".format(result["label"], result["target"], html_file, text_file, len(raw))}


if __name__ == "__main__":
    raise SystemExit(plugin.run())
