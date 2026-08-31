#!/usr/bin/env python3
"""GS 6.0 grep preview: recursive, shell-free code search."""

from __future__ import annotations

import fnmatch
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SDK = ROOT / "sdk" / "python"
if SDK.is_dir():
    sys.path.insert(0, str(SDK))

from gs_plugin import Plugin  # noqa: E402

plugin = Plugin(name="grep")

EXTENSIONS = {
    "c": {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hxx"},
    "java": {".java"},
    "kotlin": {".kt", ".kts"},
    "go": {".go"},
    "rust": {".rs"},
    "python": {".py"},
    "js": {".js", ".jsx"},
    "ts": {".ts", ".tsx"},
    "gradle": {".gradle", ".gradle.kts"},
    "xml": {".xml"},
    "json": {".json"},
    "yaml": {".yml", ".yaml"},
    "sh": {".sh", ".bash", ".zsh", ".fish"},
    "rc": {".rc", ".rc.user", ".rc.local"},
}
ALL_EXTENSIONS = set().union(*EXTENSIONS.values())
EXCLUDED_DIRS = {".git", ".repo", ".vscode", "node_modules", "out", "target", "build", "dist", "__pycache__", ".venv"}


def _args(ctx):
    raw = ctx.args.get("options") or []
    if isinstance(raw, str):
        raw = [raw]
    return [str(value) for value in raw]


def _files(root: Path, kind: str):
    extensions = ALL_EXTENSIONS if kind == "all" else EXTENSIONS.get(kind, set())
    for directory, dirs, names in os.walk(root):
        dirs[:] = sorted(name for name in dirs if name not in EXCLUDED_DIRS and not name.startswith("."))
        for name in sorted(names):
            path = Path(directory) / name
            if kind == "manifest" and name != "AndroidManifest.xml":
                continue
            if kind == "make" and not (
                name == "Makefile"
                or name.startswith("Makefile.")
                or path.suffix.lower() in {".mk", ".mak", ".bp", ".make"}
            ):
                continue
            if kind == "res" and not (path.suffix.lower() == ".xml" and path.parent.name == "res"):
                continue
            if path.suffix.lower() in extensions:
                yield path


def _parse_options(options):
    flags = {"ignore_case": False, "line_number": True, "files_only": False, "count": False, "fixed": False, "extended": False}
    before = after = 0
    i = 0
    while i < len(options):
        value = options[i]
        if value in {"-i", "--ignore-case"}:
            flags["ignore_case"] = True
        elif value in {"-n", "--line-number"}:
            flags["line_number"] = True
        elif value in {"-l", "--files-with-matches"}:
            flags["files_only"] = True
        elif value in {"-c", "--count"}:
            flags["count"] = True
        elif value in {"-F", "--fixed-strings"}:
            flags["fixed"] = True
        elif value in {"-E", "--extended-regexp"}:
            flags["extended"] = True
        elif value in {"--color=auto", "--color=always", "--color=never"}:
            pass
        elif value in {"-A", "--after-context", "-B", "--before-context"}:
            if i + 1 >= len(options) or not options[i + 1].isdigit():
                return None, "选项 {} 需要数字参数".format(value)
            if value in {"-A", "--after-context"}:
                after = int(options[i + 1])
            else:
                before = int(options[i + 1])
            i += 1
        elif value.startswith("-"):
            return None, "不支持的 grep 选项: {}".format(value)
        else:
            return None, "搜索选项必须放在 pattern 之后: {}".format(value)
        i += 1
    flags["before"] = before
    flags["after"] = after
    return flags, None


def _search(ctx, kind: str):
    pattern = str(ctx.args.get("pattern") or "")
    if not pattern:
        return {"exit_code": 2, "stderr": "缺少搜索 pattern\n"}
    flags, error = _parse_options(_args(ctx))
    if error:
        return {"exit_code": 2, "stderr": error + "\n"}
    root = Path(ctx.cwd or os.getcwd()).expanduser()
    if not root.is_dir():
        return {"exit_code": 2, "stderr": "搜索目录不存在: {}\n".format(root)}
    try:
        needle = re.escape(pattern) if flags["fixed"] else pattern
        regex = re.compile(needle, re.IGNORECASE if flags["ignore_case"] else 0)
    except re.error as exc:
        return {"exit_code": 2, "stderr": "无效正则表达式: {}\n".format(exc)}

    output = []
    matched_files = 0
    for path in _files(root, kind):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        hits = [index for index, line in enumerate(lines) if regex.search(line)]
        if not hits:
            continue
        matched_files += 1
        relative = str(path.relative_to(root))
        if flags["files_only"]:
            output.append(relative)
            continue
        if flags["count"]:
            output.append("{}:{}".format(relative, len(hits)))
            continue
        selected = set()
        for index in hits:
            selected.update(range(max(0, index - flags["before"]), min(len(lines), index + flags["after"] + 1)))
        for index in sorted(selected):
            prefix = "{}:{}:".format(relative, index + 1) if flags["line_number"] else relative + ":"
            output.append(prefix + lines[index])
    if not output:
        return {"exit_code": 1, "stdout": ""}
    return {"exit_code": 0, "stdout": "\n".join(output) + "\n"}


COMMANDS = {
    "all": "all source files", "c": "C/C++ files", "java": "Java files", "kotlin": "Kotlin files",
    "go": "Go files", "rust": "Rust files", "python": "Python files", "js": "JavaScript files",
    "ts": "TypeScript files", "gradle": "Gradle files", "make": "Makefiles and build files",
    "xml": "XML files", "json": "JSON files", "yaml": "YAML files", "sh": "Shell files",
    "res": "Android resource XML files", "manifest": "AndroidManifest.xml files", "rc": "RC config files",
}

for _name, _summary in COMMANDS.items():
    plugin.command(
        name=_name,
        summary={"zh": "在{}中搜索".format(_summary), "en": "Search {}".format(_summary)},
        usage="gs grep {} <pattern> [grep_options]".format(_name),
        args=[
            {"name": "pattern", "type": "string", "required": True, "description": {"zh": "搜索模式", "en": "Search pattern"}},
            {"name": "options", "type": "string", "variadic": True, "description": {"zh": "grep 选项", "en": "grep options"}},
        ],
    )(_search.__get__(None, type(None)))


# The SDK decorator above needs a distinct callable per command; replace the
# registrations with closures while keeping the manifest generated at runtime.
for _name in list(COMMANDS):
    entry = plugin._commands[_name]
    entry["handler"] = (lambda kind: (lambda ctx: _search(ctx, kind)))(_name)


if __name__ == "__main__":
    raise SystemExit(plugin.run())
