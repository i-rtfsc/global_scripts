#!/usr/bin/env python3
"""Compare the live GS 5.2 command inventory with GS6 protocol commands."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

try:
    import tomllib
except ImportError:  # Python 3.8-3.10 under the repository's uv environment.
    import tomli as tomllib


ROOT = Path(__file__).resolve().parents[1]


def canonical(command: str) -> str:
    return " ".join(command.replace(".", " ").replace("-", "_").split())


async def load_legacy() -> Dict[str, Set[str]]:
    from gscripts.cli.main import GlobalScriptsCLI

    cli = GlobalScriptsCLI()
    await cli.plugin_service.load_all_plugins(only_enabled=False)
    result = {}
    for name, plugin in cli.plugin_service.get_loaded_plugins().items():
        if name == "menubar":
            continue
        result[name] = {canonical(command) for command in (plugin.get("functions") or {})}
    return result


def load_gs6(binary: Path) -> Dict[str, Set[str]]:
    result = {}
    with tempfile.TemporaryDirectory(prefix="gs6-parity-") as cache:
        env = os.environ.copy()
        env.update({"GS_ROOT": str(ROOT), "GS_CACHE_DIR": cache, "GS_COLOR": "0"})
        env.pop("GS_INCLUDE_EXAMPLES", None)
        for manifest_path in sorted((ROOT / "plugins").glob("*/plugin.toml")):
            manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
            name = manifest["name"]
            subprocess.run(
                [str(binary), "plugin", "info", name],
                cwd=ROOT,
                env=env,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            commands = manifest.get("commands") or []
            cached = Path(cache) / "describe" / (name + ".json")
            if cached.is_file():
                commands = json.loads(cached.read_text(encoding="utf-8"))["result"]["commands"]
            result[name] = {
                canonical(command["name"])
                for command in commands
                if not command.get("hidden")
            }
    return result


def replacement(plugin: str, command: str, available: Set[str]) -> str:
    words = command.split()
    if plugin == "dotfiles":
        if command == "help" and "list" in available:
            return "list"
        if len(words) == 2 and words[0] in {"vim", "nvim", "tmux", "zsh", "fish", "git"}:
            action = words[1]
            if action in {"install", "uninstall"} and {"plan", "apply_plan"} <= available:
                return "plan + apply-plan"
            if action in {"backup", "restore", "status"} and action in available:
                return action
    if plugin == "spider":
        aliases = {
            "check_deps": "check_deps",
            "install_deps": "install_deps",
            "list_subplugins": "list",
            "info": "info",
        }
        if command in aliases and aliases[command] in available:
            return aliases[command].replace("_", "-")
        if len(words) == 2 and words[0] in {"cnblogs", "csdn", "jianshu"}:
            if words[1] in {"crawl", "info"} and words[1] in available:
                return words[1]
    if plugin == "grep" and command == "help":
        return "plugin overview"
    if plugin == "alias" and len(words) == 2 and words[1].endswith("aliases"):
        if {"sources", "show"} <= available:
            return "sources + show"
    return ""


def compare(
    legacy: Dict[str, Set[str]], gs6: Dict[str, Set[str]]
) -> Tuple[List[dict], List[Tuple[str, str]]]:
    summaries = []
    missing = []
    for plugin in sorted(legacy):
        old = legacy[plugin]
        new = gs6.get(plugin, set())
        direct = old & new
        mapped = {}
        for command in sorted(old - direct):
            target = replacement(plugin, command, new)
            if target:
                mapped[command] = target
            else:
                missing.append((plugin, command))
        summaries.append(
            {
                "plugin": plugin,
                "gs52": len(old),
                "gs6": len(new),
                "direct": len(direct),
                "mapped": len(mapped),
                "missing": len(old) - len(direct) - len(mapped),
                "mappings": mapped,
            }
        )
    return summaries, missing


def markdown(summaries: Iterable[dict], missing: List[Tuple[str, str]]) -> str:
    lines = [
        "# GS6 Command Parity Audit",
        "",
        "Generated from the live GS 5.2 loader and GS6 runtime `describe` results.",
        "`mapped` means the behavior is intentionally consolidated under a new GS6 command.",
        "",
        "| Plugin | GS5.2 | GS6 | Direct | Mapped | Missing |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for item in summaries:
        lines.append(
            "| {plugin} | {gs52} | {gs6} | {direct} | {mapped} | {missing} |".format(**item)
        )
    lines.extend(["", "## Missing Commands", ""])
    if missing:
        lines.extend("- `{} {}`".format(plugin, command.replace("_", "-")) for plugin, command in missing)
    else:
        lines.append("None.")
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--gs6-bin", type=Path, default=ROOT / "rust" / "target" / "debug" / "gs")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    legacy = asyncio.run(load_legacy())
    gs6 = load_gs6(args.gs6_bin.resolve())
    summaries, missing = compare(legacy, gs6)
    if args.json:
        print(json.dumps({"plugins": summaries, "missing": missing}, ensure_ascii=False, indent=2))
    else:
        print(markdown(summaries, missing), end="")
    return 1 if missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
