#!/usr/bin/env python3
"""Per-plugin health audit: manifest, metadata, groups, and a read-only smoke run.

Complements ``scripts/verify_gs.sh`` (the acceptance gate): that one checks
contracts and shell integration end to end, this one walks every plugin and
reports the health of the *plugin surface* — one row per plugin, with the
problems it found. Exit code is non-zero when anything needs attention.

    python3 scripts/audit_plugins.py [--json]

The smoke command per plugin is deliberately read-only and needs no device or
network peer. Private plugins (sgm/flyme) live outside this repository
altogether, so they never appear here.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[1]

# 只读、无需设备/网络对端/私有资产的代表命令
SMOKE: Dict[str, List[str]] = {
    "alias": ["alias", "sources", "bash"],
    "android": ["android", "doctor"],
    "devenv": ["devenv", "validate"],
    "dotfiles": ["dotfiles", "status", "zsh"],
    "grep": ["grep", "python", "def _search"],
    "identity": ["identity", "ssh", "status"],
    "multirepo": ["multirepo", "list"],
    "navigator": ["navigator", "list"],
    "spider": ["spider", "classify", "https://www.jianshu.com/p/verify"],
    "sync": ["sync", "status"],
    "system": ["system", "proxy", "status"],
    "vps": ["vps", "status"],
    "vscode": ["vscode", "paths"],
}


def plugin_command_names(manifest: dict, describe: Optional[dict]) -> List[dict]:
    """Command list for a plugin — inline (T1 / static) or from `describe`."""
    if describe is not None:
        return describe.get("commands") or []
    return manifest.get("commands") or []


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true", help="机器可读输出")
    parser.add_argument(
        "--bin",
        default=str(ROOT / "rust" / "target" / "debug" / "gs"),
        help="被测的 gs 二进制",
    )
    args = parser.parse_args()

    binary = Path(args.bin)
    if not binary.is_file():
        print("找不到 gs 二进制:{}".format(binary), file=sys.stderr)
        return 2

    cache = tempfile.mkdtemp(prefix="gs-plugin-audit-")
    env = dict(os.environ, GS_ROOT=str(ROOT), GS_CACHE_DIR=cache, GS_COLOR="0")

    def run(argv: List[str]) -> Tuple[subprocess.CompletedProcess, float]:
        started = time.perf_counter()
        proc = subprocess.run([str(binary), *argv], env=env, capture_output=True, text=True)
        return proc, (time.perf_counter() - started) * 1000

    rows: List[dict] = []
    problems: List[str] = []
    versions = set()

    for manifest_path in sorted((ROOT / "plugins").glob("*/plugin.toml")):
        name = manifest_path.parent.name
        manifest = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
        versions.add(manifest.get("version", ""))

        info, _ = run(["plugin", "info", name])
        described = Path(cache) / "describe" / (name + ".json")
        describe = None
        if described.is_file():
            describe = json.loads(described.read_text(encoding="utf-8"))["result"]
        commands = plugin_command_names(manifest, describe)

        missing_summary = [c["name"] for c in commands if not c.get("summary")]
        missing_usage = [c["name"] for c in commands if not c.get("usage")]
        prefixes = {c["name"].split(".")[0] for c in commands if "." in c["name"]}
        undeclared = sorted(prefixes - set(manifest.get("groups") or {}))

        smoke_args = SMOKE.get(name)
        smoke: Optional[str] = None
        cold = warm = None
        if smoke_args:
            first, cold = run(smoke_args)
            _, warm = run(smoke_args)
            smoke = "ok" if first.returncode == 0 else "exit={}".format(first.returncode)
            if first.returncode != 0:
                detail = (first.stderr or first.stdout).strip().splitlines()
                problems.append(
                    "{}: 冒烟命令 `{}` 退出 {} — {}".format(
                        name, " ".join(smoke_args), first.returncode, detail[0] if detail else ""
                    )
                )

        rows.append(
            {
                "plugin": name,
                "commands": len(commands),
                "info_ok": info.returncode == 0,
                "missing_summary": missing_summary,
                "missing_usage": missing_usage,
                "undeclared_groups": undeclared,
                "smoke": smoke,
                "cold_ms": cold,
                "warm_ms": warm,
            }
        )
        if info.returncode != 0:
            problems.append("{}: plugin info 退出 {}".format(name, info.returncode))
        if missing_summary:
            problems.append("{}: {} 条命令缺 summary".format(name, len(missing_summary)))
        if missing_usage:
            problems.append("{}: {} 条命令缺 usage".format(name, len(missing_usage)))
        if undeclared:
            problems.append(
                "{}: 命令前缀没有 [groups] 声明 — {}".format(name, ", ".join(undeclared))
            )
        if manifest.get("name") != name:
            problems.append(
                "{}: manifest 里的 name 是 {!r},与目录名不一致".format(name, manifest.get("name"))
            )

    if len(versions) > 1:
        problems.append("插件版本不一致:{}".format(", ".join(sorted(versions))))

    if args.json:
        print(json.dumps({"plugins": rows, "problems": problems}, ensure_ascii=False, indent=2))
    else:
        print("插件体检:{} 个\n".format(len(rows)))
        print(
            "{:<10} {:>4} {:>5} {:>5} {:>5} {:>5} {:>8} {:>8}".format(
                "插件", "命令", "info", "描述", "用法", "冒烟", "冷ms", "热ms"
            )
        )
        print("-" * 62)
        for row in rows:
            print(
                "{:<10} {:>4} {:>5} {:>5} {:>5} {:>5} {:>8} {:>8}".format(
                    row["plugin"],
                    row["commands"],
                    "ok" if row["info_ok"] else "FAIL",
                    "ok" if not row["missing_summary"] else str(len(row["missing_summary"])),
                    "ok" if not row["missing_usage"] else str(len(row["missing_usage"])),
                    row["smoke"] or "—",
                    "{:.0f}".format(row["cold_ms"]) if row["cold_ms"] is not None else "—",
                    "{:.0f}".format(row["warm_ms"]) if row["warm_ms"] is not None else "—",
                )
            )
        print()
        if problems:
            print("问题({} 条):".format(len(problems)))
            for line in problems:
                print("  -", line)
        else:
            print("没有问题:全部插件的清单、元数据、分组与冒烟命令都通过。")

    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
