#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Safely synchronize Git worktree changes to a parallel directory tree."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

_SDK = Path(__file__).resolve().parents[2] / "sdk" / "python"
if _SDK.is_dir():
    sys.path.insert(0, str(_SDK))

from gs_plugin import Plugin  # noqa: E402


plugin = Plugin(name="sync")


def _env(ctx, name, default):
    return str(ctx.env.get(name) or default)


def _settings(ctx):
    return {
        "source": Path(_env(ctx, "GS_SYNC_SOURCE_BASE", "/home/solo/code")).expanduser().resolve(),
        "target": Path(_env(ctx, "GS_SYNC_TARGET_BASE", "/home/solo/mac")).expanduser().resolve(),
        "host": _env(ctx, "GS_SYNC_VPS_HOST", "178.128.215.72"),
        "user": _env(ctx, "GS_SYNC_VPS_USER", "root"),
    }


def _git(ctx, *args):
    return subprocess.run(
        ["git", *args], cwd=ctx.cwd or os.getcwd(), capture_output=True, text=True, timeout=20
    )


def _git_root(ctx):
    result = _git(ctx, "rev-parse", "--show-toplevel")
    return Path(result.stdout.strip()).resolve() if result.returncode == 0 else None


def _changes(ctx, include_untracked):
    result = _git(
        ctx,
        "-c",
        "core.quotepath=false",
        "status",
        "--porcelain=v1",
        "--untracked-files={}".format("all" if include_untracked else "no"),
    )
    if result.returncode != 0:
        return None, result.stderr or "git status 失败"
    changes = []
    for line in result.stdout.splitlines():
        if len(line) < 4:
            continue
        status = line[:2]
        path = line[3:]
        old_path = None
        if "R" in status and " -> " in path:
            old_path, path = path.split(" -> ", 1)
        changes.append({"status": status, "path": path, "old_path": old_path})
    return changes, None


def _relative_root(root, source):
    try:
        return root.relative_to(source)
    except ValueError:
        return None


def _target_path(target_root, repo_relative, path):
    candidate = (target_root / repo_relative / path).resolve(strict=False)
    base = target_root.resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        return None
    return candidate


def _mode(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    dry_run = "--dry-run" in options
    execute = "--yes" in options
    if dry_run == execute or any(value not in {"--dry-run", "--yes"} for value in options):
        return None
    return "dry-run" if dry_run else "execute"


def _label(change):
    status = change["status"]
    if "R" in status:
        return "rename"
    if "D" in status:
        return "delete"
    if status == "??":
        return "untracked"
    if "A" in status:
        return "add"
    if "M" in status:
        return "modify"
    return "other"


def _sync(ctx, include_untracked):
    mode = _mode(ctx)
    if mode is None:
        return {"exit_code": 2, "stderr": "sync 写操作必须且只能指定 --dry-run 或 --yes\n"}
    settings = _settings(ctx)
    root = _git_root(ctx)
    if root is None:
        return {"exit_code": 1, "stderr": "当前目录不在 Git 仓库中\n"}
    repo_relative = _relative_root(root, settings["source"])
    if repo_relative is None:
        return {"exit_code": 1, "stderr": "Git 仓库不在同步源目录内: {}\n".format(settings["source"])}
    changes, error = _changes(ctx, include_untracked)
    if error:
        return {"exit_code": 1, "stderr": error + "\n"}
    lines = [
        "同步计划 ({})".format(mode),
        "Git root: {}".format(root),
        "Target: {}".format(settings["target"] / repo_relative),
    ]
    failures = []
    for change in changes:
        source = root / change["path"]
        target = _target_path(settings["target"], repo_relative, change["path"])
        if target is None:
            failures.append("目标路径越界: {}".format(change["path"]))
            continue
        label = _label(change)
        lines.append("  {} {}".format(label, change["path"]))
        if mode == "dry-run":
            continue
        try:
            if change["old_path"]:
                old_target = _target_path(settings["target"], repo_relative, change["old_path"])
                if old_target and old_target.is_file():
                    old_target.unlink()
            if label == "delete":
                if target.is_file() or target.is_symlink():
                    target.unlink()
                elif target.is_dir():
                    shutil.rmtree(target)
            elif source.is_file():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
            elif source.is_dir():
                shutil.copytree(source, target, dirs_exist_ok=True)
            else:
                failures.append("源路径不存在: {}".format(source))
        except OSError as exc:
            failures.append("{}: {}".format(change["path"], exc))
    if not changes:
        lines.append("工作区干净，没有需要同步的文件")
    if mode == "dry-run":
        lines.append("不会复制或删除文件")
    if failures:
        return {"exit_code": 1, "stdout": "\n".join(lines) + "\n", "stderr": "\n".join(failures) + "\n"}
    return {"stdout": "\n".join(lines) + "\n"}


@plugin.command(name="help", summary={"zh": "显示同步命令", "en": "Show sync commands"}, usage="gs sync help")
def help_command(ctx):
    settings = _settings(ctx)
    return {"stdout": "Sync commands: check, status, modified, all, scp, help\nSource: {}\nTarget: {}\n".format(settings["source"], settings["target"])}


@plugin.command(name="check", summary={"zh": "检查同步环境", "en": "Check sync environment"}, usage="gs sync check")
def check(ctx):
    settings = _settings(ctx)
    root = _git_root(ctx)
    checks = [
        (root is not None, "Git 仓库", str(root or "未发现")),
        (settings["source"].is_dir(), "源目录", str(settings["source"])),
        (settings["target"].is_dir(), "目标目录", str(settings["target"])),
        (os.access(settings["target"], os.W_OK), "目标可写", str(settings["target"])),
    ]
    lines = ["同步环境检查"]
    lines.extend("  [{}] {}: {}".format("OK" if ok else "--", name, detail) for ok, name, detail in checks)
    return {"exit_code": 0 if all(ok for ok, _, _ in checks) else 1, "stdout": "\n".join(lines) + "\n"}


@plugin.command(name="status", summary={"zh": "显示待同步文件", "en": "Show files pending synchronization"}, usage="gs sync status")
def status(ctx):
    root = _git_root(ctx)
    if root is None:
        return {"exit_code": 1, "stderr": "当前目录不在 Git 仓库中\n"}
    changes, error = _changes(ctx, True)
    if error:
        return {"exit_code": 1, "stderr": error + "\n"}
    counts = {}
    lines = ["Git root: {}".format(root)]
    for change in changes:
        label = _label(change)
        counts[label] = counts.get(label, 0) + 1
        lines.append("  {} {}".format(label, change["path"]))
    lines.append("Total: {}".format(len(changes)))
    for label in sorted(counts):
        lines.append("  {}: {}".format(label, counts[label]))
    return {"stdout": "\n".join(lines) + "\n"}


_WRITE_ARGS = [{"name": "options", "type": "string", "variadic": True}]


@plugin.command(name="modified", summary={"zh": "同步已跟踪的修改", "en": "Sync tracked changes"}, usage="gs sync modified <--dry-run|--yes>", args=_WRITE_ARGS)
def modified(ctx):
    return _sync(ctx, False)


@plugin.command(name="all", summary={"zh": "同步全部未提交文件", "en": "Sync all uncommitted files"}, usage="gs sync all <--dry-run|--yes>", args=_WRITE_ARGS)
def all_changes(ctx):
    return _sync(ctx, True)


@plugin.command(name="scp", summary={"zh": "生成 SCP 同步命令", "en": "Generate SCP synchronization commands"}, usage="gs sync scp")
def scp(ctx):
    settings = _settings(ctx)
    root = _git_root(ctx)
    if root is None:
        return {"exit_code": 1, "stderr": "当前目录不在 Git 仓库中\n"}
    changes, error = _changes(ctx, True)
    if error:
        return {"exit_code": 1, "stderr": error + "\n"}
    remote = "{}@{}".format(settings["user"], settings["host"])
    lines = ["#!/bin/sh", "# 在目标机器的对应仓库目录执行"]
    for change in changes:
        path = change["path"]
        if change["old_path"]:
            lines.append("rm -f -- {}".format(shlex.quote(change["old_path"])))
        if _label(change) == "delete":
            lines.append("rm -f -- {}".format(shlex.quote(path)))
            continue
        source = root / path
        if source.is_file():
            parent = str(Path(path).parent)
            if parent != ".":
                lines.append("mkdir -p -- {}".format(shlex.quote(parent)))
            remote_source = "{}:{}".format(remote, shlex.quote(str(source)))
            lines.append("scp {} {}".format(remote_source, shlex.quote(path)))
    return {"stdout": "\n".join(lines) + "\n"}


if __name__ == "__main__":
    raise SystemExit(plugin.run())
