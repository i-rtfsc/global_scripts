#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Gerrit 插件 (Python)

移植自 tmp/global_scripts-v2/bin/gs_gerrit：
- 支持推送到 Gerrit 的 refs/for 或 refs/drafts
- 支持指定分支、评审人、是否为草稿
- 改进：支持通过 --remote 指定远端；默认优先使用 origin 的 push URL
"""

from __future__ import annotations

import argparse
import os
import shlex
import subprocess
from typing import List, Tuple

from gscripts.core.config_manager import CommandResult
from gscripts.plugins.decorators import plugin_function


def _run(cmd: List[str] | str, cwd: str | None = None) -> Tuple[int, str, str]:
    """Run a shell command and return (rc, stdout, stderr)."""
    try:
        if isinstance(cmd, str):
            proc = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
        else:
            proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except Exception as e:
        return 1, "", str(e)


def _ensure_git_repo(cwd: str | None = None) -> Tuple[bool, str]:
    rc, out, err = _run(["git", "rev-parse", "--is-inside-work-tree"], cwd=cwd)
    if rc != 0 or out.strip() != "true":
        return False, (err.strip() or "Not a git repository (or any of the parent directories)")
    return True, ""


def _check_git_identity(cwd: str | None = None) -> Tuple[bool, str]:
    rc, name, _ = _run(["git", "config", "--get", "user.name"], cwd=cwd)
    if rc != 0 or not name.strip():
        return False, 'No git user.name, set it via: git config --global user.name "Your Name"'
    rc, email, _ = _run(["git", "config", "--get", "user.email"], cwd=cwd)
    if rc != 0 or not email.strip():
        return False, 'No git user.email, set it via: git config --global user.email you@example.com'
    return True, ""


def _select_remote(preferred: str | None = None, cwd: str | None = None) -> Tuple[bool, str, str]:
    """Return (ok, remote_url, err). Prefer push URL of the named remote or origin."""
    rc, out, err = _run(["git", "remote", "-v"], cwd=cwd)
    if rc != 0:
        return False, "", f"git remote -v failed: {err.strip()}"
    lines = [l for l in out.splitlines() if "(push)" in l]
    if not lines:
        return False, "", "No push remote configured. Use: git remote add origin <url>"

    # Parse: <name>\t<url> (push)
    entries: List[Tuple[str, str]] = []
    for l in lines:
        parts = l.split()
        if len(parts) >= 3:
            entries.append((parts[0], parts[1]))

    def find_by_name(name: str) -> str | None:
        for n, url in entries:
            if n == name:
                return url
        return None

    # Priority: preferred -> origin -> first push url
    if preferred:
        url = find_by_name(preferred)
        if url:
            return True, url, ""
        # If preferred not found, fall back but note it
    url = find_by_name("origin") or (entries[0][1] if entries else None)
    if not url:
        return False, "", "No valid remote found"
    return True, url, ""


def _get_current_branch(cwd: str | None = None) -> Tuple[bool, str, str]:
    """Get the current Git branch name. Returns (ok, branch_name, error)."""
    rc, out, err = _run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=cwd)
    if rc != 0:
        return False, "", f"Failed to get current branch: {err.strip()}"
    branch = out.strip()
    if not branch:
        return False, "", "Unable to determine current branch"
    return True, branch, ""


def _build_refspec(branch: str, reviewers: List[str], drafts: bool) -> str:
    base = f"refs/drafts/{branch}" if drafts else f"refs/for/{branch}"
    if reviewers:
        opts = ",".join([f"r={r.strip()}" for r in reviewers if r.strip()])
        if opts:
            return f"{base}%{opts}"
    return base


@plugin_function(
    name="push",
    description={
        "zh": "推送当前 HEAD 到 Gerrit，支持指定分支/评审人/草稿",
        "en": "Push current HEAD to Gerrit with branch/reviewer/draft options"
    },
    examples=[
        "gs gerrit push",
        "gs gerrit push -b master",
        "gs gerrit push -b main -r a@ex.com,b@ex.com",
        "gs gerrit push -d --remote origin"
    ]
)
def push(args: List[str] | None = None) -> CommandResult:
    """Push to Gerrit similar to legacy gs_gerrit."""
    args = args or []
    parser = argparse.ArgumentParser(prog="gs gerrit push", add_help=False)
    parser.add_argument("-b", "--branch", default=None)
    parser.add_argument("-r", "--reviewer", default="", help="Comma-separated reviewer emails")
    parser.add_argument("-d", "--drafts", action="store_true", help="Push as drafts (refs/drafts)")
    parser.add_argument("--remote", default=None, help="Remote name to use, e.g., origin")
    parser.add_argument("-h", "--help", action="store_true")

    try:
        ns, unknown = parser.parse_known_args(args)
    except SystemExit:
        return CommandResult(False, error="Invalid arguments", exit_code=2)

    if ns.help:
        help_text = (
            "Usage: gs gerrit push [-b BRANCH] [-r EMAILS] [-d] [--remote REMOTE]\n"
            "  -b/--branch   Target branch (default: current branch)\n"
            "  -r/--reviewer Comma-separated reviewer emails\n"
            "  -d/--drafts   Push to refs/drafts (draft change)\n"
            "  --remote      Remote name (default: prefer origin push URL)\n"
        )
        return CommandResult(True, output=help_text)

    # Get current working directory (where user executed the command)
    # Use PWD environment variable to get the actual terminal working directory
    cwd = os.environ.get('PWD')
    if not cwd:
        # Fallback to os.getcwd() if PWD is not available
        cwd = os.getcwd()

    ok, msg = _ensure_git_repo(cwd=cwd)
    if not ok:
        return CommandResult(False, error=msg, exit_code=1)

    ok, msg = _check_git_identity(cwd=cwd)
    if not ok:
        return CommandResult(False, error=msg, exit_code=1)

    ok, remote_url, err = _select_remote(ns.remote, cwd=cwd)
    if not ok:
        return CommandResult(False, error=err, exit_code=1)

    # If branch not specified, use current branch
    branch = ns.branch
    if not branch:
        ok, branch, err = _get_current_branch(cwd=cwd)
        if not ok:
            return CommandResult(False, error=err, exit_code=1)

    reviewers = [s.strip() for s in ns.reviewer.split(",") if s.strip()] if ns.reviewer else []
    refspec = _build_refspec(branch.strip(), reviewers, ns.drafts)

    # Compose command: git push <remote> HEAD:<refspec>
    # When remote_url is a URL, it can be used directly as remote target.
    cmd_list = ["git", "push", remote_url, f"HEAD:{refspec}"]

    rc, out, err = _run(cmd_list, cwd=cwd)
    success = (rc == 0)
    output_text = out.strip()
    error_text = err.strip()

    # Provide a concise echo of the executed command for transparency
    executed = "$ " + " ".join(shlex.quote(x) for x in cmd_list)
    if success:
        combined_out = executed + ("\n" + output_text if output_text else "")
        return CommandResult(True, output=combined_out, stdout=combined_out, exit_code=0)
    else:
        combined_err = executed + ("\n" + error_text if error_text else "")
        return CommandResult(False, error=combined_err, stderr=combined_err, exit_code=rc)
