#!/usr/bin/env python3
"""Multi-repository inspection, planning, and explicitly confirmed writes."""
from __future__ import annotations

import os
import json
import hashlib
from datetime import datetime, timezone
import subprocess
import shutil
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional

ROOT = Path(__file__).resolve().parents[2]
SDK = ROOT / "sdk" / "python"
if SDK.is_dir():
    sys.path.insert(0, str(SDK))
from gs_plugin import Plugin  # noqa: E402

plugin = Plugin(name="multirepo")
BUILTIN = ROOT / "plugins" / "multirepo" / "manifests"


def _safe_project_path(value: str) -> str:
    value = (value or "").strip().replace("\\", "/")
    path = Path(value)
    if not value or path.is_absolute() or ".." in path.parts:
        raise ValueError("不安全的 project path: {}".format(value or "<empty>"))
    normalized = path.as_posix().lstrip("./")
    if not normalized or normalized == ".":
        raise ValueError("不安全的 project path: {}".format(value or "<empty>"))
    return normalized


def _cwd(ctx) -> Path:
    return Path(ctx.cwd or os.getcwd()).expanduser()


def _manifest_path(ctx, requested: str = "") -> Optional[Path]:
    root = _cwd(ctx)
    if requested:
        candidate = Path(requested).expanduser()
        if candidate.is_file():
            return candidate.resolve()
        for candidate in (root / requested, root / (requested + ".xml"), BUILTIN / requested, BUILTIN / (requested + ".xml")):
            if candidate.is_file():
                return candidate.resolve()
    for candidate in (root / "default.xml", *sorted(root.glob("*.xml"))):
        if candidate.is_file():
            return candidate.resolve()
    builtin = BUILTIN / "mini-aosp.xml"
    return builtin.resolve() if builtin.is_file() else None


def _parse_manifest(path: Path):
    tree = ET.parse(path)
    root = tree.getroot()
    remotes = {e.attrib.get("name"): e.attrib.get("fetch") for e in root.findall("remote")}
    default = root.find("default")
    default_remote = default.attrib.get("remote") if default is not None else None
    default_revision = default.attrib.get("revision") if default is not None else None
    projects = []
    for elem in root.findall("project"):
        name = elem.attrib.get("name")
        if not name:
            continue
        remote = elem.attrib.get("remote", default_remote)
        fetch = remotes.get(remote, "")
        project_path = _safe_project_path(elem.attrib.get("path", name))
        projects.append({
            "name": name,
            "path": project_path,
            "remote": remote or "",
            "revision": elem.attrib.get("revision", default_revision or ""),
            "url": (fetch.rstrip("/") + "/" + name) if fetch else "",
        })
    return {
        "path": str(path),
        "remote_count": len(remotes),
        "default_remote": default_remote or "",
        "default_revision": default_revision or "",
        "projects": projects,
    }


def _plan_fingerprint(plan: dict) -> str:
    projects = plan.get("projects", [])
    identity = "\n".join(
        [plan.get("backend", ""), plan.get("manifest", ""), plan.get("root", "")]
        + [p.get("path", "") + "\t" + p.get("revision", "") + "\t" + p.get("url", "") for p in projects]
    )
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def _git_status(path: Path):
    try:
        result = subprocess.run(["git", "-C", str(path), "status", "--porcelain", "-b"], capture_output=True, text=True, timeout=5)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return {"path": str(path), "state": "git unavailable"}
    if result.returncode != 0:
        return {"path": str(path), "state": "not a git repository"}
    lines = result.stdout.splitlines()
    branch = lines[0][3:] if lines and lines[0].startswith("## ") else (lines[0] if lines else "unknown")
    changes = len(lines[1:])
    return {"path": str(path), "branch": branch, "changes": changes, "state": "clean" if changes == 0 else "modified"}


def _write_mode(options, label):
    options = [str(value) for value in (options or [])]
    dry_run = "--dry-run" in options
    execute = "--yes" in options
    if dry_run == execute:
        return None, "{} 必须且只能指定 --dry-run 或 --yes".format(label)
    return ("dry-run" if dry_run else "execute"), None


def _git_remote(path, preferred=""):
    result = subprocess.run(
        ["git", "-C", str(path), "remote", "get-url", "--push", preferred or "origin"],
        capture_output=True, text=True, timeout=10,
    )
    if result.returncode != 0:
        return None
    return result.stdout.strip()


def _current_branch(path):
    result = subprocess.run(
        ["git", "-C", str(path), "branch", "--show-current"],
        capture_output=True, text=True, timeout=10,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _is_gerrit(url):
    lowered = (url or "").lower()
    if any(host in lowered for host in ("github.com", "gitlab.com", "bitbucket.org")):
        return False
    return any(marker in lowered for marker in ("gerrit", "/a/", "review."))


@plugin.command(name="list", summary={"zh": "列出内置 manifest", "en": "List builtin manifests"}, usage="gs multirepo list")
def list_manifests(ctx):
    del ctx
    names = sorted(p.stem for p in BUILTIN.glob("*.xml") if p.is_file())
    return {"stdout": ("\n".join(names) if names else "没有内置 manifest") + "\n"}


@plugin.command(name="manifest", summary={"zh": "解析 manifest 项目", "en": "Inspect manifest projects"}, usage="gs multirepo manifest [name-or-path]", args=[{"name": "manifest", "type": "string", "description": {"zh": "manifest 名称或路径", "en": "Manifest name or path"}}])
def manifest_info(ctx):
    path = _manifest_path(ctx, str(ctx.args.get("manifest") or ""))
    if path is None:
        return {"exit_code": 2, "stderr": "未找到 manifest\n"}
    try:
        data = _parse_manifest(path)
    except (OSError, ET.ParseError, ValueError) as exc:
        return {"exit_code": 2, "stderr": "manifest 解析失败: {}\n".format(exc)}
    lines = ["Manifest: {}".format(data["path"]), "Remote: {}".format(data["default_remote"]), "Revision: {}".format(data["default_revision"]), "Projects: {}".format(len(data["projects"]))]
    lines.extend("  {} -> {}".format(p["name"], p["path"]) for p in data["projects"][:20])
    return {"stdout": "\n".join(lines) + "\n"}


@plugin.command(name="status", summary={"zh": "查看多仓库状态", "en": "Show multi-repo status"}, usage="gs multirepo status")
def status(ctx):
    root = _cwd(ctx)
    repo_meta = root / ".repo"
    lines = ["MultiRepo 状态", "根目录: {}".format(root)]
    if repo_meta.is_dir():
        projects = list(repo_meta.glob("project.list"))
        lines.append("后端: repo")
        lines.append(".repo: 存在")
        if projects:
            lines.append("项目清单: {}".format(projects[0]))
    else:
        lines.append("后端: git/未初始化")
        git = _git_status(root)
        lines.append("Git: {}".format(git.get("branch", git["state"])))
    return {"stdout": "\n".join(lines) + "\n"}


@plugin.command(name="projects", summary={"zh": "查看各子项目 Git 状态", "en": "Show child project Git status"}, usage="gs multirepo projects [manifest]", args=[{"name": "manifest", "type": "string", "description": {"zh": "manifest 名称或路径", "en": "Manifest name or path"}}])
def projects_status(ctx):
    path = _manifest_path(ctx, str(ctx.args.get("manifest") or ""))
    if path is None:
        return {"exit_code": 2, "stderr": "未找到 manifest\n"}
    try:
        projects = _parse_manifest(path)["projects"]
    except (OSError, ET.ParseError, ValueError) as exc:
        return {"exit_code": 2, "stderr": "manifest 解析失败: {}\n".format(exc)}
    root = _cwd(ctx)
    lines = ["子项目状态", "Manifest: {}".format(path)]
    missing = modified = clean = 0
    for project in projects:
        project_path = root / project["path"]
        if not (project_path / ".git").exists():
            missing += 1
            lines.append("  ❌ {} [{}]".format(project["path"], "missing"))
            continue
        state = _git_status(project_path)
        if state.get("state") == "clean":
            clean += 1
            marker = "✅"
        else:
            modified += 1
            marker = "⚠️"
        lines.append("  {} {} [{}] {}".format(marker, project["path"], state.get("state"), state.get("branch", "")))
    lines.append("汇总: clean={} modified={} missing={}".format(clean, modified, missing))
    return {"stdout": "\n".join(lines) + "\n"}


@plugin.command(name="diff", summary={"zh": "检查 manifest 与工作区差异", "en": "Compare manifest with workspace"}, usage="gs multirepo diff [manifest]", args=[{"name": "manifest", "type": "string", "description": {"zh": "manifest 名称或路径", "en": "Manifest name or path"}}])
def workspace_diff(ctx):
    path = _manifest_path(ctx, str(ctx.args.get("manifest") or ""))
    if path is None:
        return {"exit_code": 2, "stderr": "未找到 manifest\n"}
    try:
        declared = _parse_manifest(path)["projects"]
    except (OSError, ET.ParseError, ValueError) as exc:
        return {"exit_code": 2, "stderr": "manifest 解析失败: {}\n".format(exc)}
    root = _cwd(ctx)
    declared_paths = {project["path"] for project in declared}
    duplicates = len(declared_paths) != len(declared)
    actual = set()
    for child in root.iterdir() if root.is_dir() else []:
        if child.is_dir() and (child / ".git").is_dir():
            actual.add(child.relative_to(root).as_posix())
    missing = sorted(declared_paths - actual)
    extra = sorted(actual - declared_paths)
    lines = ["Manifest/工作区差异", "Manifest: {}".format(path), "声明项目: {}".format(len(declared_paths)), "实际 Git 项目: {}".format(len(actual))]
    lines.append("重复路径: {}".format("是" if duplicates else "否"))
    lines.append("缺失项目: {}".format(", ".join(missing) if missing else "无"))
    lines.append("未登记项目: {}".format(", ".join(extra) if extra else "无"))
    return {"exit_code": 1 if duplicates or missing else 0, "stdout": "\n".join(lines) + "\n"}


@plugin.command(name="init", summary={"zh": "生成多仓库初始化计划", "en": "Plan multi-repo initialization"}, usage="gs multirepo init [manifest] [--backend=git|repo] [--dry-run]", args=[{"name": "manifest", "type": "string", "description": {"zh": "manifest 名称或路径", "en": "Manifest name or path"}}, {"name": "options", "type": "string", "variadic": True, "description": {"zh": "初始化选项", "en": "Initialization options"}}])
def init_plan(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    options = [str(value) for value in options]
    if "--dry-run" not in options:
        return {"exit_code": 2, "stderr": "GS 6.0 当前仅支持 multirepo init --dry-run；不会执行写操作\n"}
    backends = [value for value in options if value.startswith("--backend=")]
    if len(backends) > 1:
        return {"exit_code": 2, "stderr": "只能指定一个 backend\n"}
    backend = "repo" if "--backend=repo" in options else "git"
    formats = [value.split("=", 1)[1] for value in options if value.startswith("--format=")]
    if len(formats) > 1 or (formats and formats[0] != "json"):
        return {"exit_code": 2, "stderr": "仅支持 --format=json\n"}
    check = "--check" in options
    unknown = [value for value in options if value not in {"--dry-run", "--backend=git", "--backend=repo", "--format=json", "--check"}]
    if unknown:
        return {"exit_code": 2, "stderr": "不支持的 init 选项: {}\n".format(" ".join(unknown))}
    path = _manifest_path(ctx, str(ctx.args.get("manifest") or ""))
    if path is None:
        return {"exit_code": 2, "stderr": "未找到 manifest\n"}
    try:
        data = _parse_manifest(path)
    except (OSError, ET.ParseError, ValueError) as exc:
        return {"exit_code": 2, "stderr": "manifest 解析失败: {}\n".format(exc)}
    root = _cwd(ctx)
    if not root.is_dir():
        return {"exit_code": 2, "stderr": "目标目录不存在: {}\n".format(root)}
    lines = ["MultiRepo init 计划（dry-run）", "Backend: {}".format(backend), "Manifest: {}".format(path), "目标目录: {}".format(root)]
    existing = []
    missing = []
    for project in data["projects"]:
        target = root / project["path"]
        if target.exists():
            existing.append((project, target))
        else:
            missing.append((project, target))
    plan_id = _plan_fingerprint({"backend": backend, "manifest": str(path), "root": str(root), "projects": data["projects"]})
    plan = {
        "schema_version": 1,
        "plan_id": plan_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "dry-run",
        "backend": backend,
        "manifest": str(path),
        "root": str(root),
        "existing": [p["path"] for p, _ in existing],
        "missing": [p["path"] for p, _ in missing],
        "projects": data["projects"],
        "actions": [],
        "summary": {
            "project_count": len(data["projects"]),
            "existing_count": len(existing),
            "missing_count": len(missing),
            "network_required": True,
            "writes_required": True,
            "risk": "high" if backend == "repo" or len(missing) > 10 else "medium",
        },
    }
    if backend == "repo":
        plan["actions"] = ["repo init", "repo sync"]
    else:
        plan["actions"] = ["git clone"] * len(missing)
    errors = []
    if not data["projects"]:
        errors.append("manifest 没有 project")
    if backend == "repo" and not data["default_remote"]:
        errors.append("repo backend 缺少 default remote")
    if backend == "repo" and not data["default_revision"]:
        errors.append("repo backend 缺少 default revision")
    if any(not project["url"] for project in data["projects"]):
        errors.append("存在无法解析 remote URL 的 project")
    if len({project["path"] for project in data["projects"]}) != len(data["projects"]):
        errors.append("存在重复 project path")
    plan["check"] = {"ok": not errors, "errors": errors}
    if check and errors:
        return {"exit_code": 1, "stderr": "计划校验失败: {}\n".format("; ".join(errors))}
    if "--format=json" in options:
        return {"stdout": json.dumps(plan, ensure_ascii=False, indent=2) + "\n"}
    lines.append("项目目录: 已存在 {}，将创建 {}".format(len(existing), len(missing)))
    for project, target in existing[:20]:
        lines.append("  冲突/已存在: {} -> {}".format(project["path"], target))
    if backend == "repo":
        lines.append("计划: repo init -u {} -b {}".format(data["default_remote"] or "<remote>", data["default_revision"] or "<revision>"))
        lines.append("计划: 使用 manifest 中的 {} 个 project（不会执行）".format(len(data["projects"])))
        lines.append("计划: repo sync（不会执行）")
    else:
        lines.append("计划: 为 {} 个缺失项目执行 git clone（不会执行）".format(len(missing)))
        for project, target in missing[:20]:
            lines.append("  git clone {} {}".format(project["url"] or "<remote-url>", target))
    lines.append("说明: 当前仅生成计划，不联网、不创建目录、不写入仓库")
    return {"stdout": "\n".join(lines) + "\n"}


@plugin.command(name="plan", summary={"zh": "生成机器可读初始化计划", "en": "Generate machine-readable init plan"}, usage="gs multirepo plan [manifest] [--backend=git|repo]", args=[{"name": "manifest", "type": "string", "description": {"zh": "manifest 名称或路径", "en": "Manifest name or path"}}, {"name": "options", "type": "string", "variadic": True, "description": {"zh": "计划选项", "en": "Plan options"}}])
def plan_command(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    ctx.args["options"] = list(options) + ["--dry-run", "--format=json", "--check"]
    return init_plan(ctx)


@plugin.command(name="verify-plan", summary={"zh": "校验 JSON 初始化计划", "en": "Verify JSON init plan"}, usage="gs multirepo verify-plan <plan.json>", args=[{"name": "file", "type": "path", "required": True, "description": {"zh": "计划文件", "en": "Plan file"}}])
def verify_plan(ctx):
    filename = str(ctx.args.get("file") or "")
    if not filename:
        return {"exit_code": 2, "stderr": "缺少计划文件\n"}
    path = Path(filename).expanduser()
    if not path.is_absolute():
        path = _cwd(ctx) / path
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"exit_code": 2, "stderr": "计划读取失败: {}\n".format(exc)}
    required = {"schema_version", "plan_id", "generated_at", "mode", "backend", "manifest", "root", "projects", "actions", "check", "summary"}
    missing = sorted(required - set(plan)) if isinstance(plan, dict) else sorted(required)
    if missing:
        return {"exit_code": 1, "stderr": "计划缺少字段: {}\n".format(", ".join(missing))}
    errors = []
    if plan["schema_version"] != 1:
        errors.append("不支持的 schema_version")
    if plan["mode"] != "dry-run":
        errors.append("计划 mode 必须是 dry-run")
    if not isinstance(plan["plan_id"], str) or len(plan["plan_id"]) != 16:
        errors.append("plan_id 无效")
    elif plan["plan_id"] != _plan_fingerprint(plan):
        errors.append("plan_id 与计划内容不匹配，计划可能已被修改")
    if not isinstance(plan["check"], dict) or plan["check"].get("ok") is not True:
        errors.append("计划 check 未通过")
    try:
        plan_root = Path(plan["root"]).expanduser().resolve()
        manifest_path = Path(plan["manifest"]).expanduser().resolve()
        if not plan_root.is_dir():
            errors.append("计划 root 不存在")
        if not manifest_path.is_file():
            errors.append("计划 manifest 不存在")
        elif manifest_path.parent != BUILTIN.resolve() and not str(manifest_path).startswith(str(plan_root)):
            errors.append("计划 manifest 与 root 不匹配")
    except (TypeError, ValueError, OSError):
        errors.append("计划 root/manifest 路径无效")
    if errors:
        return {"exit_code": 1, "stderr": "计划校验失败: {}\n".format("; ".join(errors))}
    return {"stdout": "计划有效\nplan_id: {}\nbackend: {}\n项目数: {}\n风险: {}\n".format(plan["plan_id"], plan["backend"], plan["summary"].get("project_count", 0), plan["summary"].get("risk", "unknown"))}


@plugin.command(name="apply-plan", summary={"zh": "应用已验证的多仓库计划", "en": "Apply a verified multi-repo plan"}, usage="gs multirepo apply-plan <plan.json> --yes", args=[{"name": "file", "type": "path", "required": True}, {"name": "options", "type": "string", "variadic": True}])
def apply_plan(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    if options != ["--yes"]:
        return {"exit_code": 2, "stderr": "应用计划必须显式指定 --yes\n"}
    filename = str(ctx.args.get("file") or "")
    path = Path(filename).expanduser()
    if not path.is_absolute():
        path = _cwd(ctx) / path
    try:
        plan = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"exit_code": 2, "stderr": "计划读取失败: {}\n".format(exc)}
    required = {"schema_version", "plan_id", "generated_at", "mode", "backend", "manifest", "root", "projects", "actions", "check", "summary"}
    missing = sorted(required - set(plan)) if isinstance(plan, dict) else sorted(required)
    if missing:
        return {"exit_code": 1, "stderr": "计划缺少字段: {}\n".format(", ".join(missing))}
    if plan.get("mode") != "dry-run" or plan.get("check", {}).get("ok") is not True:
        return {"exit_code": 1, "stderr": "计划必须是校验通过的 dry-run 计划\n"}
    if plan.get("plan_id") != _plan_fingerprint(plan):
        return {"exit_code": 1, "stderr": "计划 plan_id 与内容不匹配\n"}
    if plan.get("backend") != "git":
        return {"exit_code": 2, "stderr": "apply-plan 当前只支持 git backend；repo backend 请先手动执行计划\n"}
    if shutil.which("git") is None:
        return {"exit_code": 127, "stderr": "未找到 git\n"}
    root = Path(plan["root"]).expanduser().resolve()
    if not root.is_dir():
        return {"exit_code": 2, "stderr": "计划 root 不存在: {}\n".format(root)}
    results = []
    for project in plan["projects"]:
        try:
            rel = _safe_project_path(project.get("path", ""))
        except ValueError as exc:
            return {"exit_code": 1, "stderr": str(exc) + "\n"}
        target = (root / rel).resolve()
        try:
            target.relative_to(root)
        except ValueError:
            return {"exit_code": 1, "stderr": "project 目标越出 root: {}\n".format(target)}
        if target.exists():
            if (target / ".git").is_dir():
                results.append("跳过已存在: {}".format(rel))
                continue
            return {"exit_code": 1, "stderr": "目标已存在但不是 Git 仓库: {}\n".format(target)}
        target.parent.mkdir(parents=True, exist_ok=True)
        url = project.get("url") or ""
        if not url:
            return {"exit_code": 1, "stderr": "project 缺少 remote URL: {}\n".format(rel)}
        command = ["git", "clone", url, str(target)]
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        except subprocess.TimeoutExpired:
            return {"exit_code": 124, "stderr": "git clone 超时: {}\n".format(rel)}
        if result.returncode != 0:
            return {"exit_code": result.returncode or 1, "stderr": "git clone 失败 {}: {}\n".format(rel, (result.stderr or result.stdout).strip())}
        revision = str(project.get("revision") or "").strip()
        if revision:
            checkout = subprocess.run(["git", "-C", str(target), "checkout", revision], capture_output=True, text=True, timeout=120)
            if checkout.returncode != 0:
                return {"exit_code": checkout.returncode or 1, "stderr": "git checkout 失败 {}: {}\n".format(rel, (checkout.stderr or checkout.stdout).strip())}
        results.append("已克隆: {}".format(rel))
    return {"stdout": "MultiRepo 计划已应用\nBackend: git\nRoot: {}\n{}\n".format(root, "\n".join(results) if results else "无项目需要处理")}


@plugin.command(name="inspect", summary={"zh": "汇总 manifest 与当前状态", "en": "Summarize manifest and workspace"}, usage="gs multirepo inspect [manifest]", args=[{"name": "manifest", "type": "string", "description": {"zh": "manifest 名称或路径", "en": "Manifest name or path"}}])
def inspect(ctx):
    manifest_result = manifest_info(ctx)
    status_result = status(ctx)
    if manifest_result.get("exit_code", 0) != 0:
        return status_result
    return {"stdout": manifest_result.get("stdout", "") + status_result.get("stdout", "")}


@plugin.command(name="sync", summary={"zh": "同步多仓库项目", "en": "Synchronize multi-repo projects"}, usage="gs multirepo sync [manifest] [--clean] <--dry-run|--yes>", args=[{"name": "manifest", "type": "string", "description": {"zh": "manifest 名称或路径", "en": "Manifest name or path"}}, {"name": "options", "type": "string", "variadic": True}])
def sync_projects(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    mode, error = _write_mode(options, "multirepo sync")
    allowed = {"--dry-run", "--yes", "--clean"}
    unknown = [value for value in options if value not in allowed]
    if error or unknown:
        return {"exit_code": 2, "stderr": (error or "不支持的 sync 选项: {}".format(" ".join(unknown))) + "\n"}
    root = _cwd(ctx).resolve()
    clean = "--clean" in options
    if (root / ".repo").is_dir():
        command = ["repo", "sync"] + (["--force-sync"] if clean else [])
        lines = ["Backend: repo", "Command: {}".format(" ".join(command))]
        if mode == "dry-run":
            return {"stdout": "MultiRepo sync 计划（dry-run）\n{}\n不会联网或修改仓库\n".format("\n".join(lines))}
        result = subprocess.run(command, cwd=root, timeout=3600)
        return {"exit_code": result.returncode, "stdout": "Repo sync 完成\n" if result.returncode == 0 else ""}
    path = _manifest_path(ctx, str(ctx.args.get("manifest") or ""))
    if path is None:
        return {"exit_code": 2, "stderr": "未找到 manifest\n"}
    try:
        projects = _parse_manifest(path)["projects"]
    except (OSError, ET.ParseError, ValueError) as exc:
        return {"exit_code": 2, "stderr": "manifest 解析失败: {}\n".format(exc)}
    commands = []
    for project in projects:
        target = (root / project["path"]).resolve()
        try:
            target.relative_to(root)
        except ValueError:
            return {"exit_code": 1, "stderr": "project 目标越出 root: {}\n".format(target)}
        if (target / ".git").is_dir():
            if clean:
                commands.append((["git", "-C", str(target), "reset", "--hard", "HEAD"], project["path"]))
            commands.append((["git", "-C", str(target), "pull", "--ff-only"], project["path"]))
    if mode == "dry-run":
        lines = ["  {}: {}".format(name, " ".join(command)) for command, name in commands]
        return {"stdout": "MultiRepo sync 计划（dry-run）\n{}\n不会联网或修改仓库\n".format("\n".join(lines) or "无已初始化项目")}
    for command, name in commands:
        result = subprocess.run(command, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            return {"exit_code": result.returncode or 1, "stderr": "同步失败 {}: {}\n".format(name, (result.stderr or result.stdout).strip())}
    return {"stdout": "MultiRepo sync 完成: {} 个操作\n".format(len(commands))}


@plugin.command(name="checkout", summary={"zh": "为 repo 项目创建远程跟踪分支", "en": "Create local tracking branches for repo projects"}, usage="gs multirepo checkout <--dry-run|--yes>", args=[{"name": "options", "type": "string", "variadic": True}])
def checkout_branches(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    mode, error = _write_mode(options, "multirepo checkout")
    if error or any(value not in {"--dry-run", "--yes"} for value in options):
        return {"exit_code": 2, "stderr": (error or "不支持的 checkout 选项") + "\n"}
    root = _cwd(ctx).resolve()
    project_list = root / ".repo" / "project.list"
    if not project_list.is_file():
        return {"exit_code": 1, "stderr": "未找到 .repo/project.list\n"}
    actions = []
    for value in project_list.read_text(encoding="utf-8").splitlines():
        if not value.strip():
            continue
        try:
            rel = _safe_project_path(value.strip())
        except ValueError as exc:
            return {"exit_code": 1, "stderr": str(exc) + "\n"}
        project = (root / rel).resolve()
        if not (project / ".git").exists():
            continue
        result = subprocess.run(
            ["git", "-C", str(project), "for-each-ref", "--format=%(refname:short)", "refs/remotes/origin"],
            capture_output=True, text=True, timeout=20,
        )
        if result.returncode != 0:
            return {"exit_code": 1, "stderr": "读取远程分支失败: {}\n".format(rel)}
        existing = subprocess.run(
            ["git", "-C", str(project), "for-each-ref", "--format=%(refname:short)", "refs/heads"],
            capture_output=True, text=True, timeout=20,
        ).stdout.splitlines()
        original = _current_branch(project)
        for remote in result.stdout.splitlines():
            if remote.endswith("/HEAD") or not remote.startswith("origin/"):
                continue
            branch = remote.split("/", 1)[1]
            if branch not in existing:
                actions.append((project, branch, remote, original))
    if mode == "dry-run":
        lines = ["  {}: {} <- {}".format(project.relative_to(root), branch, remote) for project, branch, remote, _ in actions]
        return {"stdout": "MultiRepo checkout 计划（dry-run）\n{}\n不会创建或切换分支\n".format("\n".join(lines) or "无缺失分支")}
    touched = {}
    for project, branch, remote, original in actions:
        result = subprocess.run(
            ["git", "-C", str(project), "branch", "--track", branch, remote],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return {"exit_code": 1, "stderr": "创建分支失败 {}: {}\n".format(branch, (result.stderr or result.stdout).strip())}
        touched[str(project)] = original
    return {"stdout": "MultiRepo checkout 完成: 创建 {} 个分支\n".format(len(actions))}


@plugin.command(name="push", summary={"zh": "智能推送到 Gerrit 或普通 Git", "en": "Push to Gerrit or regular Git"}, usage="gs multirepo push [options] <--dry-run|--yes>", args=[{"name": "options", "type": "string", "variadic": True}])
def push(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    mode, error = _write_mode(options, "multirepo push")
    if error:
        return {"exit_code": 2, "stderr": error + "\n"}
    branch = remote = ""
    reviewers = []
    drafts = False
    index = 0
    while index < len(options):
        value = options[index]
        if value in {"--dry-run", "--yes"}:
            index += 1
            continue
        if value in {"-d", "--drafts"}:
            drafts = True
            index += 1
            continue
        if value in {"-b", "--branch", "-r", "--reviewer", "--remote"} and index + 1 < len(options):
            target = options[index + 1]
            if value in {"-b", "--branch"}:
                branch = target
            elif value in {"-r", "--reviewer"}:
                reviewers = [item.strip() for item in target.split(",") if item.strip()]
            else:
                remote = target
            index += 2
            continue
        return {"exit_code": 2, "stderr": "不支持或缺少值的 push 选项: {}\n".format(value)}
    root = _cwd(ctx).resolve()
    if not (root / ".git").exists():
        return {"exit_code": 1, "stderr": "当前目录不是 Git 仓库\n"}
    remote_name = remote or "origin"
    url = _git_remote(root, remote_name)
    if not url:
        return {"exit_code": 1, "stderr": "未找到 push remote: {}\n".format(remote_name)}
    branch = branch or _current_branch(root)
    if not branch:
        return {"exit_code": 1, "stderr": "无法确定目标分支\n"}
    refspec = branch
    if _is_gerrit(url):
        refspec = "refs/{}/{branch}".format("drafts" if drafts else "for", branch=branch)
        if reviewers:
            refspec += "%" + ",".join("r={}".format(item) for item in reviewers)
        refspec = "HEAD:" + refspec
    command = ["git", "push", remote_name, refspec]
    if mode == "dry-run":
        return {"stdout": "MultiRepo push 计划（dry-run）\nRemote: {}\nURL: {}\nCommand: {}\n不会联网或推送提交\n".format(remote_name, url, " ".join(command))}
    result = subprocess.run(command, cwd=root, timeout=600)
    return {"exit_code": result.returncode, "stdout": "Push 完成\n" if result.returncode == 0 else ""}


if __name__ == "__main__":
    raise SystemExit(plugin.run())
