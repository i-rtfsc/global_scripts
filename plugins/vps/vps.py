#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""VPS connection, reverse-tunnel, and SSHFS mount management."""

from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path

_SDK = Path(__file__).resolve().parents[2] / "sdk" / "python"
if _SDK.is_dir():
    sys.path.insert(0, str(_SDK))

from gs_plugin import Plugin  # noqa: E402


plugin = Plugin(name="vps")


def _env(ctx, name, default):
    return str(ctx.env.get(name) or default)


def _config(ctx):
    try:
        local_port = int(_env(ctx, "GS_VPS_LOCAL_PORT", "2222"))
        remote_port = int(_env(ctx, "GS_VPS_REMOTE_PORT", "22"))
    except ValueError:
        return None
    if not (1 <= local_port <= 65535 and 1 <= remote_port <= 65535):
        return None
    return {
        "host": _env(ctx, "GS_VPS_HOST", "178.128.215.72"),
        "user": _env(ctx, "GS_VPS_USER", "solo"),
        "local_port": local_port,
        "remote_port": remote_port,
        "mac_dir": _env(ctx, "GS_VPS_MAC_DIR", "/Users/solo/code"),
        "mount": Path(_env(ctx, "GS_VPS_MOUNT_POINT", "/home/solo/mac")).expanduser(),
    }


def _mode(ctx, label):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    dry_run = "--dry-run" in options
    execute = "--yes" in options
    if dry_run == execute or any(value not in {"--dry-run", "--yes"} for value in options):
        return None, {"exit_code": 2, "stderr": "{} 必须且只能指定 --dry-run 或 --yes\n".format(label)}
    return ("dry-run" if dry_run else "execute"), None


def _tunnel_pattern(config):
    return "autossh.*{}:localhost:{}.*{}".format(config["local_port"], config["remote_port"], config["host"])


def _tunnel_pids(config):
    try:
        result = subprocess.run(
            ["pgrep", "-f", _tunnel_pattern(config)], capture_output=True, text=True, timeout=5
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    return [int(value) for value in result.stdout.split() if value.isdigit()]


def _mountpoint(path):
    try:
        return subprocess.run(
            ["mountpoint", "-q", str(path)], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=5,
        ).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _mount_command(config):
    return [
        "sshfs", "-p", str(config["local_port"]),
        "{}@localhost:{}".format(config["user"], config["mac_dir"]),
        str(config["mount"]), "-o", "idmap=user,reconnect,ServerAliveInterval=15,StrictHostKeyChecking=no",
    ]


def _unmount(config):
    if not _mountpoint(config["mount"]):
        return 0
    for command in (["fusermount", "-u", str(config["mount"])], ["umount", str(config["mount"])]):
        if shutil.which(command[0]) and subprocess.run(command).returncode == 0:
            return 0
    return 1


_WRITE_ARGS = [{"name": "options", "type": "string", "variadic": True}]


@plugin.command(name="help", summary={"zh": "显示 VPS 命令", "en": "Show VPS commands"}, usage="gs vps help")
def help_command(ctx):
    config = _config(ctx)
    if config is None:
        return {"exit_code": 2, "stderr": "VPS 端口配置无效\n"}
    return {"stdout": "VPS commands: ssh, tunnel, status, stop, mount, unmount, remount\nHost: {}@{}\nTunnel: remote {} -> local {}\nMount: {}\n".format(config["user"], config["host"], config["local_port"], config["remote_port"], config["mount"])}


@plugin.command(name="ssh", summary={"zh": "连接 VPS", "en": "Connect to VPS"}, usage="gs vps ssh <--dry-run|--yes>", args=_WRITE_ARGS)
def ssh(ctx):
    mode, error = _mode(ctx, "vps ssh")
    if error:
        return error
    config = _config(ctx)
    if config is None:
        return {"exit_code": 2, "stderr": "VPS 端口配置无效\n"}
    command = ["ssh", "{}@{}".format(config["user"], config["host"])]
    if mode == "dry-run":
        return {"stdout": "VPS SSH 计划（dry-run）\nCommand: {}\n不会建立网络连接\n".format(" ".join(command))}
    return {"exec": command, "stdout": "连接到 VPS: {}@{}\n".format(config["user"], config["host"])}


@plugin.command(name="tunnel", summary={"zh": "创建反向 SSH 隧道", "en": "Create a reverse SSH tunnel"}, usage="gs vps tunnel <--dry-run|--yes>", args=_WRITE_ARGS)
def tunnel(ctx):
    mode, error = _mode(ctx, "vps tunnel")
    if error:
        return error
    config = _config(ctx)
    if config is None:
        return {"exit_code": 2, "stderr": "VPS 端口配置无效\n"}
    command = [
        "autossh", "-M", "0", "-fNR",
        "{}:localhost:{}".format(config["local_port"], config["remote_port"]),
        "{}@{}".format(config["user"], config["host"]),
        "-o", "ServerAliveInterval=30", "-o", "ServerAliveCountMax=30",
        "-o", "ExitOnForwardFailure=yes", "-o", "StrictHostKeyChecking=no",
    ]
    if mode == "dry-run":
        return {"stdout": "VPS tunnel 计划（dry-run）\nCommand: {}\n不会启动后台进程\n".format(" ".join(command))}
    if _tunnel_pids(config):
        return {"exit_code": 1, "stderr": "反向隧道已经在运行\n"}
    result = subprocess.run(command, timeout=60)
    return {"exit_code": result.returncode, "stdout": "反向隧道已启动\n" if result.returncode == 0 else ""}


@plugin.command(name="status", summary={"zh": "检查隧道和挂载状态", "en": "Check tunnel and mount status"}, usage="gs vps status")
def status(ctx):
    config = _config(ctx)
    if config is None:
        return {"exit_code": 2, "stderr": "VPS 端口配置无效\n"}
    pids = _tunnel_pids(config)
    return {"stdout": "VPS 状态\nTunnel: {}{}\nMount: {}\n".format("running" if pids else "stopped", " ({})".format(",".join(map(str, pids))) if pids else "", "mounted" if _mountpoint(config["mount"]) else "unmounted")}


@plugin.command(name="stop", summary={"zh": "停止反向隧道", "en": "Stop the reverse tunnel"}, usage="gs vps stop <--dry-run|--yes>", args=_WRITE_ARGS)
def stop(ctx):
    mode, error = _mode(ctx, "vps stop")
    if error:
        return error
    config = _config(ctx)
    if config is None:
        return {"exit_code": 2, "stderr": "VPS 端口配置无效\n"}
    pids = _tunnel_pids(config)
    if mode == "dry-run":
        return {"stdout": "VPS stop 计划（dry-run）\nPIDs: {}\n不会终止进程\n".format(", ".join(map(str, pids)) or "无")}
    for pid in pids:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as exc:
            return {"exit_code": 1, "stderr": "停止进程 {} 失败: {}\n".format(pid, exc)}
    return {"stdout": "反向隧道已停止\n" if pids else "没有运行中的隧道\n"}


@plugin.command(name="mount", summary={"zh": "挂载远程 Mac 目录", "en": "Mount the remote Mac directory"}, usage="gs vps mount <--dry-run|--yes>", args=_WRITE_ARGS)
def mount(ctx):
    mode, error = _mode(ctx, "vps mount")
    if error:
        return error
    config = _config(ctx)
    if config is None:
        return {"exit_code": 2, "stderr": "VPS 端口配置无效\n"}
    command = _mount_command(config)
    if mode == "dry-run":
        return {"stdout": "VPS mount 计划（dry-run）\nCommand: {}\n不会创建挂载\n".format(" ".join(command))}
    config["mount"].mkdir(parents=True, exist_ok=True)
    result = subprocess.run(command, timeout=120)
    return {"exit_code": result.returncode, "stdout": "挂载完成\n" if result.returncode == 0 else ""}


@plugin.command(name="unmount", summary={"zh": "卸载远程目录", "en": "Unmount the remote directory"}, usage="gs vps unmount <--dry-run|--yes>", args=_WRITE_ARGS)
def unmount(ctx):
    mode, error = _mode(ctx, "vps unmount")
    if error:
        return error
    config = _config(ctx)
    if config is None:
        return {"exit_code": 2, "stderr": "VPS 端口配置无效\n"}
    if mode == "dry-run":
        return {"stdout": "VPS unmount 计划（dry-run）\nMount: {}\n不会卸载目录\n".format(config["mount"])}
    rc = _unmount(config)
    return {"exit_code": rc, "stdout": "目录已卸载\n" if rc == 0 else "", "stderr": "卸载失败\n" if rc else ""}


@plugin.command(name="remount", summary={"zh": "重新挂载远程目录", "en": "Remount the remote directory"}, usage="gs vps remount <--dry-run|--yes>", args=_WRITE_ARGS)
def remount(ctx):
    mode, error = _mode(ctx, "vps remount")
    if error:
        return error
    config = _config(ctx)
    if config is None:
        return {"exit_code": 2, "stderr": "VPS 端口配置无效\n"}
    if mode == "dry-run":
        return {"stdout": "VPS remount 计划（dry-run）\nMount: {}\nCommand: {}\n不会卸载或挂载目录\n".format(config["mount"], " ".join(_mount_command(config)))}
    if _unmount(config) != 0:
        return {"exit_code": 1, "stderr": "卸载现有挂载失败\n"}
    config["mount"].mkdir(parents=True, exist_ok=True)
    result = subprocess.run(_mount_command(config), timeout=120)
    return {"exit_code": result.returncode, "stdout": "重新挂载完成\n" if result.returncode == 0 else ""}


if __name__ == "__main__":
    raise SystemExit(plugin.run())
