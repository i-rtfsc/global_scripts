#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Android plugin (device + logcat subset) — GS 6.0 native port (T2 / script).

A faithful, stdlib-only re-implementation of the legacy ``android`` subplugins
``device`` and ``logcat`` on the new ``gs_plugin`` SDK. It exercises the parts
of the protocol the ``devenv`` port did not:

  * ``.``-namespaced subcommands — ``device.*`` / ``logcat.*``.
  * a dynamic completion source — ``device.select`` completes live adb serials.
  * static ``enum`` completion — ``logcat.tail`` level (baked into the shell).
  * streamed output — ``logcat.tail`` / ``logcat.filter`` sample lines via
    ``ctx.emit_output``.

Published under the plugin name **``android6``** (own dir) so it sits *beside*
the legacy ``android`` plugin instead of shadowing it — the not-yet-ported
subplugins (emulator/input/fs/…) keep working via the old path. Selected-device
state shares the legacy file ``~/.config/global-scripts/config/android.json``
(same schema), so a device picked here is seen by the legacy plugin and back.

The interactive ``device choose`` (reads stdin) cannot work under T2 — stdin is
the JSON-RPC channel — so it becomes ``device.select <serial>`` with dynamic
serial completion, matching the protocol doc's worked example.
"""

from __future__ import annotations

import json
import os
import select
import shutil
import subprocess
import sys
import time

# Make the SDK importable in-tree (repo layout) or from PYTHONPATH.
_SDK = os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python")
if os.path.isdir(_SDK):
    sys.path.insert(0, os.path.abspath(_SDK))

from gs_plugin import Plugin  # noqa: E402

plugin = Plugin(name="android6")


# ---- selected-device state (stdlib; shares the legacy android.json) --------

def _config_path():
    # Mirrors gscripts ConfigManager._get_config_dir(): ~/.config/global-scripts.
    return os.path.join(
        os.path.expanduser("~"), ".config", "global-scripts", "config", "android.json"
    )


def _read_state():
    try:
        with open(_config_path(), "r", encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def _write_state(data):
    path = _config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def _get_selected():
    v = _read_state().get("selected_device")
    return v if isinstance(v, str) and v.strip() else None


def _set_selected(serial):
    state = _read_state()
    if serial:
        state["selected_device"] = serial
    else:
        state.pop("selected_device", None)
    _write_state(state)


# ---- adb helpers (sync; the legacy used asyncio, T2 has no event loop) ------

def _adb_exists():
    return shutil.which("adb") is not None


def _list_devices():
    """Serials reported as ``device`` by ``adb devices`` ([] on any failure)."""
    try:
        r = subprocess.run(
            ["adb", "devices"], capture_output=True, text=True, timeout=10
        )
    except Exception:
        return []
    if r.returncode != 0:
        return []
    out = []
    for line in r.stdout.strip().splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            out.append(parts[0])
    return out


def _active_device():
    """Selected serial if still connected, else the first device (and persist
    it — mirrors the legacy fallback). ``None`` when nothing is connected."""
    devices = _list_devices()
    if not devices:
        return None
    selected = _get_selected()
    if selected in devices:
        return selected
    _set_selected(devices[0])
    return devices[0]


def _adb_base(with_serial=True):
    base = ["adb"]
    if with_serial:
        serial = _active_device()
        if serial:
            base += ["-s", serial]
    return base


def _run_adb(ctx, extra, with_serial=True, timeout=60):
    """Run an adb command, stream its stdout/stderr, return its exit code."""
    if not _adb_exists():
        ctx.emit_output("stderr", "未找到 adb，请先安装 Android Platform Tools\n")
        return 127
    cmd = _adb_base(with_serial) + extra
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        ctx.emit_output("stderr", "adb 超时: {}\n".format(" ".join(cmd)))
        return 124
    except Exception as e:  # noqa: BLE001
        ctx.emit_output("stderr", "adb 执行异常: {}\n".format(e))
        return 1
    if r.stdout:
        ctx.emit_output("stdout", r.stdout)
    if r.stderr:
        ctx.emit_output("stderr", r.stderr)
    return r.returncode


def _resolve_out(ctx, path):
    """Resolve a relative output path against the *user's* cwd — the plugin
    process runs in its own dir, so a bare filename must not land there."""
    if os.path.isabs(path):
        return path
    base = ctx.cwd or os.getcwd()
    return os.path.join(base, path)


# ---- device.* --------------------------------------------------------------

@plugin.command(
    name="device.devices",
    summary={"zh": "列出所有连接的设备", "en": "List connected devices"},
    usage="gs android6 device.devices",
    examples=["gs android6 device.devices"],
)
def device_devices(ctx):
    if not _adb_exists():
        ctx.emit_output("stderr", "未找到 adb\n")
        return 127
    devices = _list_devices()
    if not devices:
        ctx.emit_output("stderr", "未检测到设备（adb devices 为空）\n")
        return 1
    ctx.emit_output("stdout", "\n".join(devices) + "\n")
    return 0


@plugin.command(
    name="device.select",
    summary={"zh": "选择并保存默认设备", "en": "Select & persist the default device"},
    usage="gs android6 device.select <serial>",
    examples=["gs android6 device.select emulator-5554"],
    args=[
        {"name": "serial", "type": "string", "required": True,
         "description": {"zh": "设备序列号", "en": "Device serial"},
         "complete": {"kind": "dynamic", "source": "device_serials"}},
    ],
)
def device_select(ctx):
    serial = ctx.args.get("serial")
    if not serial:
        ctx.emit_output("stderr", "用法: gs android6 device.select <serial>\n")
        return 2
    _set_selected(serial)
    note = "" if serial in _list_devices() else "（当前未连接）"
    ctx.emit_output("stdout", "已选择设备: {}{}\n".format(serial, note))
    return 0


@plugin.command(
    name="device.current",
    summary={"zh": "查看当前默认设备", "en": "Show the current default device"},
    usage="gs android6 device.current",
    examples=["gs android6 device.current"],
)
def device_current(ctx):
    serial = _active_device()
    if not serial:
        ctx.emit_output("stderr", "无活动设备，运行: gs android6 device.select <serial>\n")
        return 1
    ctx.emit_output("stdout", "当前设备: {}\n".format(serial))
    return 0


@plugin.command(
    name="device.clear",
    summary={"zh": "清除已选设备", "en": "Clear the selected device"},
    usage="gs android6 device.clear",
    examples=["gs android6 device.clear"],
)
def device_clear(ctx):
    _set_selected(None)
    ctx.emit_output("stdout", "已清除选中设备\n")
    return 0


@plugin.command(
    name="device.connect",
    summary={"zh": "通过 IP 连接设备", "en": "Connect to a device over IP"},
    usage="gs android6 device.connect <ip[:port]>",
    examples=["gs android6 device.connect 192.168.1.10:5555"],
    args=[
        {"name": "target", "type": "string", "required": True,
         "description": {"zh": "IP[:端口]", "en": "ip[:port]"}},
    ],
)
def device_connect(ctx):
    target = ctx.args.get("target")
    if not target:
        ctx.emit_output("stderr", "用法: gs android6 device.connect <ip[:port]>\n")
        return 2
    return _run_adb(ctx, ["connect", target], with_serial=False)


@plugin.command(
    name="device.disconnect",
    summary={"zh": "断开 IP 连接", "en": "Disconnect from an IP device"},
    usage="gs android6 device.disconnect [ip[:port]]",
    examples=["gs android6 device.disconnect", "gs android6 device.disconnect 192.168.1.10:5555"],
    args=[
        {"name": "target", "type": "string", "required": False,
         "description": {"zh": "IP[:端口]（缺省=全部）", "en": "ip[:port] (default: all)"}},
    ],
)
def device_disconnect(ctx):
    target = ctx.args.get("target")
    extra = ["disconnect"] + ([target] if target else [])
    return _run_adb(ctx, extra, with_serial=False)


@plugin.command(
    name="device.size",
    summary={"zh": "获取屏幕尺寸", "en": "Get the screen size"},
    usage="gs android6 device.size",
    examples=["gs android6 device.size"],
)
def device_size(ctx):
    return _run_adb(ctx, ["shell", "wm", "size"])


@plugin.command(
    name="device.wait",
    summary={"zh": "等待设备就绪", "en": "Wait for a device"},
    usage="gs android6 device.wait",
    examples=["gs android6 device.wait"],
)
def device_wait(ctx):
    rc = _run_adb(ctx, ["wait-for-device"], with_serial=False, timeout=120)
    if rc == 0:
        ctx.emit_output("stdout", "device is ready\n")
    return rc


@plugin.command(
    name="device.screencap",
    summary={"zh": "截屏到本地", "en": "Capture a screenshot to a local file"},
    usage="gs android6 device.screencap [outfile.png]",
    examples=["gs android6 device.screencap", "gs android6 device.screencap screen.png"],
    args=[
        {"name": "outfile", "type": "path", "required": False, "default": "screencap.png",
         "description": {"zh": "输出文件", "en": "Output file"},
         "complete": {"kind": "file", "pattern": "*.png"}},
    ],
)
def device_screencap(ctx):
    if not _adb_exists():
        ctx.emit_output("stderr", "未找到 adb\n")
        return 127
    out = _resolve_out(ctx, ctx.args.get("outfile") or "screencap.png")
    base = _adb_base(with_serial=True)
    # Prefer `exec-out screencap -p` (binary on stdout, no /sdcard round-trip).
    try:
        r = subprocess.run(base + ["exec-out", "screencap", "-p"],
                           capture_output=True, timeout=60)
    except Exception as e:  # noqa: BLE001
        ctx.emit_output("stderr", "adb 执行异常: {}\n".format(e))
        return 1
    if r.returncode == 0 and r.stdout:
        try:
            with open(out, "wb") as f:
                f.write(r.stdout)
        except OSError as e:
            ctx.emit_output("stderr", "写入失败: {}\n".format(e))
            return 1
        ctx.emit_output("stdout", "已保存到 {}\n".format(out))
        return 0
    # Fallback: screencap to /sdcard then pull.
    tmp = "/sdcard/__gs_screencap.png"
    if _run_adb(ctx, ["shell", "screencap", "-p", tmp]) != 0:
        return 1
    rc = subprocess.run(base + ["pull", tmp, out], capture_output=True, text=True, timeout=60)
    subprocess.run(base + ["shell", "rm", "-f", tmp], capture_output=True, timeout=30)
    if rc.returncode == 0:
        ctx.emit_output("stdout", "已保存到 {}\n".format(out))
        return 0
    ctx.emit_output("stderr", rc.stderr or "pull 失败\n")
    return 1


# ---- logcat.* --------------------------------------------------------------

def _sample_logcat(ctx, extra, limit, keyword=None, max_seconds=8.0):
    """Sample up to ``limit`` raw logcat lines (the legacy is non-blocking too),
    streaming matches via ``ctx.emit_output``, then kill the long-running adb.

    Bounded by both ``limit`` lines *and* ``max_seconds`` wall-clock — the legacy
    only bounded by line count, so on a quiet device its ``readline`` loop would
    block forever waiting for the Nth line. Under T2 a hung invoke is worse, so
    we ``select`` with a deadline (POSIX; falls back to plain readline elsewhere).
    """
    if not _adb_exists():
        ctx.emit_output("stderr", "未找到 adb\n")
        return 127
    cmd = _adb_base(with_serial=True) + extra
    ctx.emit_progress(message="sampling logcat", stage="logcat")
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:  # noqa: BLE001
        ctx.emit_output("stderr", "adb 执行异常: {}\n".format(e))
        return 1
    if proc.stdout is None:
        proc.kill()
        ctx.emit_output("stderr", "无法读取 logcat 输出\n")
        return 1
    matched = 0
    deadline = time.monotonic() + max_seconds
    try:
        for _ in range(limit):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                ready, _, _ = select.select([proc.stdout], [], [], remaining)
                if not ready:
                    break  # deadline hit with no new line
            except (OSError, ValueError):
                pass  # non-POSIX / unselectable: fall back to a plain read
            line = proc.stdout.readline()
            if not line:
                break
            text = line.decode("utf-8", "ignore")
            if keyword is not None and keyword not in text:
                continue
            ctx.emit_output("stdout", text)
            matched += 1
    finally:
        try:
            proc.kill()
        except Exception:
            pass
    if keyword is not None and matched == 0:
        ctx.emit_output("stdout", "没有匹配的日志行: {}\n".format(keyword))
    return 0


@plugin.command(
    name="logcat.clear",
    summary={"zh": "清除 logcat 缓冲区", "en": "Clear the logcat buffer"},
    usage="gs android6 logcat.clear",
    examples=["gs android6 logcat.clear"],
)
def logcat_clear(ctx):
    return _run_adb(ctx, ["logcat", "-c"])


@plugin.command(
    name="logcat.tail",
    summary={"zh": "采样跟随 logcat（前 100 行）", "en": "Tail logcat (first 100 lines)"},
    usage="gs android6 logcat.tail [level]",
    examples=["gs android6 logcat.tail", "gs android6 logcat.tail *:W"],
    args=[
        {"name": "level", "type": "string", "required": False, "default": "*:I",
         "description": {"zh": "logcat 过滤等级（如 *:W）", "en": "logcat filterspec (e.g. *:W)"},
         "complete": {"kind": "enum", "values": ["*:V", "*:D", "*:I", "*:W", "*:E", "*:F"]}},
    ],
)
def logcat_tail(ctx):
    level = ctx.args.get("level") or "*:I"
    return _sample_logcat(ctx, ["logcat", "-v", "time", level], limit=100)


@plugin.command(
    name="logcat.filter",
    summary={"zh": "按关键字过滤 logcat（采样前 200 行）", "en": "Filter logcat by keyword (sample 200)"},
    usage="gs android6 logcat.filter <keyword>",
    examples=["gs android6 logcat.filter ActivityManager"],
    args=[
        {"name": "keyword", "type": "string", "required": True,
         "description": {"zh": "包含关键字", "en": "Substring to match"}},
    ],
)
def logcat_filter(ctx):
    keyword = ctx.args.get("keyword")
    if not keyword:
        ctx.emit_output("stderr", "用法: gs android6 logcat.filter <keyword>\n")
        return 2
    return _sample_logcat(ctx, ["logcat", "-v", "time", "*:I"], limit=200, keyword=keyword)


# ---- dynamic completion: live device serials -------------------------------

@plugin.completer(source="device_serials")
def complete_serials(params):
    # Short TTL — the device set changes when you plug/unplug (spec §3.2 uses 5s).
    return {"values": [{"value": d} for d in _list_devices()], "ttl": 5}


if __name__ == "__main__":
    raise SystemExit(plugin.run())
