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

 This entry is published under the formal plugin name **``android``** and lives
 in the existing plugin directory while the legacy subplugins remain beside it.
 The not-yet-ported subplugins (emulator/input/fs/…) keep working via the old path.
 GS 6.0 keeps selected-device state isolated from the 5.2 legacy configuration.

The interactive ``device choose`` (reads stdin) cannot work under T2 — stdin is
the JSON-RPC channel — so it becomes ``device.select <serial>`` with dynamic
serial completion, matching the protocol doc's worked example.
"""

from __future__ import annotations

import json
import os
import re
import select
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Make the SDK importable in-tree (repo layout) or from PYTHONPATH.
_SDK = os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python")
if os.path.isdir(_SDK):
    sys.path.insert(0, os.path.abspath(_SDK))

from gs_plugin import Plugin  # noqa: E402

plugin = Plugin(name="android")

# Kept as explicit command metadata so GS6's runtime description contains the
# same four build commands exposed by the legacy Android plugin.  They remain
# shell-backed and are intentionally guarded by the existing capability model.
def _build_plan(ctx, action):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    options = [str(x) for x in options]
    dry_run = "--dry-run" in options
    execute = "--yes" in options
    if dry_run == execute:
        ctx.emit_output("stderr", "android build 必须且只能指定 --dry-run 或 --yes\n")
        return 2
    allowed = {"--dry-run", "--yes"}
    unknown = [x for x in options if x not in allowed and not x.startswith(("-t=", "-j=", "-m=", "-c=", "-b="))]
    if unknown:
        ctx.emit_output("stderr", "不支持的 build 选项: {}\n".format(" ".join(unknown)))
        return 2
    if dry_run:
        ctx.emit_output("stdout", "Android build 计划（dry-run）\n动作: {}\n不会执行构建、不会修改源码或设备\n".format(action))
        return 0
    build_script = os.path.join(_legacy_dir("build"), "plugin.sh")
    if not os.path.isfile(build_script):
        ctx.emit_output("stderr", "未找到 Android build 脚本: {}\n".format(build_script))
        return 1
    function = "gs_android_build" if action == "build" else "gs_android_build_{}".format(action.replace("-", "_"))
    argv = [x for x in options if x != "--yes"]
    program = 'source "$1" && shift && {} "$@"'.format(function)
    result = subprocess.run(["bash", "-c", program, "bash", build_script] + argv, cwd=ctx.cwd or os.getcwd())
    return result.returncode


@plugin.command(name="build.ninja-clean", summary={"zh": "清理 ninja 输出", "en": "Clean ninja output"}, usage="gs android build ninja-clean --dry-run", args=[{"name": "options", "type": "string", "variadic": True}])
def build_ninja_clean(ctx):
    return _build_plan(ctx, "ninja-clean")

@plugin.command(name="build.make", summary={"zh": "执行 make 构建", "en": "Run make build"}, usage="gs android build make --dry-run [options]", args=[{"name": "options", "type": "string", "variadic": True}])
def build_make(ctx):
    return _build_plan(ctx, "make")

@plugin.command(name="build.build", summary={"zh": "执行完整构建", "en": "Run full build"}, usage="gs android build build --dry-run [options]", args=[{"name": "options", "type": "string", "variadic": True}])
def build_build(ctx):
    return _build_plan(ctx, "build")

@plugin.command(name="build.qssi", summary={"zh": "构建 QSSI", "en": "Build QSSI"}, usage="gs android build qssi --dry-run [options]", args=[{"name": "options", "type": "string", "variadic": True}])
def build_qssi(ctx):
    return _build_plan(ctx, "qssi")

@plugin.command(name="build.vendor", summary={"zh": "构建 vendor", "en": "Build vendor"}, usage="gs android build vendor --dry-run [options]", args=[{"name": "options", "type": "string", "variadic": True}])
def build_vendor(ctx):
    return _build_plan(ctx, "vendor")


# ---- selected-device state (stdlib; shares the legacy android.json) --------

def _config_path():
    # GS6 state must not mutate the legacy 5.2 android.json. Tests and
    # development shells can provide an isolated directory explicitly.
    root = os.environ.get("GS6_ANDROID_STATE_DIR")
    if not root:
        root = os.path.join(os.environ.get("GS_CACHE_DIR", os.path.expanduser(
            "~/.config/global-scripts/cache")), "android-gs6")
    return os.path.join(root, "android.json")


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
    return devices[0]


def _adb_base(with_serial=True, serial=None):
    base = ["adb"]
    if serial:
        base += ["-s", serial]
    elif with_serial:
        active = _active_device()
        if active:
            base += ["-s", active]
    return base


def _run_adb(ctx, extra, with_serial=True, serial=None, timeout=60):
    """Run an adb command, stream its stdout/stderr, return its exit code."""
    if not _adb_exists():
        ctx.emit_output("stderr", "未找到 adb，请先安装 Android Platform Tools\n")
        return 127
    cmd = _adb_base(with_serial, serial) + extra
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


def _dry_run_only(ctx, label):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    if "--dry-run" not in options:
        ctx.emit_output("stderr", "GS 6.0 当前仅支持 {} --dry-run\n".format(label))
        return 2
    ctx.emit_output("stdout", "{} 计划（dry-run）\n不会修改设备\n".format(label))
    return 0


def _valid_package(value):
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_.$-]+", value) is not None


def _adb_capture(extra, with_serial=True, serial=None, timeout=60):
    """Like ``_run_adb`` but returns ``(rc, stdout, stderr)`` without streaming —
    for multi-step commands that decide what to print after several adb calls."""
    if not _adb_exists():
        return (127, "", "adb not found")
    try:
        r = subprocess.run(_adb_base(with_serial, serial) + extra,
                           capture_output=True, text=True, timeout=timeout)
        return (r.returncode, r.stdout, r.stderr)
    except Exception as e:  # noqa: BLE001
        return (1, "", str(e))


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
    usage="gs android device.devices",
    examples=["gs android device.devices"],
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
    usage="gs android device.select <serial>",
    examples=["gs android device.select emulator-5554"],
    args=[
        {"name": "serial", "type": "string", "required": True,
         "description": {"zh": "设备序列号", "en": "Device serial"},
         "complete": {"kind": "dynamic", "source": "device_serials"}},
    ],
)
def device_select(ctx):
    serial = ctx.args.get("serial")
    if not serial:
        ctx.emit_output("stderr", "用法: gs android device.select <serial>\n")
        return 2
    if not re.fullmatch(r"[A-Za-z0-9._:-]+", str(serial)):
        ctx.emit_output("stderr", "设备序列号包含非法字符\n")
        return 2
    _set_selected(serial)
    note = "" if serial in _list_devices() else "（当前未连接）"
    ctx.emit_output("stdout", "已选择设备: {}{}\n".format(serial, note))
    return 0


@plugin.command(
    name="device.choose",
    summary={"zh": "选择并保存默认设备", "en": "Choose and persist the default device"},
    usage="gs android device choose",
    examples=["gs android device choose"],
)
def device_choose(ctx):
    ctx.emit_output(
        "stdout",
        "GS 6.0: 交互式选择已改为 `gs android device select <serial>`。\n",
    )
    return 0


@plugin.command(
    name="device.current",
    summary={"zh": "查看当前默认设备", "en": "Show the current default device"},
    usage="gs android device.current",
    examples=["gs android device.current"],
)
def device_current(ctx):
    serial = _active_device()
    if not serial:
        ctx.emit_output("stderr", "无活动设备，运行: gs android device.select <serial>\n")
        return 1
    ctx.emit_output("stdout", "当前设备: {}\n".format(serial))
    return 0


@plugin.command(
    name="device.clear",
    summary={"zh": "清除已选设备", "en": "Clear the selected device"},
    usage="gs android device.clear",
    examples=["gs android device.clear"],
)
def device_clear(ctx):
    _set_selected(None)
    ctx.emit_output("stdout", "已清除选中设备\n")
    return 0


@plugin.command(
    name="device.connect",
    summary={"zh": "通过 IP 连接设备", "en": "Connect to a device over IP"},
    usage="gs android device.connect <ip[:port]>",
    examples=["gs android device.connect 192.168.1.10:5555"],
    args=[
        {"name": "target", "type": "string", "required": True,
         "description": {"zh": "IP[:端口]", "en": "ip[:port]"}},
        {"name": "options", "type": "string", "variadic": True},
    ],
)
def device_connect(ctx):
    target = ctx.args.get("target")
    if not target:
        ctx.emit_output("stderr", "用法: gs android device.connect <ip[:port]>\n")
        return 2
    if not re.fullmatch(r"(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(?::[0-9]{1,5})?", str(target)):
        ctx.emit_output("stderr", "目标必须是合法的 IP/主机名[:端口]\n")
        return 2
    options = ctx.args.get("options") or []
    if isinstance(options, str): options = [options]
    if "--dry-run" in options:
        return _dry_run_only(ctx, "device.connect {}".format(target))
    if "--yes" not in options:
        ctx.emit_output("stderr", "device.connect 必须指定 --dry-run 或 --yes\n")
        return 2
    return _run_adb(ctx, ["connect", str(target)], with_serial=False)


@plugin.command(
    name="device.disconnect",
    summary={"zh": "断开 IP 连接", "en": "Disconnect from an IP device"},
    usage="gs android device.disconnect [ip[:port]]",
    examples=["gs android device.disconnect", "gs android device.disconnect 192.168.1.10:5555"],
    args=[
        {"name": "target", "type": "string", "required": False,
         "description": {"zh": "IP[:端口]（缺省=全部）", "en": "ip[:port] (default: all)"}},
        {"name": "options", "type": "string", "variadic": True},
    ],
)
def device_disconnect(ctx):
    target = ctx.args.get("target")
    if target and not re.fullmatch(r"(?:[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])(?::[0-9]{1,5})?", str(target)):
        ctx.emit_output("stderr", "目标必须是合法的 IP/主机名[:端口]\n")
        return 2
    options = ctx.args.get("options") or []
    if isinstance(options, str): options = [options]
    if "--dry-run" in options:
        return _dry_run_only(ctx, "device.disconnect{}".format(" " + target if target else ""))
    if "--yes" not in options:
        ctx.emit_output("stderr", "device.disconnect 必须指定 --dry-run 或 --yes\n")
        return 2
    return _run_adb(ctx, ["disconnect"] + ([str(target)] if target else []), with_serial=False)


@plugin.command(
    name="device.size",
    summary={"zh": "获取屏幕尺寸", "en": "Get the screen size"},
    usage="gs android device.size",
    examples=["gs android device.size"],
)
def device_size(ctx):
    return _run_adb(ctx, ["shell", "wm", "size"])


@plugin.command(
    name="device.wait",
    summary={"zh": "等待设备就绪", "en": "Wait for a device"},
    usage="gs android device.wait",
    examples=["gs android device.wait"],
)
def device_wait(ctx):
    rc = _run_adb(ctx, ["wait-for-device"], with_serial=False, timeout=120)
    if rc == 0:
        ctx.emit_output("stdout", "device is ready\n")
    return rc


@plugin.command(
    name="device.screencap",
    summary={"zh": "截屏到本地", "en": "Capture a screenshot to a local file"},
    usage="gs android device.screencap [outfile.png]",
    examples=["gs android device.screencap", "gs android device.screencap screen.png"],
    args=[
        {"name": "outfile", "type": "path", "required": False, "default": "screencap.png",
         "description": {"zh": "输出文件", "en": "Output file"},
         "complete": {"kind": "file", "pattern": "*.png"}},
        {"name": "options", "type": "string", "variadic": True},
    ],
)
def device_screencap(ctx):
    out = Path(_resolve_out(ctx, ctx.args.get("outfile") or "screencap.png")).resolve()
    cwd = Path(ctx.cwd or os.getcwd()).resolve()
    try:
        out.relative_to(cwd)
    except ValueError:
        ctx.emit_output("stderr", "截屏目标不能越出当前工作目录\n")
        return 2
    if out.suffix.lower() != ".png":
        ctx.emit_output("stderr", "截屏输出必须使用 .png 扩展名\n")
        return 2
    options = ctx.args.get("options") or []
    if isinstance(options, str): options = [options]
    if "--dry-run" in options:
        ctx.emit_output("stdout", "device.screencap 计划（dry-run）\nOutput: {}\n不会访问设备或写入文件\n".format(out))
        return 0
    if "--yes" not in options:
        ctx.emit_output("stderr", "device.screencap 必须指定 --dry-run 或 --yes\n")
        return 2
    if not _adb_exists():
        return 127
    try:
        result = subprocess.run(_adb_base() + ["exec-out", "screencap", "-p"], capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as exc:
        ctx.emit_output("stderr", "截屏失败: {}\n".format(exc))
        return 1
    if result.returncode != 0:
        ctx.emit_output("stderr", result.stderr.decode(errors="replace"))
        return result.returncode
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(result.stdout)
    ctx.emit_output("stdout", "✅ 截屏已保存: {}\n".format(out))
    return 0


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
    usage="gs android logcat.clear",
    examples=["gs android logcat.clear", "gs android logcat.clear --dry-run"],
    args=[{"name": "options", "type": "string", "variadic": True}],
)
def logcat_clear(ctx):
    # Clearing the volatile log buffer is explicitly approved for GS6.
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    if "--dry-run" in options:
        return _dry_run_only(ctx, "logcat.clear")
    return _run_adb(ctx, ["logcat", "-c"])


@plugin.command(
    name="logcat.tail",
    summary={"zh": "采样跟随 logcat（前 100 行）", "en": "Tail logcat (first 100 lines)"},
    usage="gs android logcat.tail [level]",
    examples=["gs android logcat.tail", "gs android logcat.tail *:W"],
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
    usage="gs android logcat.filter <keyword>",
    examples=["gs android logcat.filter ActivityManager"],
    args=[
        {"name": "keyword", "type": "string", "required": True,
         "description": {"zh": "包含关键字", "en": "Substring to match"}},
    ],
)
def logcat_filter(ctx):
    keyword = ctx.args.get("keyword")
    if not keyword:
        ctx.emit_output("stderr", "用法: gs android logcat.filter <keyword>\n")
        return 2
    return _sample_logcat(ctx, ["logcat", "-v", "time", "*:I"], limit=200, keyword=keyword)


# ---- dynamic completion: live device serials -------------------------------

@plugin.completer(source="device_serials")
def complete_serials(params):
    # Short TTL — the device set changes when you plug/unplug (spec §3.2 uses 5s).
    return {"values": [{"value": d} for d in _list_devices()], "ttl": 5}


# ---- emulator.* ------------------------------------------------------------

def _emulator_bin():
    """Locate the SDK ``emulator`` binary (common paths, $ANDROID_HOME, PATH)."""
    candidates = [
        os.path.expanduser("~/Library/Android/sdk/emulator/emulator"),
        os.path.expanduser("~/Android/Sdk/emulator/emulator"),
    ]
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if sdk:
        candidates.append(os.path.join(sdk, "emulator", "emulator"))
    for c in candidates:
        if os.path.isfile(c):
            return c
    return shutil.which("emulator")


def _list_avds():
    emu = _emulator_bin()
    if not emu:
        return []
    try:
        r = subprocess.run([emu, "-list-avds"], capture_output=True, text=True, timeout=10)
    except Exception:
        return []
    if r.returncode != 0:
        return []
    return [line.strip() for line in r.stdout.strip().splitlines() if line.strip()]


def _running_emulators():
    return [d for d in _list_devices() if d.startswith("emulator-")]


@plugin.command(
    name="emulator.list",
    summary={"zh": "列出可用模拟器", "en": "List available emulators"},
    usage="gs android emulator.list",
    examples=["gs android emulator.list"],
)
def emulator_list(ctx):
    if not _emulator_bin():
        ctx.emit_output("stderr", "未找到 emulator（装 Android SDK 并设 ANDROID_HOME）\n")
        return 1
    avds = _list_avds()
    if not avds:
        ctx.emit_output("stderr", "未找到 AVD（先在 Android Studio 创建）\n")
        return 1
    running = _running_emulators()
    lines = ["📱 可用模拟器:"] + ["  • {}".format(a) for a in avds]
    lines.append("\n🟢 运行中: {}".format(", ".join(running)) if running else "\n⚪ 无运行中的模拟器")
    ctx.emit_output("stdout", "\n".join(lines) + "\n")
    return 0


@plugin.command(
    name="emulator.start",
    summary={"zh": "启动模拟器", "en": "Start an emulator"},
    usage="gs android emulator.start [avd]",
    examples=["gs android emulator.start", "gs android emulator.start Pixel_6_API_34"],
    args=[
        {"name": "avd", "type": "string", "required": False,
         "description": {"zh": "AVD 名（缺省=第一个）", "en": "AVD name (default: first)"},
         "complete": {"kind": "dynamic", "source": "avds"}},
        {"name": "options", "type": "string", "variadic": True},
    ],
)
def emulator_start(ctx):
    emu = _emulator_bin()
    avds = _list_avds()
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    dry_run = "--dry-run" in options
    execute = "--yes" in options
    if dry_run == execute:
        ctx.emit_output("stderr", "emulator start 必须且只能指定 --dry-run 或 --yes\n")
        return 2
    avd = ctx.args.get("avd") or (avds[0] if avds else "<first-avd>")
    if ctx.args.get("avd") and avds and avd not in avds:
        ctx.emit_output("stderr", "AVD '{}' 不存在。可用: {}\n".format(avd, ", ".join(avds)))
        return 1
    if dry_run:
        ctx.emit_output("stdout", "Emulator start 计划（dry-run）\nBinary: {}\nAVD: {}\n运行中: {}\n不会启动进程\n".format(emu or "<emulator-not-found>", avd, ", ".join(_running_emulators()) or "无"))
        return 0
    if not emu or not avds:
        ctx.emit_output("stderr", "未找到 emulator 或 AVD\n")
        return 1
    try:
        process = subprocess.Popen([emu, "-avd", avd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, start_new_session=True)
    except OSError as exc:
        ctx.emit_output("stderr", "启动 emulator 失败: {}\n".format(exc))
        return 1
    ctx.emit_output("stdout", "Emulator 已启动\nAVD: {}\nPID: {}\n".format(avd, process.pid))
    return 0


@plugin.command(
    name="emulator.stop",
    summary={"zh": "停止模拟器", "en": "Stop running emulator(s)"},
    usage="gs android emulator.stop [serial]",
    examples=["gs android emulator.stop", "gs android emulator.stop emulator-5554"],
    args=[
        {"name": "serial", "type": "string", "required": False,
         "description": {"zh": "模拟器序列号（缺省=全部）", "en": "Emulator serial (default: all)"},
         "complete": {"kind": "dynamic", "source": "running_emulators"}},
        {"name": "options", "type": "string", "variadic": True},
    ],
)
def emulator_stop(ctx):
    running = _running_emulators()
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    dry_run = "--dry-run" in options
    execute = "--yes" in options
    if dry_run == execute:
        ctx.emit_output("stderr", "emulator stop 必须且只能指定 --dry-run 或 --yes\n")
        return 2
    target = ctx.args.get("serial")
    if target and target not in running:
        ctx.emit_output("stderr", "'{}' 不在运行列表: {}\n".format(target, ", ".join(running)))
        return 1
    targets = [target] if target else running
    if dry_run:
        ctx.emit_output("stdout", "Emulator stop 计划（dry-run）\nTargets: {}\n不会停止进程\n".format(", ".join(targets) or "无运行实例"))
        return 0
    rc = 0
    for serial in targets:
        rc |= _run_adb(ctx, ["-s", serial, "emu", "kill"], with_serial=False)
    return 1 if rc else 0


@plugin.command(
    name="emulator.restart",
    summary={"zh": "重启模拟器", "en": "Restart emulator"},
    usage="gs android emulator.restart [avd]",
    examples=["gs android emulator.restart"],
    args=[
        {"name": "avd", "type": "string", "required": False,
         "description": {"zh": "AVD 名", "en": "AVD name"},
         "complete": {"kind": "dynamic", "source": "avds"}},
        {"name": "options", "type": "string", "variadic": True},
    ],
)
def emulator_restart(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    dry_run = "--dry-run" in options
    execute = "--yes" in options
    if dry_run == execute:
        ctx.emit_output("stderr", "emulator restart 必须且只能指定 --dry-run 或 --yes\n")
        return 2
    avd = ctx.args.get("avd") or (_list_avds()[0] if _list_avds() else "<first-avd>")
    running = _running_emulators()
    if dry_run:
        ctx.emit_output("stdout", "Emulator restart 计划（dry-run）\nStop: {}\nStart AVD: {}\n不会停止或启动进程\n".format(", ".join(running) or "无运行实例", avd))
        return 0
    for serial in running:
        rc = _run_adb(ctx, ["-s", serial, "emu", "kill"], with_serial=False)
        if rc != 0:
            return rc
    ctx.args["avd"] = avd
    ctx.args["options"] = ["--yes"]
    return emulator_start(ctx)


@plugin.command(
    name="emulator.status",
    summary={"zh": "模拟器状态", "en": "Emulator status"},
    usage="gs android emulator.status",
    examples=["gs android emulator.status"],
)
def emulator_status(ctx):
    emu = _emulator_bin()
    if not emu:
        ctx.emit_output("stderr", "未找到 emulator\n")
        return 1
    avds, running = _list_avds(), _running_emulators()
    lines = ["📱 模拟器状态:", "   路径: {}".format(emu),
             "   AVD 总数: {}".format(len(avds)), "   运行中: {}".format(len(running))]
    if avds:
        lines += ["\n📋 可用 AVD:"] + ["   • {}".format(a) for a in avds]
    lines += (["\n🟢 运行中:"] + ["   • {}".format(s) for s in running]) if running else ["\n⚪ 无运行中的模拟器"]
    ctx.emit_output("stdout", "\n".join(lines) + "\n")
    return 0


@plugin.command(
    name="emulator.path",
    summary={"zh": "显示 emulator 路径", "en": "Show emulator path"},
    usage="gs android emulator.path",
    examples=["gs android emulator.path"],
)
def emulator_path(ctx):
    emu = _emulator_bin()
    if not emu:
        ctx.emit_output("stderr", "未找到 emulator\n")
        return 1
    ctx.emit_output("stdout", "emulator: {}\n".format(emu))
    return 0


@plugin.completer(source="avds")
def complete_avds(params):
    return {"values": [{"value": a} for a in _list_avds()], "ttl": 10}


@plugin.completer(source="running_emulators")
def complete_running_emulators(params):
    return {"values": [{"value": s} for s in _running_emulators()], "ttl": 5}


# ---- input.* ---------------------------------------------------------------

def _input_key(ctx, code):
    return _run_adb(ctx, ["shell", "input", "keyevent", code])


def _input_dry_run(ctx, label, command):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    if "--dry-run" not in options:
        return _run_adb(ctx, command[1:])
    ctx.emit_output("stdout", "Android input 计划（dry-run）\nCommand: {}\n不会向设备发送事件\n".format(" ".join(command)))
    return 0


@plugin.command(
    name="input.keyevent",
    summary={"zh": "发送按键事件", "en": "Send a keyevent"},
    usage="gs android input.keyevent <KEYCODE>",
    examples=["gs android input.keyevent 26"],
    args=[{"name": "keycode", "type": "string", "required": True,
           "description": {"zh": "键码", "en": "Keycode"}},
        {"name": "options", "type": "string", "variadic": True}],
)
def input_keyevent(ctx):
    code = ctx.args.get("keycode")
    if not code:
        ctx.emit_output("stderr", "用法: gs android input.keyevent <KEYCODE>\n")
        return 2
    return _input_dry_run(ctx, "input keyevent", ["adb", "shell", "input", "keyevent", str(code)])


@plugin.command(
    name="input.tap",
    summary={"zh": "点击坐标", "en": "Tap at coordinates"},
    usage="gs android input.tap <x> <y>",
    examples=["gs android input.tap 100 200"],
    args=[
        {"name": "x", "type": "string", "required": True, "description": {"zh": "X 坐标", "en": "X"}},
        {"name": "y", "type": "string", "required": True, "description": {"zh": "Y 坐标", "en": "Y"}},
        {"name": "options", "type": "string", "variadic": True},
    ],
)
def input_tap(ctx):
    x, y = ctx.args.get("x"), ctx.args.get("y")
    if x is None or y is None:
        ctx.emit_output("stderr", "用法: gs android input.tap <x> <y>\n")
        return 2
    if not str(x).isdigit() or not str(y).isdigit():
        ctx.emit_output("stderr", "坐标必须是非负整数\n")
        return 2
    return _input_dry_run(ctx, "input tap", ["adb", "shell", "input", "tap", str(x), str(y)])


@plugin.command(
    name="input.text",
    summary={"zh": "输入文本", "en": "Type text"},
    usage="gs android input.text <text...>",
    examples=["gs android input.text hello", "gs android input.text hello world"],
    args=[{"name": "text", "type": "string", "required": True, "variadic": True,
           "description": {"zh": "文本（多词自动合并）", "en": "Text (multiple words are joined)"}},
          {"name": "options", "type": "string", "variadic": True}],
)
def input_text(ctx):
    raw = ctx.args.get("text")
    if not raw:
        ctx.emit_output("stderr", "用法: gs android input.text <text...>\n")
        return 2
    if isinstance(raw, list):
        raw = " ".join(str(t) for t in raw)
    if len(str(raw)) > 500 or any(ord(ch) < 32 for ch in str(raw)):
        ctx.emit_output("stderr", "文本必须小于等于 500 字符且不能包含控制字符\n")
        return 2
    # Android `input text` wants spaces as %s.
    return _input_dry_run(ctx, "input text", ["adb", "shell", "input", "text", str(raw).replace(" ", "%s")])


@plugin.command(
    name="input.swipe",
    summary={"zh": "滑动手势", "en": "Swipe gesture"},
    usage="gs android input.swipe <x1> <y1> <x2> <y2> [duration_ms]",
    examples=["gs android input.swipe 100 100 300 300", "gs android input.swipe 100 100 300 300 500"],
    args=[
        {"name": "x1", "type": "string", "required": True},
        {"name": "y1", "type": "string", "required": True},
        {"name": "x2", "type": "string", "required": True},
        {"name": "y2", "type": "string", "required": True},
        {"name": "duration", "type": "string", "required": False,
         "description": {"zh": "时长 ms", "en": "duration ms"}},
        {"name": "options", "type": "string", "variadic": True},
    ],
)
def input_swipe(ctx):
    x1, y1, x2, y2 = (ctx.args.get(k) for k in ("x1", "y1", "x2", "y2"))
    if None in (x1, y1, x2, y2):
        ctx.emit_output("stderr", "用法: gs android input.swipe <x1> <y1> <x2> <y2> [duration_ms]\n")
        return 2
    if not all(str(v).isdigit() for v in (x1, y1, x2, y2)):
        ctx.emit_output("stderr", "坐标必须是非负整数\n")
        return 2
    cmd = ["adb", "shell", "input", "swipe", str(x1), str(y1), str(x2), str(y2)]
    if ctx.args.get("duration"):
        if not str(ctx.args["duration"]).isdigit() or int(ctx.args["duration"]) > 120000:
            ctx.emit_output("stderr", "duration 必须是 0..120000 的整数\n")
            return 2
        cmd.append(str(ctx.args["duration"]))
    return _input_dry_run(ctx, "input swipe", cmd)


@plugin.command(
    name="input.longpress",
    summary={"zh": "长按", "en": "Long press"},
    usage="gs android input.longpress <x> <y> [duration_ms]",
    examples=["gs android input.longpress 200 400", "gs android input.longpress 200 400 800"],
    args=[
        {"name": "x", "type": "string", "required": True},
        {"name": "y", "type": "string", "required": True},
        {"name": "duration", "type": "string", "required": False, "default": "700"},
        {"name": "options", "type": "string", "variadic": True},
    ],
)
def input_longpress(ctx):
    x, y = ctx.args.get("x"), ctx.args.get("y")
    if x is None or y is None:
        ctx.emit_output("stderr", "用法: gs android input.longpress <x> <y> [duration_ms]\n")
        return 2
    if not str(x).isdigit() or not str(y).isdigit():
        ctx.emit_output("stderr", "坐标必须是非负整数\n")
        return 2
    dur = str(ctx.args.get("duration") or "700")
    if not dur.isdigit() or int(dur) > 120000:
        ctx.emit_output("stderr", "duration 必须是 0..120000 的整数\n")
        return 2
    return _input_dry_run(ctx, "input longpress", ["adb", "shell", "input", "swipe", str(x), str(y), str(x), str(y), dur])


# Convenience key commands (KEYCODE_*), registered programmatically.
_INPUT_KEYS = [
    ("back", "4", {"zh": "返回键", "en": "Back"}),
    ("home", "3", {"zh": "主页键", "en": "Home"}),
    ("recent", "187", {"zh": "多任务键", "en": "Recents"}),
    ("power", "26", {"zh": "电源键", "en": "Power"}),
    ("volume_up", "24", {"zh": "音量+", "en": "Volume Up"}),
    ("volume_down", "25", {"zh": "音量-", "en": "Volume Down"}),
    ("enter", "66", {"zh": "回车", "en": "Enter"}),
    ("del", "67", {"zh": "删除", "en": "Delete"}),
    ("space", "62", {"zh": "空格", "en": "Space"}),
    ("menu", "82", {"zh": "菜单键", "en": "Menu"}),
]
for _kname, _kcode, _kdesc in _INPUT_KEYS:
    def _make_key(code):
        def handler(ctx):
            return _input_dry_run(ctx, "input." + code, ["adb", "shell", "input", "keyevent", code])
        return handler
    plugin.command(
        name="input." + _kname, summary=_kdesc,
        usage="gs android input." + _kname,
        args=[{"name": "options", "type": "string", "variadic": True}],
    )(_make_key(_kcode))


def _input_touch(ctx, enable):
    return _input_dry_run(ctx, "input.{}".format("enable" if enable else "disable"), ["adb", "shell", "settings", "put", "system", "touch_event", "1" if enable else "0"])


@plugin.command(
    name="input.disable",
    summary={"zh": "禁用触摸输入", "en": "Disable touch input"},
    usage="gs android input.disable",
    examples=["gs android input.disable --dry-run"],
    args=[{"name": "options", "type": "string", "variadic": True}],
)
def input_disable(ctx):
    return _input_touch(ctx, enable=False)


@plugin.command(
    name="input.enable",
    summary={"zh": "启用触摸输入", "en": "Enable touch input"},
    usage="gs android input.enable",
    examples=["gs android input.enable --dry-run"],
    args=[{"name": "options", "type": "string", "variadic": True}],
)
def input_enable(ctx):
    return _input_touch(ctx, enable=True)


@plugin.command(
    name="input.screenrecord",
    summary={"zh": "屏幕录制（限时）", "en": "Record screen (time-limited)"},
    usage="gs android input.screenrecord <filename> [seconds]",
    examples=["gs android input.screenrecord demo", "gs android input.screenrecord demo 15"],
    args=[
        {"name": "filename", "type": "string", "required": True,
         "description": {"zh": "输出名（不含扩展名）", "en": "Output name (no extension)"}},
        {"name": "seconds", "type": "string", "required": False, "default": "10",
         "description": {"zh": "录制秒数（默认 10）", "en": "Seconds (default 10)"}},
        {"name": "options", "type": "string", "variadic": True},
    ],
)
def input_screenrecord(ctx):
    fn = ctx.args.get("filename")
    if not fn:
        ctx.emit_output("stderr", "用法: gs android input.screenrecord <filename> [seconds]\n")
        return 2
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    dry_run = "--dry-run" in options
    execute = "--yes" in options
    if dry_run == execute:
        ctx.emit_output("stderr", "input screenrecord 必须且只能指定 --dry-run 或 --yes\n")
        return 2
    secs = str(ctx.args.get("seconds") or "10")
    if not secs.isdigit() or not 1 <= int(secs) <= 180:
        ctx.emit_output("stderr", "seconds 必须是 1..180 的整数\n")
        return 2
    limit = int(secs)
    if "/" in str(fn) or ".." in Path(str(fn)).parts:
        ctx.emit_output("stderr", "filename 不能包含路径穿越\n")
        return 2
    if dry_run:
        ctx.emit_output("stdout", "Screenrecord 计划（dry-run）\n文件: {}.mp4\n时长: {} 秒\n不会启动录屏\n".format(fn, limit))
        return 0
    device_path = "/sdcard/{}.mp4".format(fn)
    ctx.emit_progress(message="recording {}s".format(limit), stage="screenrecord")
    # The legacy `screenrecord` was unbounded (blocks until Ctrl+C). Under T2 a
    # one-shot invoke must terminate, so we pass --time-limit explicitly.
    rc = _run_adb(ctx, ["shell", "screenrecord", "--time-limit", str(limit), device_path],
                  timeout=limit + 30)
    if rc != 0:
        return rc
    local = _resolve_out(ctx, fn + ".mp4")
    rc2 = _run_adb(ctx, ["pull", device_path, local])
    if rc2 == 0:
        ctx.emit_output("stdout", "✅ 已保存 {}\n".format(local))
    return rc2


# ---- dump.* ----------------------------------------------------------------

@plugin.command(
    name="dump.battery",
    summary={"zh": "电池信息", "en": "Battery info"},
    usage="gs android dump.battery",
    examples=["gs android dump.battery"],
)
def dump_battery(ctx):
    return _run_adb(ctx, ["shell", "dumpsys", "battery"])


@plugin.command(
    name="dump.build",
    summary={"zh": "系统属性 getprop", "en": "System build properties"},
    usage="gs android dump.build",
    examples=["gs android dump.build"],
)
def dump_build(ctx):
    return _run_adb(ctx, ["shell", "getprop"])


@plugin.command(
    name="dump.top",
    summary={"zh": "进程 CPU 占用快照", "en": "Top processes snapshot"},
    usage="gs android dump.top [n]",
    examples=["gs android dump.top", "gs android dump.top 10"],
    args=[{"name": "n", "type": "string", "required": False, "default": "20",
           "description": {"zh": "行数", "en": "Line count"}}],
)
def dump_top(ctx):
    n = str(ctx.args.get("n") or "20")
    if not n.isdigit() or not 1 <= int(n) <= 500:
        ctx.emit_output("stderr", "n 必须是 1..500 的整数\n")
        return 2
    rc, out, _ = _adb_capture(
        ["shell", "sh", "-c", "(busybox top -bn1 || top -bn1) 2>/dev/null | head -n {}".format(n)])
    if rc == 0 and out.strip():
        ctx.emit_output("stdout", out)
        return 0
    return _run_adb(ctx, ["shell", "dumpsys", "cpuinfo"])


@plugin.command(
    name="dump.meminfo",
    summary={"zh": "内存信息", "en": "Memory info"},
    usage="gs android dump.meminfo [package]",
    examples=["gs android dump.meminfo", "gs android dump.meminfo com.example.app"],
    args=[{"name": "package", "type": "string", "required": False,
           "description": {"zh": "包名（可选）", "en": "Package (optional)"}}],
)
def dump_meminfo(ctx):
    pkg = ctx.args.get("package")
    if pkg and not _valid_package(pkg):
        ctx.emit_output("stderr", "包名包含非法字符\n")
        return 2
    return _run_adb(ctx, ["shell", "dumpsys", "meminfo"] + ([pkg] if pkg else []))


@plugin.command(
    name="dump.cpuinfo",
    summary={"zh": "CPU 信息", "en": "CPU info"},
    usage="gs android dump.cpuinfo",
    examples=["gs android dump.cpuinfo"],
)
def dump_cpuinfo(ctx):
    return _run_adb(ctx, ["shell", "dumpsys", "cpuinfo"])


@plugin.command(
    name="dump.activity",
    summary={"zh": "当前焦点 Activity", "en": "Current focused activity"},
    usage="gs android dump.activity",
    examples=["gs android dump.activity"],
)
def dump_activity(ctx):
    # ``dumpsys activity top`` can be megabytes and time out on real devices.
    # Query the lightweight window service and retain only the focused entries.
    rc, out, err = _adb_capture(["shell", "dumpsys", "window", "windows"], timeout=20)
    if rc != 0:
        ctx.emit_output("stderr", err or "无法读取当前焦点 Activity\n")
        return rc
    lines = [line for line in out.splitlines()
             if "mCurrentFocus=" in line or "mFocusedApp=" in line]
    if not lines:
        # Android 14+ may omit the legacy focus keys from ``dumpsys window``.
        # The activity service still exposes a compact resumed-activity record.
        rc2, out2, err2 = _adb_capture(["shell", "dumpsys", "activity", "activities"], timeout=20)
        if rc2 == 0:
            lines = [line for line in out2.splitlines()
                     if "topResumedActivity=" in line or "ResumedActivity:" in line]
    if not lines:
        ctx.emit_output("stderr", "未找到当前焦点 Activity\n")
        return 1
    ctx.emit_output("stdout", "\n".join(lines) + "\n")
    return 0


@plugin.command(
    name="dump.packages",
    summary={"zh": "列出已安装包", "en": "List installed packages"},
    usage="gs android dump.packages [keyword]",
    examples=["gs android dump.packages", "gs android dump.packages google"],
    args=[{"name": "keyword", "type": "string", "required": False,
           "description": {"zh": "过滤关键字", "en": "Filter keyword"}}],
)
def dump_packages(ctx):
    kw = ctx.args.get("keyword")
    if kw:
        rc, out, err = _adb_capture(["shell", "pm", "list", "packages", "-f"])
        if rc != 0:
            ctx.emit_output("stderr", err or "pm list packages 失败\n")
            return rc
        matched = [line for line in out.splitlines() if str(kw) in line]
        if matched:
            ctx.emit_output("stdout", "\n".join(matched) + "\n")
        return 0
    return _run_adb(ctx, ["shell", "pm", "list", "packages", "-f"])


@plugin.command(
    name="dump.appops",
    summary={"zh": "应用操作权限", "en": "App ops"},
    usage="gs android dump.appops <package>",
    examples=["gs android dump.appops com.example.app"],
    args=[{"name": "package", "type": "string", "required": True,
           "description": {"zh": "包名", "en": "Package"}}],
)
def dump_appops(ctx):
    pkg = ctx.args.get("package")
    if not pkg:
        ctx.emit_output("stderr", "用法: gs android dump.appops <package>\n")
        return 2
    if not _valid_package(pkg):
        ctx.emit_output("stderr", "包名包含非法字符\n")
        return 2
    return _run_adb(ctx, ["shell", "appops", "get", pkg])


# ---- proc.* ----------------------------------------------------------------

@plugin.command(
    name="proc.ps_grep",
    summary={"zh": "按关键字查进程", "en": "ps grep"},
    usage="gs android proc.ps_grep <keyword>",
    examples=["gs android proc.ps_grep zygote"],
    args=[{"name": "keyword", "type": "string", "required": True,
           "description": {"zh": "关键字", "en": "Keyword"}},
          {"name": "options", "type": "string", "variadic": True}],
)
def proc_ps_grep(ctx):
    kw = ctx.args.get("keyword")
    if not kw:
        ctx.emit_output("stderr", "用法: gs android proc.ps_grep <keyword>\n")
        return 2
    rc, out, err = _adb_capture(["shell", "ps"])
    if rc != 0:
        ctx.emit_output("stderr", err or "读取进程列表失败\n")
        return rc
    matched = [line for line in out.splitlines() if str(kw) in line]
    if matched:
        ctx.emit_output("stdout", "\n".join(matched) + "\n")
        return 0
    return 1


@plugin.command(
    name="proc.kill_grep",
    summary={"zh": "按关键字杀进程", "en": "Kill by grep"},
    usage="gs android proc.kill_grep <keyword>",
    examples=["gs android proc.kill_grep com.example.app"],
    args=[{"name": "keyword", "type": "string", "required": True,
           "description": {"zh": "关键字", "en": "Keyword"}},
          {"name": "options", "type": "string", "variadic": True}],
)
def proc_kill_grep(ctx):
    kw = ctx.args.get("keyword")
    if not kw:
        ctx.emit_output("stderr", "用法: gs android proc.kill_grep <keyword>\n")
        return 2
    rc, out, err = _adb_capture(["shell", "ps"])
    if rc != 0:
        ctx.emit_output("stderr", err or "读取进程列表失败\n")
        return rc
    pids = []
    for line in out.splitlines():
        columns = line.split()
        if str(kw) in line and len(columns) > 1 and columns[1].isdigit():
            pids.append(columns[1])
    if not pids:
        ctx.emit_output("stderr", "未找到匹配进程\n")
        return 1
    return _run_adb(ctx, ["shell", "kill"] + pids)


def _proc_am_event(ctx, event):
    pkg = ctx.args.get("package")
    if not pkg:
        ctx.emit_output("stderr", "用法: 需要 <package>\n")
        return 2
    if not _valid_package(pkg):
        ctx.emit_output("stderr", "包名包含非法字符\n")
        return 2
    esc = pkg.replace(".", r"\.")
    regex = "{0}.*{1}|{1}.*{0}".format(event, esc)
    # Mirrors the legacy: grep AM event traces saved under /data/local/tmp.
    sh = "cd /data/local/tmp && cat * 2>/dev/null | grep -E '{}'".format(regex)
    return _run_adb(ctx, ["shell", sh])


_AM_EVENTS = [
    ("am-proc-start", "am_proc_start", {"zh": "监控进程启动事件", "en": "Monitor process start events"}),
    ("am-proc-died", "am_proc_died", {"zh": "监控进程死亡事件", "en": "Monitor process died events"}),
    ("am-kill", "am_kill", {"zh": "监控进程被杀事件", "en": "Monitor process kill events"}),
    ("am-anr", "am_anr", {"zh": "监控 ANR 事件", "en": "Monitor ANR events"}),
]
for _aname, _aevent, _adesc in _AM_EVENTS:
    def _make_am(event):
        def handler(ctx):
            return _proc_am_event(ctx, event)
        return handler
    plugin.command(
        name="proc." + _aname, summary=_adesc,
        usage="gs android proc.{} <package>".format(_aname),
        args=[{"name": "package", "type": "string", "required": True,
               "description": {"zh": "包名", "en": "Package"}}],
    )(_make_am(_aevent))


# ---- surface.* -------------------------------------------------------------

@plugin.command(
    name="surface.show_refresh_rate",
    summary={"zh": "刷新率显示开关", "en": "Toggle refresh-rate overlay"},
    usage="gs android surface.show_refresh_rate <0|1>",
    examples=["gs android surface.show_refresh_rate 1", "gs android surface.show_refresh_rate 0"],
    args=[{"name": "toggle", "type": "enum", "required": True,
           "description": {"zh": "0=关 1=开", "en": "0=off 1=on"},
           "complete": {"kind": "enum", "values": ["0", "1"]}},
          {"name": "options", "type": "string", "variadic": True}],
)
def surface_show_refresh_rate(ctx):
    v = ctx.args.get("toggle")
    if v is None:
        ctx.emit_output("stderr", "用法: gs android surface.show_refresh_rate <0|1>\n")
        return 2
    return _run_adb(ctx, ["shell", "service", "call", "SurfaceFlinger", "1034", "i32", str(v)])


@plugin.command(
    name="surface.set_refresh_rate",
    summary={"zh": "设置刷新率", "en": "Set refresh rate"},
    usage="gs android surface.set_refresh_rate <rate>",
    examples=["gs android surface.set_refresh_rate 60", "gs android surface.set_refresh_rate 120"],
    args=[{"name": "rate", "type": "string", "required": True,
           "description": {"zh": "刷新率", "en": "Rate"}},
          {"name": "options", "type": "string", "variadic": True}],
)
def surface_set_refresh_rate(ctx):
    rate = ctx.args.get("rate")
    if not rate:
        ctx.emit_output("stderr", "用法: gs android surface.set_refresh_rate <rate>\n")
        return 2
    return _run_adb(ctx, ["shell", "service", "call", "SurfaceFlinger", "1035", "i32", str(rate)])


@plugin.command(
    name="surface.dump_refresh_rate",
    summary={"zh": "Dump 刷新率信息", "en": "Dump refresh info"},
    usage="gs android surface.dump_refresh_rate",
    examples=["gs android surface.dump_refresh_rate"],
)
def surface_dump_refresh_rate(ctx):
    return _run_adb(ctx, ["shell", "dumpsys", "SurfaceFlinger"])


# ---- fs.* ------------------------------------------------------------------

# Curated device path aliases (each value is a list of candidate locations;
# the first that exists on the device wins). Mirrors the legacy COMMON_PATHS.
_FS_COMMON_PATHS = {
    "framework": ["/system/framework/framework.jar"],
    "framework_ext": ["/system/framework/framework-ext.jar"],
    "services": ["/system/framework/services.jar"],
    "toybox": ["/system/bin/toybox"],
    "surfaceflinger": ["/system/bin/surfaceflinger"],
    "libandroid_runtime.so": ["/system/lib64/libandroid_runtime.so", "/system/lib/libandroid_runtime.so"],
    "libgui": ["/system/lib64/libgui.so", "/system/lib/libgui.so"],
    "libgpuservice": ["/system/lib64/libgpuservice.so", "/system/lib/libgpuservice.so"],
    "libinputflinger": ["/system/lib64/libinputflinger.so", "/system/lib/libinputflinger.so"],
    "libui": ["/system/lib64/libui.so", "/system/lib/libui.so"],
    "libbinder": ["/system/lib64/libbinder.so", "/system/lib/libbinder.so"],
    "framework_res": ["/system/framework/framework-res.apk"],
    "systemui_apk": ["/system/priv-app/SystemUI/SystemUI.apk",
                     "/product/priv-app/SystemUI/SystemUI.apk",
                     "/system_ext/priv-app/SystemUI/SystemUI.apk"],
    "settings_apk": ["/system/priv-app/Settings/Settings.apk",
                     "/product/priv-app/Settings/Settings.apk",
                     "/system_ext/priv-app/Settings/Settings.apk"],
    "bootanimation": ["/system/media/bootanimation.zip", "/product/media/bootanimation.zip"],
}
_FS_ALIASES = sorted(_FS_COMMON_PATHS.keys())


def _fs_exists(path):
    if not isinstance(path, str) or not path.startswith("/"):
        return False
    if any(ch in path for ch in "'\"`;$|&\n\r"):
        return False
    rc, _, _ = _adb_capture(["shell", "test", "-e", path])
    return rc == 0


def _fs_resolve_alias(name):
    entry = _FS_COMMON_PATHS.get(name)
    if not entry:
        return None
    for p in entry:
        if _fs_exists(p):
            return p
    return entry[0]


def _fs_transfer_plan(ctx, direction, local, remote):
    options = ctx.args.get("options") or []
    if isinstance(options, str):
        options = [options]
    local_path = Path(_resolve_out(ctx, local)).resolve()
    cwd = Path(ctx.cwd or os.getcwd()).resolve()
    if direction == "push" and not local_path.is_file():
        ctx.emit_output("stderr", "本地文件不存在: {}\n".format(local_path))
        return 1
    if direction == "pull":
        try:
            local_path.relative_to(cwd)
        except ValueError:
            ctx.emit_output("stderr", "拉取目标不能越出当前工作目录: {}\n".format(local_path))
            return 2
    if not str(remote).startswith("/"):
        ctx.emit_output("stderr", "设备路径必须是绝对路径或有效别名\n")
        return 2
    if "--dry-run" in options:
        ctx.emit_output("stdout", "Android fs {} 计划（dry-run）\nLocal: {}\nRemote: {}\n不会传输文件\n".format(direction, local_path, remote))
        return 0
    return _run_adb(ctx, [direction, str(local_path), remote] if direction == "push" else [direction, remote, str(local_path)])


@plugin.command(
    name="fs.push",
    summary={"zh": "推送文件到设备", "en": "Push a file to the device"},
    usage="gs android fs.push <local> <remote|alias>",
    examples=["gs android fs.push app.apk /sdcard/app.apk", "gs android fs.push ./framework.jar framework"],
    args=[
        {"name": "local", "type": "path", "required": True,
         "description": {"zh": "本地文件", "en": "Local file"}, "complete": {"kind": "file"}},
        {"name": "remote", "type": "string", "required": True,
         "description": {"zh": "设备路径或别名", "en": "Device path or alias"}},
        {"name": "options", "type": "string", "variadic": True},
    ],
)
def fs_push(ctx):
    local, remote = ctx.args.get("local"), ctx.args.get("remote")
    if not local or not remote:
        ctx.emit_output("stderr", "用法: gs android fs.push <local> <remote|alias>\n")
        return 2
    if remote in _FS_COMMON_PATHS:
        remote = _fs_resolve_alias(remote)
    return _fs_transfer_plan(ctx, "push", local, remote)


@plugin.command(
    name="fs.pull",
    summary={"zh": "从设备拉取文件", "en": "Pull a file from the device"},
    usage="gs android fs.pull <remote|alias> <local>",
    examples=["gs android fs.pull /sdcard/log.txt ./log.txt", "gs android fs.pull libgpuservice ./libgpuservice.so"],
    args=[
        {"name": "remote", "type": "string", "required": True,
         "description": {"zh": "设备路径或别名", "en": "Device path or alias"}},
        {"name": "local", "type": "path", "required": True,
         "description": {"zh": "本地目标", "en": "Local target"}, "complete": {"kind": "file"}},
        {"name": "options", "type": "string", "variadic": True},
    ],
)
def fs_pull(ctx):
    remote, local = ctx.args.get("remote"), ctx.args.get("local")
    if not remote or not local:
        ctx.emit_output("stderr", "用法: gs android fs.pull <remote|alias> <local>\n")
        return 2
    if remote in _FS_COMMON_PATHS:
        remote = _fs_resolve_alias(remote)
    return _fs_transfer_plan(ctx, "pull", local, remote)


@plugin.command(
    name="fs.common",
    summary={"zh": "展示常见路径映射", "en": "Show common path aliases"},
    usage="gs android fs.common",
    examples=["gs android fs.common"],
)
def fs_common(ctx):
    lines = ["{}: {}".format(k, ", ".join(v)) for k, v in _FS_COMMON_PATHS.items()]
    ctx.emit_output("stdout", "\n".join(lines) + "\n")
    return 0


@plugin.command(
    name="fs.resolve",
    summary={"zh": "解析别名到设备实际路径", "en": "Resolve an alias to an on-device path"},
    usage="gs android fs.resolve <name>",
    examples=["gs android fs.resolve libgui"],
    args=[{"name": "name", "type": "enum", "required": True,
           "description": {"zh": "别名", "en": "Alias"},
           "complete": {"kind": "enum", "values": _FS_ALIASES}}],
)
def fs_resolve(ctx):
    name = ctx.args.get("name")
    if not name:
        ctx.emit_output("stderr", "用法: gs android fs.resolve <name>\n")
        return 2
    path = _fs_resolve_alias(name)
    if not path:
        ctx.emit_output("stderr", "未知或无法解析的别名: {}\n".format(name))
        return 1
    ctx.emit_output("stdout", path + "\n")
    return 0


@plugin.command(
    name="fs.verify",
    summary={"zh": "校验常见路径在设备是否存在", "en": "Verify common paths on the device"},
    usage="gs android fs.verify",
    examples=["gs android fs.verify"],
)
def fs_verify(ctx):
    lines = []
    for k in _FS_ALIASES:
        resolved = _fs_resolve_alias(k)
        if resolved and _fs_exists(resolved):
            lines.append("[OK] {}: {}".format(k, resolved))
        else:
            lines.append("[--] {}: not found".format(k))
    ctx.emit_output("stdout", "\n".join(lines) + "\n")
    return 0


@plugin.command(
    name="fs.exists",
    summary={"zh": "检查设备路径是否存在", "en": "Check whether a device path exists"},
    usage="gs android fs.exists <path>",
    examples=["gs android fs.exists /system/bin/sh"],
    args=[{"name": "path", "type": "string", "required": True,
           "description": {"zh": "设备路径", "en": "Device path"}}],
)
def fs_exists(ctx):
    path = ctx.args.get("path")
    if not path:
        ctx.emit_output("stderr", "用法: gs android fs.exists <path>\n")
        return 2
    if not isinstance(path, str) or not path.startswith("/") or any(
        ch in path for ch in "'\"`;$|&\n\r"
    ):
        ctx.emit_output("stderr", "路径必须是安全的绝对设备路径\n")
        return 2
    ok = _fs_exists(path)
    ctx.emit_output("stdout", ("exists" if ok else "not found") + "\n")
    return 0 if ok else 1


@plugin.command(
    name="fs.push_common",
    summary={"zh": "推送文件到常见路径", "en": "Push a file to a common path"},
    usage="gs android fs.push_common <local> <name>",
    examples=["gs android fs.push_common ./framework.jar framework"],
    args=[
        {"name": "local", "type": "path", "required": True, "complete": {"kind": "file"},
         "description": {"zh": "本地文件", "en": "Local file"}},
        {"name": "name", "type": "enum", "required": True, "complete": {"kind": "enum", "values": _FS_ALIASES},
         "description": {"zh": "别名", "en": "Alias"}},
        {"name": "options", "type": "string", "variadic": True},
    ],
)
def fs_push_common(ctx):
    local, name = ctx.args.get("local"), ctx.args.get("name")
    if not local or not name:
        ctx.emit_output("stderr", "用法: gs android fs.push_common <local> <name>\n")
        return 2
    remote = _fs_resolve_alias(name)
    if not remote:
        ctx.emit_output("stderr", "未知别名: {}\n".format(name))
        return 1
    return _fs_transfer_plan(ctx, "push", local, remote)


@plugin.command(
    name="fs.pull_common",
    summary={"zh": "从常见路径拉取文件", "en": "Pull a file from a common path"},
    usage="gs android fs.pull_common <name> <local>",
    examples=["gs android fs.pull_common framework ./framework.jar"],
    args=[
        {"name": "name", "type": "enum", "required": True, "complete": {"kind": "enum", "values": _FS_ALIASES},
         "description": {"zh": "别名", "en": "Alias"}},
        {"name": "local", "type": "path", "required": True, "complete": {"kind": "file"},
         "description": {"zh": "本地目标", "en": "Local target"}},
        {"name": "options", "type": "string", "variadic": True},
    ],
)
def fs_pull_common(ctx):
    name, local = ctx.args.get("name"), ctx.args.get("local")
    if not name or not local:
        ctx.emit_output("stderr", "用法: gs android fs.pull_common <name> <local>\n")
        return 2
    remote = _fs_resolve_alias(name)
    if not remote:
        ctx.emit_output("stderr", "未知别名: {}\n".format(name))
        return 1
    return _fs_transfer_plan(ctx, "pull", local, remote)


@plugin.command(
    name="fs.find_apk",
    summary={"zh": "查找包名的 APK 路径", "en": "Find the APK path(s) for a package"},
    usage="gs android fs.find_apk <package>",
    examples=["gs android fs.find_apk com.android.settings"],
    args=[{"name": "package", "type": "string", "required": True,
           "description": {"zh": "包名", "en": "Package"},
           "complete": {"kind": "dynamic", "source": "packages"}}],
)
def fs_find_apk(ctx):
    pkg = ctx.args.get("package")
    if not pkg:
        ctx.emit_output("stderr", "用法: gs android fs.find_apk <package>\n")
        return 2
    if not _valid_package(pkg):
        ctx.emit_output("stderr", "包名包含非法字符\n")
        return 2
    rc, out, err = _adb_capture(["shell", "pm", "path", pkg])
    if rc != 0:
        ctx.emit_output("stderr", err or "pm path 失败\n")
        return rc
    paths = [line.split(":", 1)[1].strip() for line in out.splitlines() if ":" in line]
    ctx.emit_output("stdout", ("\n".join(paths) if paths else "") + "\n")
    return 0


@plugin.command(
    name="fs.locate_so",
    summary={"zh": "在常见目录定位 .so 库", "en": "Locate a .so library in common dirs"},
    usage="gs android fs.locate_so <libname.so>",
    examples=["gs android fs.locate_so libandroid_runtime.so"],
    args=[{"name": "lib", "type": "string", "required": True,
           "description": {"zh": "库名", "en": "Library name"}}],
)
def fs_locate_so(ctx):
    lib = ctx.args.get("lib")
    if not lib:
        ctx.emit_output("stderr", "用法: gs android fs.locate_so <libname.so>\n")
        return 2
    if any(ch in str(lib) for ch in "'\"`;$|&\n\r/") or not str(lib).endswith(".so"):
        ctx.emit_output("stderr", "库名必须是安全的 .so 文件名\n")
        return 2
    dirs = ["/system/lib64", "/system/lib", "/vendor/lib64", "/vendor/lib",
            "/product/lib64", "/product/lib", "/system_ext/lib64", "/system_ext/lib",
            "/apex/com.android.runtime/lib64", "/apex/com.android.runtime/lib"]
    query = " ; ".join("if [ -e '{0}/{1}' ]; then echo '{0}/{1}'; fi".format(d, lib) for d in dirs)
    # Single shell string (see _fs_exists): keeps the pipeline/`if` intact through adb.
    return _run_adb(ctx, ["shell", query])


@plugin.command(
    name="fs.ls",
    summary={"zh": "列出设备目录或文件", "en": "List a device directory or file"},
    usage="gs android fs.ls <path>",
    examples=["gs android fs.ls /system/bin"],
    args=[{"name": "path", "type": "string", "required": True,
           "description": {"zh": "设备路径", "en": "Device path"}}],
)
def fs_ls(ctx):
    path = ctx.args.get("path")
    if not path:
        ctx.emit_output("stderr", "用法: gs android fs.ls <path>\n")
        return 2
    if not isinstance(path, str) or not path.startswith("/") or any(
        ch in path for ch in "'\"`;$|&\n\r"
    ):
        ctx.emit_output("stderr", "路径必须是安全的绝对设备路径\n")
        return 2
    return _run_adb(ctx, ["shell", "ls", "-l", path])


# ---- system.* --------------------------------------------------------------

@plugin.command(
    name="system.selinux-disable",
    summary={"zh": "禁用 SELinux", "en": "Disable SELinux"},
    usage="gs android system.selinux-disable",
    examples=["gs android system.selinux-disable --dry-run"],
    args=[{"name": "options", "type": "string", "variadic": True}],
)
def system_selinux_disable(ctx):
    return _run_adb(ctx, ["shell", "setenforce", "0"])


@plugin.command(
    name="system.hidden-api-enable",
    summary={"zh": "启用 Hidden API 访问", "en": "Enable Hidden API access"},
    usage="gs android system.hidden-api-enable",
    examples=["gs android system.hidden-api-enable --dry-run"],
    args=[{"name": "options", "type": "string", "variadic": True}],
)
def system_hidden_api_enable(ctx):
    rc = _run_adb(ctx, ["shell", "settings", "put", "global", "hidden_api_policy_pre_p_apps", "1"])
    return rc or _run_adb(ctx, ["shell", "settings", "put", "global", "hidden_api_policy_p_apps", "1"])


@plugin.command(
    name="system.hidden-api-disable",
    summary={"zh": "禁用 Hidden API 访问", "en": "Disable Hidden API access"},
    usage="gs android system.hidden-api-disable",
    examples=["gs android system.hidden-api-disable --dry-run"],
    args=[{"name": "options", "type": "string", "variadic": True}],
)
def system_hidden_api_disable(ctx):
    rc = _run_adb(ctx, ["shell", "settings", "delete", "global", "hidden_api_policy_pre_p_apps"])
    return rc or _run_adb(ctx, ["shell", "settings", "delete", "global", "hidden_api_policy_p_apps"])


@plugin.command(
    name="system.settings-dump",
    summary={"zh": "Dump 所有 SettingsProvider 配置", "en": "Dump all SettingsProvider config"},
    usage="gs android system.settings-dump",
    examples=["gs android system.settings-dump"],
)
def system_settings_dump(ctx):
    return _run_adb(ctx, ["shell", "dumpsys", "settings"])


@plugin.command(
    name="system.remove-dex2oat",
    summary={"zh": "删除 dex2oat 缓存并重启", "en": "Remove dex2oat cache and reboot"},
    usage="gs android system.remove-dex2oat",
    examples=["gs android system.remove-dex2oat --dry-run"],
    args=[{"name": "options", "type": "string", "variadic": True}],
)
def system_remove_dex2oat(ctx):
    _run_adb(ctx, ["root"])
    _run_adb(ctx, ["remount"])
    for directory in ("/system/framework/oat", "/system/framework/arm", "/system/framework/arm64"):
        rc = _run_adb(ctx, ["shell", "rm", "-rf", directory])
        if rc != 0:
            return rc
    return _run_adb(ctx, ["reboot"])


@plugin.command(
    name="system.abx2xml",
    summary={"zh": "ABX 转 XML", "en": "Convert ABX to XML"},
    usage="gs android system.abx2xml <file_path>",
    examples=["gs android system.abx2xml /data/system/packages.xml"],
    args=[{"name": "file", "type": "string", "required": True,
           "description": {"zh": "设备文件路径", "en": "Device file path"}}],
)
def system_abx2xml(ctx):
    fp = ctx.args.get("file")
    if not fp:
        ctx.emit_output("stderr", "用法: gs android system.abx2xml <file_path>\n")
        return 2
    if not isinstance(fp, str) or not fp.startswith("/") or any(ch in fp for ch in "'\"`;$|&\n\r"):
        ctx.emit_output("stderr", "文件路径必须是安全的绝对设备路径\n")
        return 2
    return _run_adb(ctx, ["shell", "cat {} | abx2xml - -".format(fp)])


@plugin.command(
    name="system.imei",
    summary={"zh": "获取设备 IMEI", "en": "Get device IMEI"},
    usage="gs android system.imei",
    examples=["gs android system.imei"],
)
def system_imei(ctx):
    return _run_adb(ctx, ["shell", "service call iphonesubinfo 1 | cut -c 52-66 | tr -d '.[:space:]'"])


# ---- app.* -----------------------------------------------------------------

_PKG_ARG = {"name": "package", "type": "string", "required": True,
            "description": {"zh": "包名", "en": "Package"},
            "complete": {"kind": "dynamic", "source": "packages"}}


@plugin.command(
    name="app.list-3rd",
    summary={"zh": "列出第三方应用", "en": "List third-party apps"},
    usage="gs android app.list-3rd",
    examples=["gs android app.list-3rd"],
)
def app_list_3rd(ctx):
    return _run_adb(ctx, ["shell", "pm", "list", "packages", "-f", "-3"])


@plugin.command(
    name="app.list-system",
    summary={"zh": "列出系统应用", "en": "List system apps"},
    usage="gs android app.list-system",
    examples=["gs android app.list-system"],
)
def app_list_system(ctx):
    return _run_adb(ctx, ["shell", "pm", "list", "packages", "-f", "-s"])


def _app_version(ctx, pkg):
    if not _valid_package(pkg):
        ctx.emit_output("stderr", "包名包含非法字符\n")
        return 2
    rc, out, err = _adb_capture(["shell", "dumpsys", "package", pkg])
    if rc != 0:
        ctx.emit_output("stderr", err or "dumpsys package 失败\n")
        return rc
    vlines = [line for line in out.splitlines() if "version" in line.lower()]
    ctx.emit_output("stdout", ("\n".join(vlines) if vlines else out) + "\n")
    return 0


@plugin.command(
    name="app.version",
    summary={"zh": "获取应用版本信息", "en": "Get app version info"},
    usage="gs android app.version <package>",
    examples=["gs android app.version com.android.settings"],
    args=[_PKG_ARG, {"name": "options", "type": "string", "variadic": True}],
)
def app_version(ctx):
    pkg = ctx.args.get("package")
    if not pkg:
        ctx.emit_output("stderr", "用法: gs android app.version <package>\n")
        return 2
    return _app_version(ctx, pkg)


@plugin.command(
    name="app.kill",
    summary={"zh": "终止应用进程", "en": "Kill an app process"},
    usage="gs android app.kill <package>",
    examples=["gs android app.kill com.example.app"],
    args=[_PKG_ARG, {"name": "options", "type": "string", "variadic": True}],
)
def app_kill(ctx):
    pkg = ctx.args.get("package")
    if not pkg:
        ctx.emit_output("stderr", "用法: gs android app.kill <package>\n")
        return 2
    if not _valid_package(pkg):
        ctx.emit_output("stderr", "包名包含非法字符\n")
        return 2
    return _run_adb(ctx, ["shell", "am", "force-stop", pkg])


@plugin.command(
    name="app.clear",
    summary={"zh": "清除应用数据", "en": "Clear app data"},
    usage="gs android app.clear <package>",
    examples=["gs android app.clear com.example.app"],
    args=[_PKG_ARG, {"name": "options", "type": "string", "variadic": True}],
)
def app_clear(ctx):
    pkg = ctx.args.get("package")
    if not pkg:
        ctx.emit_output("stderr", "用法: gs android app.clear <package>\n")
        return 2
    if not _valid_package(pkg):
        ctx.emit_output("stderr", "包名包含非法字符\n")
        return 2
    return _run_adb(ctx, ["shell", "pm", "clear", pkg])


@plugin.command(
    name="app.log",
    summary={"zh": "显示应用日志（dump 模式）", "en": "Show app logs (dump mode)"},
    usage="gs android app.log <package>",
    examples=["gs android app.log com.example.app"],
    args=[_PKG_ARG],
)
def app_log(ctx):
    pkg = ctx.args.get("package")
    if not pkg:
        ctx.emit_output("stderr", "用法: gs android app.log <package>\n")
        return 2
    if not _valid_package(pkg):
        ctx.emit_output("stderr", "包名包含非法字符\n")
        return 2
    rc, out, _ = _adb_capture(["shell", "pidof", pkg])
    pids = out.split()
    if rc != 0 or not pids:
        ctx.emit_output("stderr", "未找到进程: {}\n".format(pkg))
        return 1
    # `-d`: dump existing logs and exit. The legacy followed forever (`logcat
    # --pid`), which would hang a one-shot T2 invoke.
    return _run_adb(ctx, ["shell", "logcat", "-d", "--pid={}".format(pids[0])])


@plugin.command(
    name="app.version-settings",
    summary={"zh": "获取设置应用版本", "en": "Get Settings app version"},
    usage="gs android app.version-settings",
    examples=["gs android app.version-settings"],
)
def app_version_settings(ctx):
    return _app_version(ctx, "com.android.settings")


@plugin.completer(source="packages")
def complete_packages(params):
    rc, out, _ = _adb_capture(["shell", "pm", "list", "packages"], timeout=5)
    if rc != 0:
        return {"values": []}
    pkgs = [line[len("package:"):].strip() for line in out.splitlines() if line.startswith("package:")]
    return {"values": [{"value": p} for p in pkgs], "ttl": 30}


# ---- shared helpers for asset-backed subplugins (perfetto/winscope/frida) ---

# Heavy assets (perfetto config, 12MB Winscope HTML, frida .js + binaries) are
# NOT copied — android references them in the legacy plugin tree so a fresh
# checkout stays small and the two ports share one source of truth.
_LEGACY_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "android"))
_FRIDA_RELEASES = "https://github.com/frida/frida/releases"


def _legacy_dir(sub):
    return os.path.join(_LEGACY_ROOT, sub)


def _find_asset(ctx, name, sub):
    """Locate an asset by priority: absolute path → user cwd → legacy plugin dir."""
    if os.path.isabs(name):
        return name if os.path.exists(name) else None
    cwd_candidate = _resolve_out(ctx, name)
    if os.path.exists(cwd_candidate):
        return cwd_candidate
    legacy_candidate = os.path.join(_legacy_dir(sub), name)
    if os.path.exists(legacy_candidate):
        return legacy_candidate
    return None


def _list_files(dirpath, ext):
    try:
        return sorted(f for f in os.listdir(dirpath) if f.endswith(ext))
    except OSError:
        return []


def _human_size(n):
    if n > 1024 * 1024:
        return "{:.1f}MB".format(n / 1024 / 1024)
    if n > 1024:
        return "{:.1f}KB".format(n / 1024)
    return "{}B".format(n)


def _open_command():
    for c in ("open", "xdg-open", "start"):
        if shutil.which(c):
            return c
    return None


def _adb_input(ctx, extra, data, with_serial=True, timeout=120):
    """Run adb feeding ``data`` (bytes) on stdin; stream output, return rc.
    Used by perfetto to pipe a config to ``perfetto -c -``."""
    if not _adb_exists():
        ctx.emit_output("stderr", "未找到 adb，请先安装 Android Platform Tools\n")
        return 127
    cmd = _adb_base(with_serial) + extra
    try:
        r = subprocess.run(cmd, input=data, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired:
        ctx.emit_output("stderr", "adb 超时: {}\n".format(" ".join(cmd)))
        return 124
    except Exception as e:  # noqa: BLE001
        ctx.emit_output("stderr", "adb 执行异常: {}\n".format(e))
        return 1
    if r.stdout:
        ctx.emit_output("stdout", r.stdout.decode("utf-8", "ignore"))
    if r.stderr:
        ctx.emit_output("stderr", r.stderr.decode("utf-8", "ignore"))
    return r.returncode


def _run_local_stream(ctx, argv, timeout=None):
    """Stream a *local* (non-adb) subprocess line-by-line. Used for the
    foreground Winscope proxy, which runs until the user interrupts it."""
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1)
    except FileNotFoundError:
        ctx.emit_output("stderr", "未找到命令: {}\n".format(argv[0]))
        return 127
    except Exception as e:  # noqa: BLE001
        ctx.emit_output("stderr", "执行异常: {}\n".format(e))
        return 1
    deadline = (time.monotonic() + timeout) if timeout else None
    try:
        for line in proc.stdout:  # type: ignore[union-attr]
            ctx.emit_output("stdout", line)
            if deadline and time.monotonic() > deadline:
                proc.terminate()
                break
    except KeyboardInterrupt:
        proc.terminate()
    return proc.wait()


# ---- perfetto.* ------------------------------------------------------------

@plugin.command(
    name="perfetto.trace",
    summary={"zh": "使用配置文件采集并拉取 trace", "en": "Collect a trace with a config file and pull it"},
    usage="gs android perfetto.trace [-f <config.pbtx>] [out_file]",
    examples=["gs android perfetto.trace -f config.pbtx trace.perfetto-trace",
              "gs android perfetto.trace trace.perfetto-trace"],
    args=[
        {"name": "config", "type": "path", "flag": "-f",
         "description": {"zh": "Perfetto 配置(pbtx/txt)", "en": "Perfetto config (pbtx/txt)"},
         "complete": {"kind": "file"}},
        {"name": "out", "type": "path", "required": False,
         "description": {"zh": "输出文件", "en": "Output file"}, "complete": {"kind": "file"}},
        {"name": "options", "type": "string", "variadic": True},
    ],
)
def perfetto_trace(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str): options = [options]
    config_arg = ctx.args.get("config")
    if config_arg:
        config_path = _find_asset(ctx, config_arg, "perfetto")
    else:
        config_path = os.path.join(_legacy_dir("perfetto"), "config.pbtx")
    if not config_path or not os.path.exists(config_path):
        ctx.emit_output("stderr", "配置文件未找到: {}\n".format(config_arg or "config.pbtx"))
        return 1
    out_file = Path(_resolve_out(ctx, ctx.args.get("out") or "trace.perfetto-trace")).resolve()
    cwd = Path(ctx.cwd or os.getcwd()).resolve()
    try:
        out_file.relative_to(cwd)
    except ValueError:
        ctx.emit_output("stderr", "trace 输出不能越出当前工作目录\n")
        return 2
    if out_file.suffix not in (".trace", ".perfetto-trace"):
        ctx.emit_output("stderr", "trace 输出扩展名必须是 .trace 或 .perfetto-trace\n")
        return 2
    if "--dry-run" in options:
        ctx.emit_output("stdout", "Config: {}\nOutput: {}\nDuration: config-defined\n".format(Path(config_path).resolve(), out_file)); return 0
    with open(config_path, "rb") as fh: data = fh.read()
    remote = "/data/misc/perfetto-traces/trace.perfetto-trace"
    rc = _adb_input(ctx, ["shell", "perfetto", "-c", "-", "--txt", "-o", remote], data, timeout=180)
    if rc != 0: return rc
    return _run_adb(ctx, ["pull", remote, str(out_file)])


@plugin.command(
    name="perfetto.default",
    summary={"zh": "快速采集常用事件 20s", "en": "Quick 20s trace of common categories"},
    usage="gs android perfetto.default [out_file]",
    examples=["gs android perfetto.default", "gs android perfetto.default quick.perfetto-trace"],
    args=[{"name": "out", "type": "path", "required": False,
           "description": {"zh": "输出文件", "en": "Output file"}, "complete": {"kind": "file"}},
          {"name": "options", "type": "string", "variadic": True}],
)
def perfetto_default(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str): options = [options]
    out_file = Path(_resolve_out(ctx, ctx.args.get("out") or "trace.perfetto-trace")).resolve()
    cwd = Path(ctx.cwd or os.getcwd()).resolve()
    try:
        out_file.relative_to(cwd)
    except ValueError:
        ctx.emit_output("stderr", "trace 输出不能越出当前工作目录\n")
        return 2
    if out_file.suffix not in (".trace", ".perfetto-trace"):
        ctx.emit_output("stderr", "trace 输出扩展名必须是 .trace 或 .perfetto-trace\n")
        return 2
    cats = ["sched", "freq", "idle", "am", "wm", "gfx", "view", "binder_driver",
            "hal", "dalvik", "camera", "input", "res", "memory"]
    if "--dry-run" in options:
        ctx.emit_output("stdout", "Output: {}\nDuration: 20s\nCategories: {}\n".format(out_file, ", ".join(cats))); return 0
    remote = "/data/misc/perfetto-traces/trace.perfetto-trace"
    rc = _run_adb(ctx, ["shell", "perfetto", "-o", remote, "-t", "20s"] + cats, timeout=60)
    if rc != 0: return rc
    return _run_adb(ctx, ["pull", remote, str(out_file)])


# ---- winscope.* ------------------------------------------------------------

def _winscope_start(ctx, html_name):
    html_path = _find_asset(ctx, html_name, "winscope")
    if not html_path:
        avail = _list_files(_legacy_dir("winscope"), ".html")
        ctx.emit_output("stderr", "HTML 文件未找到: {}\n可用: {}\n".format(html_name, ", ".join(avail)))
        return 1
    options = ctx.args.get("options") or []
    if isinstance(options, str): options = [options]
    dry_run = "--dry-run" in options
    execute = "--yes" in options
    if dry_run == execute:
        ctx.emit_output("stderr", "winscope start 必须且只能指定 --dry-run 或 --yes\n")
        return 2
    if dry_run:
        ctx.emit_output("stdout", "Winscope start 计划（dry-run）\nHTML: {}\n不会启动浏览器或代理\n".format(html_path))
        return 0
    open_cmd = _open_command()
    if not open_cmd:
        ctx.emit_output("stderr", "未找到打开 HTML 的命令(open/xdg-open/start)\n")
        return 1
    # Background launches MUST detach stdio, or the core (which reads the
    # plugin's stdout to EOF) blocks until the browser/proxy exits.
    try:
        subprocess.Popen([open_cmd, html_path], stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
    except Exception as e:  # noqa: BLE001
        ctx.emit_output("stderr", "启动 Winscope 失败: {}\n".format(e))
        return 1
    ctx.emit_output("stdout", "✅ Winscope 已启动: {}\n".format(html_path))
    proxy = os.path.join(_legacy_dir("winscope"), "winscope_proxy.py")
    if os.path.exists(proxy):
        try:
            subprocess.Popen([sys.executable, proxy], stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
            ctx.emit_output("stdout", "🌐 代理服务器已启动\n")
        except Exception as e:  # noqa: BLE001
            ctx.emit_output("stdout", "⚠️ 代理服务器启动失败: {}\n".format(e))
    else:
        ctx.emit_output("stdout", "⚠️ 未找到代理脚本，部分功能不可用\n")
    return 0


@plugin.command(
    name="winscope.start",
    summary={"zh": "启动 Winscope UI 分析工具", "en": "Start the Winscope UI analysis tool"},
    usage="gs android winscope.start [-f <html_file>]",
    examples=["gs android winscope.start", "gs android winscope.start -f winscope-aosp.html"],
    args=[{"name": "html", "type": "path", "flag": "-f",
           "description": {"zh": "HTML 文件", "en": "HTML file"}, "complete": {"kind": "file"}},
          {"name": "options", "type": "string", "variadic": True}],
)
def winscope_start(ctx):
    return _winscope_start(ctx, ctx.args.get("html") or "winscope.html")


@plugin.command(
    name="winscope.aosp",
    summary={"zh": "启动 AOSP 版 Winscope", "en": "Start the AOSP-version Winscope"},
    usage="gs android winscope.aosp",
    examples=["gs android winscope.aosp --dry-run"],
    args=[{"name": "options", "type": "string", "variadic": True}],
)
def winscope_aosp(ctx):
    return _winscope_start(ctx, "winscope-aosp.html")


@plugin.command(
    name="winscope.proxy",
    summary={"zh": "前台启动代理服务器", "en": "Start the proxy server in the foreground"},
    usage="gs android winscope.proxy",
    examples=["gs android winscope.proxy --dry-run"],
    args=[{"name": "options", "type": "string", "variadic": True}],
)
def winscope_proxy(ctx):
    proxy = os.path.join(_legacy_dir("winscope"), "winscope_proxy.py")
    if not os.path.exists(proxy):
        ctx.emit_output("stderr", "未找到代理脚本: {}\n".format(proxy))
        return 1
    options = ctx.args.get("options") or []
    if isinstance(options, str): options = [options]
    dry_run = "--dry-run" in options
    execute = "--yes" in options
    if dry_run == execute:
        ctx.emit_output("stderr", "winscope proxy 必须且只能指定 --dry-run 或 --yes\n")
        return 2
    if dry_run:
        ctx.emit_output("stdout", "Winscope proxy 计划（dry-run）\nProxy: {}\n不会启动进程\n".format(proxy))
        return 0
    try:
        process = subprocess.Popen([sys.executable, proxy], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, start_new_session=True)
    except OSError as exc:
        ctx.emit_output("stderr", "启动 Winscope proxy 失败: {}\n".format(exc))
        return 1
    ctx.emit_output("stdout", "Winscope proxy 已启动\nPID: {}\nProxy: {}\n".format(process.pid, proxy))
    return 0


@plugin.command(
    name="winscope.files",
    summary={"zh": "列出可用的 HTML 文件", "en": "List available HTML files"},
    usage="gs android winscope.files",
    examples=["gs android winscope.files"],
)
def winscope_files(ctx):
    cwd = ctx.cwd or os.getcwd()
    wdir = _legacy_dir("winscope")
    lines = ["📁 可用的 Winscope HTML 文件:", "=" * 35, "", "📁 当前目录 ({}):".format(cwd)]
    cwd_htmls = _list_files(cwd, ".html")
    if cwd_htmls:
        for h in cwd_htmls:
            lines.append("  • {} ({})".format(h, _human_size(os.path.getsize(os.path.join(cwd, h)))))
    else:
        lines.append("  📭 未找到 HTML 文件")
    lines += ["", "📁 插件目录 ({}):".format(wdir)]
    pdir_htmls = _list_files(wdir, ".html")
    if pdir_htmls:
        for h in pdir_htmls:
            tag = " (AOSP 版)" if "aosp" in h.lower() else ""
            lines.append("  • {} ({}){}".format(h, _human_size(os.path.getsize(os.path.join(wdir, h))), tag))
    else:
        lines.append("  📭 未找到 HTML 文件")
    ctx.emit_output("stdout", "\n".join(lines) + "\n")
    return 0


@plugin.command(
    name="winscope.status",
    summary={"zh": "检查 Winscope 环境状态", "en": "Check the Winscope environment status"},
    usage="gs android winscope.status",
    examples=["gs android winscope.status"],
)
def winscope_status(ctx):
    wdir = _legacy_dir("winscope")
    proxy = os.path.join(wdir, "winscope_proxy.py")
    oc = _open_command()
    lines = ["🔍 Winscope 环境状态:", "=" * 30,
             ("✅ 浏览器打开命令: {}".format(oc) if oc else "❌ 未找到浏览器打开命令"),
             "✅ Python: {}".format(sys.version.split()[0]),
             "✅ 插件目录 HTML 文件数: {}".format(len(_list_files(wdir, ".html"))),
             ("✅ 代理脚本可用" if os.path.exists(proxy) else "⚠️ 未找到代理脚本"),
             ("✅ adb 可用" if _adb_exists() else "⚠️ 未找到 adb")]
    ctx.emit_output("stdout", "\n".join(lines) + "\n")
    return 0


# ---- frida.* ---------------------------------------------------------------

def _frida_inject_bin():
    return os.path.join(_legacy_dir("frida"), "frida-inject")


def _frida_server_bin():
    return os.path.join(_legacy_dir("frida"), "frida-server")


def _extract_js_desc(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            head = f.read(500)
    except OSError:
        return None
    for line in head.split("\n")[:10]:
        s = line.strip()
        if s.startswith("//") and len(line) > 10:
            return s[2:].strip()
    return None


@plugin.command(
    name="frida.inject",
    summary={"zh": "注入 JavaScript 脚本到进程", "en": "Inject a JavaScript script into a process"},
    usage="gs android frida.inject -p <process> -f <script.js>",
    examples=["gs android frida.inject -p system_server -f android-trace.js",
              "gs android frida.inject -p com.example.app -f hook.js"],
    args=[
        {"name": "process", "type": "string", "flag": "-p", "default": "system_server",
         "description": {"zh": "进程名(默认 system_server)", "en": "Process name (default system_server)"},
         "complete": {"kind": "dynamic", "source": "packages"}},
        {"name": "script", "type": "path", "flag": "-f", "required": True,
         "description": {"zh": "JavaScript 文件", "en": "JavaScript file"}, "complete": {"kind": "file"}},
        {"name": "options", "type": "string", "variadic": True},
    ],
)
def frida_inject(ctx):
    options = ctx.args.get("options") or []
    if isinstance(options, str): options = [options]
    process = ctx.args.get("process") or "system_server"
    script = ctx.args.get("script")
    if not script:
        ctx.emit_output("stderr", "必须指定 JavaScript 文件(-f)\n")
        return 2
    if not re.fullmatch(r"[A-Za-z0-9_.$:-]+", str(process)):
        ctx.emit_output("stderr", "进程名包含非法字符\n")
        return 2
    js_path = _find_asset(ctx, script, "frida")
    if not js_path:
        avail = _list_files(_legacy_dir("frida"), ".js")
        ctx.emit_output("stderr", "JS 文件未找到: {}\n可用: {}\n".format(script, ", ".join(avail)))
        return 1
    device_js = "/data/local/frida/" + os.path.basename(js_path)
    if "--dry-run" in options:
        ctx.emit_output("stdout", "Process: {}\nScript: {}\nDevice script: {}\n".format(process, Path(js_path).resolve(), device_js))
        return 0
    inject_bin = _frida_inject_bin()
    if not os.path.isfile(inject_bin):
        ctx.emit_output("stderr", "未找到本地 frida-inject: {}\n".format(inject_bin))
        return 1
    prc, pout, _ = _adb_capture(["shell", "pidof", process])
    pids = pout.split()
    if prc != 0 or not pids:
        ctx.emit_output("stderr", "进程未找到: {}\n".format(process))
        return 1
    _run_adb(ctx, ["shell", "mkdir", "-p", "/data/local/frida"])
    rc = _run_adb(ctx, ["push", js_path, device_js])
    if rc != 0: return rc
    # Injection is intentionally bounded: frida-inject stays attached unless
    # the script exits, which would otherwise hang a one-shot GS invocation.
    rc, out, err = _adb_capture(
        ["shell", "/data/local/frida/frida-inject", "-p", pids[0], "-s", device_js, "--eternalize"],
        timeout=20,
    )
    if out:
        ctx.emit_output("stdout", out)
    if err:
        ctx.emit_output("stderr", err)
    if '"type":"error"' in out or '"type": "error"' in out:
        return 1
    return rc


@plugin.command(
    name="frida.server",
    summary={"zh": "管理 frida-server", "en": "Manage frida-server"},
    usage="gs android frida.server <start|stop|status>",
    examples=["gs android frida.server start", "gs android frida.server status"],
    args=[{"name": "action", "type": "enum", "required": False, "default": "start",
           "description": {"zh": "操作", "en": "Action"},
           "complete": {"kind": "enum", "values": ["start", "stop", "status"]}},
          {"name": "options", "type": "string", "variadic": True}],
)
def frida_server(ctx):
    action = ctx.args.get("action") or "start"
    options = ctx.args.get("options") or []
    if isinstance(options, str): options = [options]
    if action != "status" and "--dry-run" in options:
        return _dry_run_only(ctx, "frida.server {}".format(action))
    if action == "start":
        rc, out, _ = _adb_capture(["shell", "pgrep", "frida-server"])
        if rc == 0 and out.strip():
            ctx.emit_output("stdout", "frida-server 已在运行\n")
            return 0
        binp = _frida_server_bin()
        if not os.path.exists(binp):
            ctx.emit_output("stderr", "未找到 frida-server: {}\n请从 {} 下载并放入 {}/\n".format(
                binp, _FRIDA_RELEASES, _legacy_dir("frida")))
            return 1
        _adb_capture(["root"])
        _adb_capture(["remount"])
        _adb_capture(["shell", "mkdir", "-p", "/data/local/frida"])
        drc, _, _ = _adb_capture(["shell", "test", "-x", "/data/local/frida/frida-server"])
        if drc != 0:
            rc = _run_adb(ctx, ["push", binp, "/data/local/frida/frida-server"])
            if rc != 0:
                return rc
            rc = _run_adb(ctx, ["shell", "chmod", "a+x", "/data/local/frida/frida-server"])
            if rc != 0:
                return rc
        # Redirect device-side stdio so `&` truly detaches (else adb holds the
        # connection open and the one-shot call hangs).
        _adb_capture(["shell", "/data/local/frida/frida-server >/dev/null 2>&1 &"], timeout=10)
        ctx.emit_output("stdout", "✅ frida-server 已启动\n")
        return 0
    if action in ("stop", "kill"):
        _run_adb(ctx, ["shell", "pkill", "frida"])
        ctx.emit_output("stdout", "✅ frida-server 已停止\n")
        return 0
    if action == "status":
        rc, out, _ = _adb_capture(["shell", "pgrep", "frida-server"])
        if rc == 0 and out.strip():
            ctx.emit_output("stdout", "✅ frida-server 运行中 (PID: {})\n".format(", ".join(out.split())))
        else:
            ctx.emit_output("stdout", "⚠️ frida-server 未运行\n")
        return 0
    ctx.emit_output("stderr", "未知操作: {}\n可用: start, stop, status\n".format(action))
    return 2


@plugin.command(
    name="frida.scripts",
    summary={"zh": "列出可用的 JavaScript 脚本", "en": "List available JavaScript scripts"},
    usage="gs android frida.scripts",
    examples=["gs android frida.scripts"],
)
def frida_scripts(ctx):
    cwd = ctx.cwd or os.getcwd()
    fdir = _legacy_dir("frida")
    lines = ["📜 可用的 Frida JavaScript 脚本:", "=" * 40, "", "📁 当前目录 ({}):".format(cwd)]
    cjs = _list_files(cwd, ".js")
    if cjs:
        for j in cjs:
            p = os.path.join(cwd, j)
            lines.append("  • {} ({})".format(j, _human_size(os.path.getsize(p))))
            d = _extract_js_desc(p)
            if d:
                lines.append("    └─ {}".format(d))
    else:
        lines.append("  📭 未找到 JavaScript 文件")
    lines += ["", "📁 插件目录 ({}):".format(fdir)]
    pjs = _list_files(fdir, ".js")
    if pjs:
        for j in pjs:
            p = os.path.join(fdir, j)
            lines.append("  • {} ({})".format(j, _human_size(os.path.getsize(p))))
            d = _extract_js_desc(p)
            if d:
                lines.append("    └─ {}".format(d))
    else:
        lines.append("  📭 未找到 JavaScript 文件")
    ctx.emit_output("stdout", "\n".join(lines) + "\n")
    return 0


@plugin.command(
    name="frida.status",
    summary={"zh": "检查 Frida 环境状态", "en": "Check the Frida environment status"},
    usage="gs android frida.status",
    examples=["gs android frida.status"],
)
def frida_status(ctx):
    lines = ["🔍 Frida 环境状态:", "=" * 30]
    dev = _active_device()
    if dev:
        lines.append("✅ 设备已连接: {}".format(dev))
        ib = _frida_inject_bin()
        lines.append("✅ frida-inject 可用 ({})".format(_human_size(os.path.getsize(ib)))
                     if os.path.exists(ib) else "❌ 未找到 frida-inject")
        sb = _frida_server_bin()
        lines.append("✅ frida-server 可用 ({})".format(_human_size(os.path.getsize(sb)))
                     if os.path.exists(sb) else "⚠️ 未找到 frida-server")
        rc, out, _ = _adb_capture(["shell", "pgrep", "frida-server"])
        if rc == 0 and out.strip():
            lines.append("✅ 设备上 frida-server 运行中 (PID: {})".format(", ".join(out.split())))
        else:
            lines.append("⚠️ 设备上 frida-server 未运行")
        drc, _, _ = _adb_capture(["shell", "test", "-x", "/data/local/frida/frida-inject"])
        lines.append("✅ 设备上已安装 frida-inject" if drc == 0 else "⚠️ 设备上未安装 frida-inject")
    else:
        lines.append("❌ 未检测到 Android 设备")
    cwd = ctx.cwd or os.getcwd()
    lines += ["", "📜 JavaScript 文件:",
              "  当前目录: {} 个".format(len(_list_files(cwd, ".js"))),
              "  插件目录: {} 个".format(len(_list_files(_legacy_dir("frida"), ".js")))]
    ctx.emit_output("stdout", "\n".join(lines) + "\n")
    return 0


@plugin.command(
    name="doctor",
    summary={"zh": "检查 Android 插件开发环境", "en": "Check the Android plugin environment"},
    usage="gs android doctor",
    examples=["gs android doctor"],
)
def android_doctor(ctx):
    adb = shutil.which("adb")
    devices = _list_devices() if adb else []
    sdk = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
    emulator = _emulator_bin()
    checks = [
        (bool(adb), "adb", adb or "not found"),
        (bool(devices), "device", ", ".join(devices) if devices else "not connected (offline checks available)"),
        (bool(sdk), "Android SDK", sdk or "ANDROID_SDK_ROOT/ANDROID_HOME not set"),
        (bool(emulator), "emulator", emulator or "not found"),
        (os.path.isdir(_legacy_dir("winscope")), "Winscope assets", _legacy_dir("winscope")),
        (os.path.isdir(_legacy_dir("frida")), "Frida assets", _legacy_dir("frida")),
        (os.path.exists(os.path.join(_legacy_dir("perfetto"), "config.pbtx")),
         "Perfetto config", os.path.join(_legacy_dir("perfetto"), "config.pbtx")),
    ]
    lines = ["Android GS 6.0 doctor"]
    for ok, name, detail in checks:
        lines.append("[{}] {:16} {}".format("OK" if ok else "--", name + ":", detail))
    lines.append("结果: 可离线开发" if adb else "结果: 缺少 adb")
    ctx.emit_output("stdout", "\n".join(lines) + "\n")
    return 0 if adb else 1


if __name__ == "__main__":
    raise SystemExit(plugin.run())
