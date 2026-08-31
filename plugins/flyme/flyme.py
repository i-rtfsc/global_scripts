#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""FlymeOS development helper migrated from the GS 5.2 userspace plugin."""

from __future__ import annotations

import os
import sys

_SDK = os.path.join(os.path.dirname(__file__), "..", "..", "sdk", "python")
if os.path.isdir(_SDK):
    sys.path.insert(0, os.path.abspath(_SDK))

from gs_plugin import Plugin  # noqa: E402


plugin = Plugin(name="flyme")


@plugin.command(
    name="build",
    summary={"zh": "构建 FlymeOS 固件", "en": "Build FlymeOS firmware"},
    usage="gs flyme build [target]",
    examples=["gs flyme build", "gs flyme build m1892"],
    args=[
        {
            "name": "target",
            "type": "string",
            "description": {"zh": "目标设备，默认 all", "en": "Device target; defaults to all"},
        }
    ],
)
def build(ctx):
    target = str(ctx.args.get("target") or "all")
    ctx.emit_output(
        "stdout",
        "FlymeOS 构建功能\n目标设备: {}\n这是兼容 GS 5.2 的示例功能，实际构建需要配置相关环境\n".format(target),
    )
    return 0


@plugin.command(
    name="flash",
    summary={"zh": "刷写 FlymeOS 固件到设备", "en": "Flash FlymeOS firmware"},
    usage="gs flyme flash <firmware_path>",
    examples=["gs flyme flash ./flyme_build.zip"],
    args=[
        {
            "name": "firmware_path",
            "type": "file",
            "required": True,
            "description": {"zh": "固件路径", "en": "Firmware path"},
            "complete": {"kind": "file"},
        }
    ],
)
def flash(ctx):
    firmware = str(ctx.args.get("firmware_path") or "")
    ctx.emit_output(
        "stdout",
        "FlymeOS 刷写功能\n固件路径: {}\n这是兼容 GS 5.2 的示例功能，不会写入设备\n".format(firmware),
    )
    return 0


@plugin.command(
    name="info",
    summary={"zh": "显示 FlymeOS 插件信息", "en": "Show FlymeOS plugin information"},
    usage="gs flyme info",
    examples=["gs flyme info"],
)
def info(ctx):
    ctx.emit_output(
        "stdout",
        "FlymeOS Development Plugin\n功能: 构建、刷写 FlymeOS 固件\nGS6 保留了 5.2 示例插件的行为\n",
    )
    return 0


if __name__ == "__main__":
    plugin.run()
