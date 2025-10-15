#!/usr/bin/env python3
"""
Python Simple Plugin Example
纯Python插件示例 - 演示Python装饰器的使用
"""

from gscripts.plugins.decorators import plugin_function

@plugin_function(
    name="status",
    description="显示Python插件状态信息",
    usage="gs python-simple status",
    examples=["gs python-simple status"]
)
async def status():
    """显示插件状态"""
    print("✅ python-simple Status | Type: Pure Python | Implementation: Python decorators | Active: ✅")

@plugin_function(
    name="info", 
    description="显示Python插件基本信息",
    usage="gs python-simple info",
    examples=["gs python-simple info"]
)
async def info():
    """显示插件信息"""
    print("📋 python-simple Info | Type: Pure Python | Features: Decorators only | No shell/JSON dependencies")

@plugin_function(
    name="demo",
    description="演示Python插件功能",
    usage="gs python-simple demo", 
    examples=["gs python-simple demo"]
)
async def demo():
    """演示功能"""
    print("🎯 python-simple Demo | Language: Python | Decorators: ✅ | Async Support: ✅")
