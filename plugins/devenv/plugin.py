#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DevEnv Plugin - Development Environment Manager
快速安装和配置开发工具
"""

import sys
import json
import platform
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

# 添加项目根目录到 Python 路径
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.base import BasePlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.models.result import CommandResult
from gscripts.core.logger import get_logger
from gscripts.cli.formatters import OutputFormatter
from gscripts.utils.rich_table import RichTableFormatter

logger = get_logger(tag="PLUGIN.DEVENV", name=__name__)


class DevEnvPlugin(BasePlugin):
    """开发环境管理插件"""

    def __init__(self):
        self.name = "devenv"
        self.plugin_dir = Path(__file__).parent
        self.config_dir = self.plugin_dir / "config"

        # 加载配置
        raw_tools_config = self._load_json(self.config_dir / "tools.json")
        self.presets_config = self._load_json(self.config_dir / "presets.json")

        # 合并 tools_required 和 tools_optional 到统一的 tools 字典
        self.tools_config = {"tools": {}}
        if "tools_required" in raw_tools_config:
            self.tools_config["tools"].update(raw_tools_config["tools_required"])
        if "tools_optional" in raw_tools_config:
            self.tools_config["tools"].update(raw_tools_config["tools_optional"])
        # 兼容旧格式（直接使用 tools 键）
        if "tools" in raw_tools_config and not ("tools_required" in raw_tools_config or "tools_optional" in raw_tools_config):
            self.tools_config = raw_tools_config

        # 检测平台
        self.platform, self.package_manager = self._detect_platform()

        logger.info(f"DevEnv initialized: platform={self.platform}, pm={self.package_manager}")

    def _load_json(self, file_path: Path) -> Dict:
        """加载JSON配置文件"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load {file_path}: {e}")
            return {}

    def _detect_platform(self) -> tuple:
        """检测操作系统和包管理器"""
        system = platform.system()

        if system == "Darwin":
            return "macos", "brew"
        elif system == "Linux":
            # 检测发行版
            if Path("/etc/debian_version").exists():
                return "linux", "apt"
            elif Path("/etc/redhat-release").exists():
                return "linux", "yum"
            else:
                return "linux", "unknown"
        else:
            return "unknown", "unknown"

    async def _check_installed(self, tool_name: str) -> bool:
        """检查工具是否已安装"""
        tool_config = self.tools_config.get("tools", {}).get(tool_name)
        if not tool_config:
            return False

        platform_config = tool_config.get(self.platform)
        if not platform_config:
            return False

        check_cmd = platform_config.get("check")
        if not check_cmd:
            return False

        try:
            result = subprocess.run(
                check_cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False

    async def _install_tool(self, tool_name: str) -> CommandResult:
        """安装单个工具"""
        tool_config = self.tools_config.get("tools", {}).get(tool_name)
        if not tool_config:
            return CommandResult(
                success=False,
                error=f"工具 '{tool_name}' 不存在"
            )

        # 检查是否已安装
        if await self._check_installed(tool_name):
            return CommandResult(
                success=True,
                output=f"✅ {tool_config['name']} 已安装"
            )

        # 获取平台配置
        platform_config = tool_config.get(self.platform)
        if not platform_config:
            return CommandResult(
                success=False,
                error=f"工具 '{tool_name}' 不支持当前平台 {self.platform}"
            )

        # 检查是否为系统自带工具
        method = platform_config.get("method")
        if method == "preinstalled":
            return CommandResult(
                success=False,
                error=f"⚠️  {tool_config['name']} 是系统自带工具，无需安装（或已移除）"
            )

        # 执行安装
        logger.info(f"Installing {tool_name}...")

        if method == "brew":
            package = platform_config.get("package")
            is_cask = platform_config.get("cask", False)
            cmd = f"brew install {'--cask ' if is_cask else ''}{package}"
        elif method == "apt":
            package = platform_config.get("package")
            cmd = f"sudo apt-get update && sudo apt-get install -y {package}"
        elif method == "script":
            cmd = platform_config.get("install_script")
        else:
            return CommandResult(
                success=False,
                error=f"不支持的安装方式: {method}"
            )

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=600
            )

            if result.returncode != 0:
                return CommandResult(
                    success=False,
                    error=f"安装失败: {result.stderr.decode('utf-8', errors='ignore')}"
                )

            # 执行后置命令
            post_install = platform_config.get("post_install", [])
            for post_cmd in post_install:
                subprocess.run(post_cmd, shell=True, timeout=60)

            # 验证安装
            if await self._check_installed(tool_name):
                return CommandResult(
                    success=True,
                    output=f"✅ {tool_config['name']} 安装成功"
                )
            else:
                return CommandResult(
                    success=False,
                    error=f"安装后验证失败: {tool_name}"
                )

        except subprocess.TimeoutExpired:
            return CommandResult(
                success=False,
                error=f"安装超时: {tool_name}"
            )
        except Exception as e:
            return CommandResult(
                success=False,
                error=f"安装异常: {str(e)}"
            )

    async def _install_preset(self, preset_name: str, skip_optional: bool = False) -> CommandResult:
        """安装预设环境"""
        preset = self.presets_config.get("presets", {}).get(preset_name)
        if not preset:
            return CommandResult(
                success=False,
                error=f"预设 '{preset_name}' 不存在"
            )

        # 如果预设包含其他预设
        if "includes" in preset:
            results = []
            for sub_preset in preset["includes"]:
                result = await self._install_preset(sub_preset, skip_optional)
                results.append(f"{sub_preset}: {'✅' if result.success else '❌'}")

            return CommandResult(
                success=True,
                output="\\n".join(results)
            )

        # 安装工具列表
        tools = preset.get("tools", [])
        results = []
        failed = []

        for tool_name in tools:
            tool_config = self.tools_config.get("tools", {}).get(tool_name, {})
            is_required = tool_config.get("required", False)

            # 跳过可选工具
            if skip_optional and not is_required:
                logger.info(f"⏭️  跳过可选工具: {tool_name}")
                continue

            result = await self._install_tool(tool_name)
            if result.success:
                results.append(f"✅ {tool_name}")
            else:
                failed.append(f"❌ {tool_name}: {result.error}")
                results.append(f"❌ {tool_name}")

        output = "\\n".join(results)
        if failed:
            output += "\\n\\n失败列表:\\n" + "\\n".join(failed)

        return CommandResult(
            success=len(failed) == 0,
            output=output
        )

    @plugin_function(
        name="list",
        description={"zh": "列出所有可安装工具", "en": "List all available tools"},
        usage="gs devenv list [--required|--optional]",
        examples=[
            "gs devenv list",
            "gs devenv list --required",
            "gs devenv list --optional"
        ]
    )
    async def list_tools(self, args: List[str] = None) -> CommandResult:
        """列出所有工具"""
        args = args or []
        show_required_only = "--required" in args
        show_optional_only = "--optional" in args

        tools = self.tools_config.get("tools", {})

        # 准备表格数据
        headers = ["类型", "工具ID", "名称", "分类", "描述"]
        rows = []

        for tool_name, tool_config in sorted(tools.items()):
            is_required = tool_config.get("required", False)

            # 过滤
            if show_required_only and not is_required:
                continue
            if show_optional_only and is_required:
                continue

            # 类型标记
            type_marker = "✅ 必选" if is_required else "⭐ 可选"

            # 获取工具信息
            name = tool_config.get("name", tool_name)
            category = tool_config.get("category", "")
            desc = tool_config.get("description", {})
            desc_text = desc.get("zh", desc.get("en", ""))

            rows.append([type_marker, tool_name, name, category, desc_text])

        # 使用表格格式化器
        table_formatter = RichTableFormatter()
        table_output = table_formatter.draw_table(headers, rows)

        return CommandResult(
            success=True,
            output=table_output
        )

    @plugin_function(
        name="status",
        description={"zh": "查看工具安装状态", "en": "Check tool installation status"},
        usage="gs devenv status [tool_name] [--required|--optional]",
        examples=[
            "gs devenv status",
            "gs devenv status jdk",
            "gs devenv status --required",
            "gs devenv status --optional"
        ]
    )
    async def check_status(self, args: List[str] = None) -> CommandResult:
        """查看安装状态"""
        args = args or []

        # 检查是否指定了单个工具
        tool_name = None
        show_required_only = "--required" in args
        show_optional_only = "--optional" in args

        for arg in args:
            if not arg.startswith("--"):
                tool_name = arg
                break

        if tool_name:
            # 检查单个工具
            is_installed = await self._check_installed(tool_name)
            tool_config = self.tools_config.get("tools", {}).get(tool_name, {})
            name = tool_config.get("name", tool_name)

            if is_installed:
                output = f"✅ {name} - 已安装"
            else:
                output = f"❌ {name} - 未安装"

            return CommandResult(success=True, output=output)

        # 检查所有工具
        tools = self.tools_config.get("tools", {})
        headers = ["类型", "状态", "工具ID", "名称", "安装状态"]
        rows = []

        for tool_name, tool_config in sorted(tools.items()):
            is_required = tool_config.get("required", False)

            # 过滤
            if show_required_only and not is_required:
                continue
            if show_optional_only and is_required:
                continue

            is_installed = await self._check_installed(tool_name)
            type_marker = "✅ 必选" if is_required else "⭐ 可选"
            status_marker = "✅" if is_installed else "❌"
            name = tool_config.get("name", tool_name)
            status = "已安装" if is_installed else "未安装"

            rows.append([type_marker, status_marker, tool_name, name, status])

        # 使用表格格式化器
        table_formatter = RichTableFormatter()
        table_output = table_formatter.draw_table(headers, rows)

        return CommandResult(
            success=True,
            output=table_output
        )

    @plugin_function(
        name="check",
        description={"zh": "环境检查", "en": "Environment check"},
        usage="gs devenv check [--all]",
        examples=[
            "gs devenv check",
            "gs devenv check --all"
        ]
    )
    async def check_env(self, args: List[str] = None) -> CommandResult:
        """环境检查"""
        args = args or []
        check_all = "--all" in args

        tools = self.tools_config.get("tools", {})
        missing_required = []
        missing_optional = []
        installed_required = []
        installed_optional = []

        for tool_name, tool_config in tools.items():
            is_required = tool_config.get("required", False)
            is_installed = await self._check_installed(tool_name)

            if is_installed:
                if is_required:
                    installed_required.append(tool_name)
                else:
                    installed_optional.append(tool_name)
            else:
                if is_required:
                    missing_required.append(tool_name)
                else:
                    missing_optional.append(tool_name)

        # 构建输出
        output_parts = []

        # 平台信息
        output_parts.append(f"📍 平台: {self.platform}")
        output_parts.append(f"📦 包管理器: {self.package_manager}")
        output_parts.append("")

        # 必选工具状态表格
        if missing_required or installed_required:
            output_parts.append("✅ 必选工具状态:")
            headers = ["状态", "工具ID", "备注"]
            rows = []

            for tool in sorted(installed_required):
                rows.append(["✅", tool, "已安装"])
            for tool in sorted(missing_required):
                rows.append(["❌", tool, "未安装"])

            table_formatter = RichTableFormatter()
            table_output = table_formatter.draw_table(headers, rows)
            output_parts.append(table_output)
            output_parts.append("")

        # 统计信息
        total_required = len(installed_required) + len(missing_required)
        output_parts.append(f"📊 必选工具: {len(installed_required)}/{total_required} 已安装")

        # 可选工具（如果使用 --all）
        if check_all and (missing_optional or installed_optional):
            output_parts.append("")
            output_parts.append("⭐ 可选工具状态:")
            headers = ["状态", "工具ID", "备注"]
            rows = []

            for tool in sorted(installed_optional):
                rows.append(["✅", tool, "已安装"])
            for tool in sorted(missing_optional):
                rows.append(["❌", tool, "未安装"])

            table_formatter = RichTableFormatter()
            table_output = table_formatter.draw_table(headers, rows)
            output_parts.append(table_output)
            output_parts.append("")

            total_optional = len(installed_optional) + len(missing_optional)
            output_parts.append(f"📊 可选工具: {len(installed_optional)}/{total_optional} 已安装")

        return CommandResult(
            success=len(missing_required) == 0,
            output="\\n".join(output_parts)
        )

    @plugin_function(
        name="install",
        description={"zh": "安装工具或预设环境", "en": "Install tools or presets"},
        usage="gs devenv install <tool|preset> [--required-only]",
        examples=[
            "gs devenv install jdk",
            "gs devenv install full-required",
            "gs devenv install full-dev --required-only"
        ]
    )
    async def install(self, args: List[str] = None) -> CommandResult:
        """安装工具或预设"""
        if not args:
            return CommandResult(
                success=False,
                error="请指定要安装的工具或预设\\n使用 'gs devenv list' 查看可用工具"
            )

        target = args[0]
        skip_optional = '--required-only' in args or '--skip-optional' in args

        # 检查是预设还是单个工具
        if target in self.presets_config.get("presets", {}):
            return await self._install_preset(target, skip_optional)
        elif target in self.tools_config.get("tools", {}):
            return await self._install_tool(target)
        else:
            return CommandResult(
                success=False,
                error=f"未找到工具或预设: {target}"
            )

    @plugin_function(
        name="presets",
        description={"zh": "列出所有预设环境", "en": "List all presets"},
        usage="gs devenv presets",
        examples=["gs devenv presets"]
    )
    async def list_presets(self, args: List[str] = None) -> CommandResult:
        """列出所有预设"""
        presets = self.presets_config.get("presets", {})

        headers = ["类型", "预设名称", "显示名称", "描述", "包含内容"]
        rows = []

        for preset_name, preset_config in sorted(presets.items()):
            is_required = preset_config.get("required", False)
            type_marker = "✅ 必选" if is_required else "⭐ 可选"
            name = preset_config.get("name", preset_name)
            desc = preset_config.get("description", {})
            desc_text = desc.get("zh", desc.get("en", ""))

            # 构建包含内容
            if "includes" in preset_config:
                content = f"预设: {', '.join(preset_config['includes'])}"
            elif "tools" in preset_config:
                tool_count = len(preset_config['tools'])
                content = f"{tool_count}个工具"
            else:
                content = "N/A"

            rows.append([type_marker, preset_name, name, desc_text, content])

        # 使用表格格式化器
        table_formatter = RichTableFormatter()
        table_output = table_formatter.draw_table(headers, rows)

        return CommandResult(
            success=True,
            output=table_output
        )

    async def _check_package_availability(self, tool_name: str, platform_config: dict, method: str, platform: str) -> tuple:
        """检查包是否在包管理器中可用（不安装）

        Returns:
            (is_available: bool, message: str)
        """
        import re

        if method == "brew":
            package = platform_config.get("package")
            is_cask = platform_config.get("cask", False)
            if is_cask:
                cmd = f"brew info --cask {package} 2>&1"
            else:
                cmd = f"brew info {package} 2>&1"

        elif method == "apt":
            package = platform_config.get("package", "")
            # 只检查第一个包名
            first_package = package.split()[0] if package else ""
            if not first_package:
                return False, "包名为空"
            cmd = f"apt-cache show {first_package} 2>&1"

        elif method == "script":
            # 对于 script 方法，尝试检查常见的包管理器
            install_script = platform_config.get("install_script", "")

            # 检查 npm 包
            if "npm install -g" in install_script:
                match = re.search(r'npm install -g\s+(@?[\w/-]+)', install_script)
                if match:
                    package = match.group(1)
                    cmd = f"npm view {package} version 2>&1"
                else:
                    return None, "无法解析npm包名"

            # 检查 pip 包
            elif "pip3 install" in install_script or "pip install" in install_script:
                match = re.search(r'pip3? install\s+([\w-]+)', install_script)
                if match:
                    package = match.group(1)
                    cmd = f"pip3 index versions {package} 2>&1"
                else:
                    return None, "无法解析pip包名"

            # 其他脚本方法无法验证
            else:
                return None, "script方法无法自动验证"

        elif method == "preinstalled":
            return None, "系统预装工具"

        else:
            return None, "未知安装方法"

        # 只在当前平台检查
        if platform != self.platform:
            return None, f"跳过非当前平台 ({self.platform})"

        try:
            result = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30
            )

            output = result.stdout.decode('utf-8', errors='ignore') + result.stderr.decode('utf-8', errors='ignore')

            # 根据不同的包管理器判断
            if method == "brew":
                if result.returncode == 0 or "stable" in output.lower() or "version" in output.lower():
                    return True, "包可用"
                elif "No available formula" in output or "No such file" in output:
                    return False, f"Homebrew中不存在包: {package}"
                else:
                    return False, f"检查失败: {output[:100]}"

            elif method == "apt":
                if result.returncode == 0 or "Package:" in output:
                    return True, "包可用"
                elif "Unable to locate package" in output or "No packages found" in output:
                    return False, f"APT源中不存在包: {first_package}"
                else:
                    return False, f"检查失败: {output[:100]}"

            elif "npm" in cmd:
                if result.returncode == 0 and output.strip():
                    return True, f"npm包可用 (版本: {output.strip()[:20]})"
                elif "404" in output or "not found" in output.lower():
                    return False, f"npm中不存在包: {package}"
                else:
                    return False, f"检查失败: {output[:100]}"

            elif "pip" in cmd:
                if "Available versions:" in output or result.returncode == 0:
                    return True, "pip包可用"
                elif "No matching distribution" in output or "not find" in output.lower():
                    return False, f"PyPI中不存在包: {package}"
                else:
                    return False, f"检查失败: {output[:100]}"

            else:
                return None, "无法判断结果"

        except subprocess.TimeoutExpired:
            return False, "检查超时"
        except Exception as e:
            return False, f"检查异常: {str(e)}"

    @plugin_function(
        name="validate",
        description={"zh": "验证工具配置（不执行安装）", "en": "Validate tool configurations (dry-run)"},
        usage="gs devenv validate [--verbose] [--check-availability]",
        examples=[
            "gs devenv validate",
            "gs devenv validate --verbose",
            "gs devenv validate --check-availability"
        ]
    )
    async def validate(self, args: List[str] = None) -> CommandResult:
        """验证所有工具配置的正确性"""
        args = args or []
        verbose = "--verbose" in args
        check_availability = "--check-availability" in args

        tools = self.tools_config.get("tools", {})
        presets = self.presets_config.get("presets", {})

        errors = []
        warnings = []
        availability_errors = []
        availability_warnings = []
        validated_tools = 0

        # 验证工具配置
        for tool_name, tool_config in tools.items():
            validated_tools += 1

            # 检查必需字段
            if "name" not in tool_config:
                errors.append(f"❌ {tool_name}: 缺少 'name' 字段")

            if "description" not in tool_config:
                errors.append(f"❌ {tool_name}: 缺少 'description' 字段")

            if "category" not in tool_config:
                warnings.append(f"⚠️  {tool_name}: 缺少 'category' 字段")

            # 检查平台配置
            has_platform_config = False
            for platform in ["macos", "linux"]:
                if platform in tool_config:
                    has_platform_config = True
                    platform_config = tool_config[platform]

                    # 检查安装方法
                    method = platform_config.get("method")
                    if not method:
                        errors.append(f"❌ {tool_name}.{platform}: 缺少 'method' 字段")
                    elif method not in ["brew", "apt", "script", "preinstalled"]:
                        errors.append(f"❌ {tool_name}.{platform}: 不支持的方法 '{method}'")

                    # 检查 check 命令
                    if "check" not in platform_config:
                        errors.append(f"❌ {tool_name}.{platform}: 缺少 'check' 命令")

                    # 检查安装配置
                    if method == "brew":
                        if "package" not in platform_config:
                            errors.append(f"❌ {tool_name}.{platform}: brew 方法缺少 'package' 字段")
                    elif method == "apt":
                        if "package" not in platform_config:
                            errors.append(f"❌ {tool_name}.{platform}: apt 方法缺少 'package' 字段")
                    elif method == "script":
                        if "install_script" not in platform_config:
                            errors.append(f"❌ {tool_name}.{platform}: script 方法缺少 'install_script' 字段")

                    # 检查 fallback 配置
                    if "fallback" in platform_config:
                        fallback = platform_config["fallback"]
                        if "method" not in fallback:
                            warnings.append(f"⚠️  {tool_name}.{platform}.fallback: 缺少 'method' 字段")
                        if fallback.get("method") == "script" and "install_script" not in fallback:
                            warnings.append(f"⚠️  {tool_name}.{platform}.fallback: 缺少 'install_script' 字段")

                    # 深度检查：验证包可用性
                    if check_availability and method:
                        is_available, msg = await self._check_package_availability(
                            tool_name, platform_config, method, platform
                        )

                        if is_available is False:
                            # 检查是否有 fallback
                            if "fallback" in platform_config:
                                fallback_method = platform_config["fallback"].get("method")
                                fallback_available, fallback_msg = await self._check_package_availability(
                                    tool_name, platform_config["fallback"], fallback_method, platform
                                )
                                if fallback_available is False:
                                    availability_errors.append(
                                        f"❌ {tool_name}.{platform}: 主方法和备用方法都不可用\n"
                                        f"   主方法: {msg}\n"
                                        f"   备用方法: {fallback_msg}"
                                    )
                                elif fallback_available is True:
                                    availability_warnings.append(
                                        f"⚠️  {tool_name}.{platform}: 主方法不可用但备用方法可用\n"
                                        f"   主方法: {msg}\n"
                                        f"   备用方法: {fallback_msg}"
                                    )
                            else:
                                availability_errors.append(f"❌ {tool_name}.{platform}: {msg}")
                        elif is_available is None and verbose:
                            availability_warnings.append(f"ℹ️  {tool_name}.{platform}: {msg}")

            if not has_platform_config:
                errors.append(f"❌ {tool_name}: 没有任何平台配置")

        # 验证预设配置
        validated_presets = 0
        for preset_name, preset_config in presets.items():
            validated_presets += 1

            # 检查必需字段
            if "name" not in preset_config:
                errors.append(f"❌ preset '{preset_name}': 缺少 'name' 字段")

            if "description" not in preset_config:
                errors.append(f"❌ preset '{preset_name}': 缺少 'description' 字段")

            # 检查内容
            has_content = False
            if "tools" in preset_config:
                has_content = True
                # 验证工具是否存在
                for tool_name in preset_config["tools"]:
                    if tool_name not in tools:
                        errors.append(f"❌ preset '{preset_name}': 引用了不存在的工具 '{tool_name}'")

            if "includes" in preset_config:
                has_content = True
                # 验证预设是否存在
                for sub_preset in preset_config["includes"]:
                    if sub_preset not in presets:
                        errors.append(f"❌ preset '{preset_name}': 引用了不存在的预设 '{sub_preset}'")

            if not has_content:
                errors.append(f"❌ preset '{preset_name}': 没有 'tools' 或 'includes' 字段")

        # 构建输出
        output_parts = []
        output_parts.append("🔍 配置验证报告")
        output_parts.append("=" * 60)
        output_parts.append("")

        # 统计信息
        output_parts.append(f"📦 已验证工具: {validated_tools} 个")
        output_parts.append(f"🎨 已验证预设: {validated_presets} 个")
        if check_availability:
            output_parts.append(f"🔎 包可用性检查: 已启用 (当前平台: {self.platform})")
        output_parts.append(f"🔴 配置错误: {len(errors)}")
        output_parts.append(f"🟡 配置警告: {len(warnings)}")
        if check_availability:
            output_parts.append(f"🔴 可用性错误: {len(availability_errors)}")
            output_parts.append(f"🟡 可用性警告: {len(availability_warnings)}")
        output_parts.append("")

        # 显示配置错误
        if errors:
            output_parts.append("🔴 配置错误列表:")
            output_parts.append("-" * 60)
            for error in errors:
                output_parts.append(error)
            output_parts.append("")

        # 显示可用性错误
        if check_availability and availability_errors:
            output_parts.append("🔴 包可用性错误:")
            output_parts.append("-" * 60)
            for error in availability_errors:
                output_parts.append(error)
            output_parts.append("")

        # 显示配置警告
        if warnings and (verbose or not errors):
            output_parts.append("🟡 配置警告列表:")
            output_parts.append("-" * 60)
            for warning in warnings:
                output_parts.append(warning)
            output_parts.append("")

        # 显示可用性警告
        if check_availability and availability_warnings and (verbose or not availability_errors):
            output_parts.append("🟡 包可用性警告:")
            output_parts.append("-" * 60)
            for warning in availability_warnings:
                output_parts.append(warning)
            output_parts.append("")

        # 结论
        total_errors = len(errors) + len(availability_errors)
        total_warnings = len(warnings) + len(availability_warnings)

        if total_errors == 0 and total_warnings == 0:
            if check_availability:
                output_parts.append("✅ 验证通过！所有工具配置正确且包在当前平台可用。")
            else:
                output_parts.append("✅ 配置验证通过！所有工具配置正确。")
                output_parts.append("ℹ️  提示: 使用 --check-availability 可以验证包是否真实存在")
        elif total_errors == 0:
            output_parts.append(f"✅ 验证通过！有 {total_warnings} 个警告但不影响使用。")
        else:
            output_parts.append(f"❌ 验证失败！发现 {total_errors} 个错误，请修正后再试。")

        return CommandResult(
            success=total_errors == 0,
            output="\n".join(output_parts)
        )
