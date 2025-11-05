#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Global Scripts - 系统命令处理器
处理所有系统级命令：help, version, status, doctor, refresh
"""

import os
import sys
import json
import subprocess
from pathlib import Path
from typing import Dict, Any

from .formatters import OutputFormatter
from ..core.config_manager import ConfigManager
from ..models.result import CommandResult
from ..application.services import PluginService, PluginExecutor
from ..core.constants import GlobalConstants
from ..utils.i18n import I18nManager
from ..utils.shell_utils import detect_current_shell

from ..core.logger import get_logger
from ..utils.logging_utils import (
    correlation_id,
    duration,
)

logger = get_logger(tag="CLI.SYSTEM", name=__name__)


class SystemCommands:
    """系统命令处理器"""

    def __init__(
        self,
        config_manager: ConfigManager,
        plugin_service: PluginService,
        plugin_executor: PluginExecutor,
        chinese: bool = True,
    ):
        self.config_manager = config_manager
        self.plugin_service = plugin_service
        self.plugin_executor = plugin_executor
        self.chinese = chinese
        self.formatter = OutputFormatter(chinese=chinese)
        self.constants = GlobalConstants()
        self.i18n = I18nManager(chinese=chinese)
        self.project_root = Path(__file__).resolve().parents[3]

    def show_help(self) -> CommandResult:
        """显示帮助信息"""
        help_text = self.formatter.format_help_usage()
        return CommandResult(
            success=True,
            message=self.i18n.get_message("commands.help"),
            output=help_text,
        )

    def show_version(self) -> CommandResult:
        """显示版本信息"""
        version = self.constants.project_version
        version_text = f"{self.constants.project_name} v{version}"
        return CommandResult(
            success=True,
            message=self.i18n.get_message("commands.version"),
            output=version_text,
        )

    async def system_status(self) -> CommandResult:
        """系统状态检查"""
        try:
            cid = correlation_id()
            from time import monotonic

            start_ts = monotonic()
            logger.debug(f"cid={cid} status enter")

            # 从router index加载插件信息
            plugins_data = self._load_router_index()

            if plugins_data:
                # 从index统计信息
                plugins_total = len(plugins_data)
                plugins_enabled = sum(
                    1 for p in plugins_data.values() if p.get("enabled", True)
                )
                plugins_disabled = plugins_total - plugins_enabled
                functions_total = sum(
                    len(p.get("commands", {})) for p in plugins_data.values()
                )

                health_result = {
                    "status": "healthy",
                    "plugins_total": plugins_total,
                    "plugins_enabled": plugins_enabled,
                    "plugins_disabled": plugins_disabled,
                    "functions_total": functions_total,
                    "issues": [],
                }
            else:
                # 回退到plugin_service
                logger.debug(f"cid={cid} status fallback to plugin_service")
                health_result = await self.plugin_service.health_check()

            # i18n labels with graceful fallback
            def _label(key: str, zh_fallback: str, en_fallback: str) -> str:
                msg = self.i18n.get_message(key)
                return (
                    zh_fallback
                    if msg == key and self.i18n.current_language == "zh"
                    else (en_fallback if msg == key else msg)
                )

            status_label = _label("cli.status", "状态", "Status")
            total_plugins_label = _label(
                "plugin_list.stats_format.total_plugins", "总插件数", "Total plugins"
            )
            enabled_label = _label(
                "plugin_list.stats_format.enabled", "已启用", "enabled"
            )
            disabled_label = _label(
                "plugin_list.stats_format.disabled", "已禁用", "disabled"
            )
            total_cmds_label = _label(
                "plugin_list.stats_format.total_commands", "总命令数", "Total commands"
            )
            config_dir_label = _label("cli.directory", "配置目录", "Directory")
            version_label = _label("cli.version", "版本", "Version")
            issues_label = _label("cli.issues", "问题", "Issues")

            status_value = (
                _label("cli.enabled", "正常", "Healthy")
                if health_result.get("status") == "healthy"
                else _label("cli.disabled", "异常", "Unhealthy")
            )

            status_info = {
                status_label: status_value,
                total_plugins_label: health_result.get("plugins_total", 0),
                enabled_label: health_result.get("plugins_enabled", 0),
                disabled_label: health_result.get("plugins_disabled", 0),
                total_cmds_label: health_result.get("functions_total", 0),
                config_dir_label: str(self.config_manager.get_plugins_dir()),
                version_label: self.constants.project_version,
            }

            # 如果有问题，添加问题信息
            if health_result.get("issues"):
                status_info[issues_label] = "; ".join(health_result["issues"])

            # 使用统一的格式化器绘制信息表（title 显示在 Panel 边框上）
            title_text = f"🔧 {self.i18n.get_message('commands.system_status')}"
            info_table = self.formatter.format_info_table(status_info, title=title_text)

            output = info_table

            took = duration(start_ts)
            logger.info(
                f"cid={cid} status ok took_ms={took} plugins_total={health_result.get('plugins_total')} "
                f"enabled={health_result.get('plugins_enabled')} disabled={health_result.get('plugins_disabled')} "
                f"functions_total={health_result.get('functions_total')} issues_cnt={len(health_result.get('issues') or [])}"
            )
            return CommandResult(
                success=True,
                message=self.i18n.get_message("commands.command_success"),
                output=output,
            )
        except Exception as e:
            cid = correlation_id()
            logger.error(f"cid={cid} status fail error={type(e).__name__}: {e}")
            return CommandResult(
                success=False,
                error=self.i18n.get_message("errors.execution_failed", error=str(e)),
                exit_code=self.constants.exit_execution_error,
            )

    async def system_doctor(self) -> CommandResult:
        """系统诊断 - 全面检查环境配置"""
        try:
            cid = correlation_id()
            from time import monotonic

            start_ts = monotonic()
            logger.debug(f"cid={cid} doctor enter")

            checks = []
            issues = []
            warnings = []

            # 1. Python环境检查
            py_version = sys.version.split()[0]
            py_check = self._check_python_version()
            checks.append(("Python Version", py_version, py_check["status"]))
            if not py_check["ok"]:
                issues.append(py_check["message"])

            # 2. 必需工具检查
            jq_check = self._check_command("jq")
            checks.append(
                ("jq (JSON processor)", jq_check["version"], jq_check["status"])
            )
            if not jq_check["ok"]:
                issues.append(jq_check["message"])

            # 3. Shell环境检查
            shell = detect_current_shell()
            shell_check = self._check_shell_config(shell)
            checks.append(("Current Shell", shell, shell_check["status"]))
            if not shell_check["ok"]:
                issues.append(shell_check["message"])

            # 4. 配置文件检查
            config_check = self._check_config_files()
            checks.append(
                ("Config Files", config_check["summary"], config_check["status"])
            )
            if not config_check["ok"]:
                issues.extend(config_check.get("issues", []))
            warnings.extend(config_check.get("warnings", []))

            # 5. Router Index检查
            router_check = self._check_router_index()
            checks.append(
                ("Router Index", router_check["summary"], router_check["status"])
            )
            if not router_check["ok"]:
                issues.append(router_check["message"])

            # 6. 补全脚本检查
            completion_check = self._check_completions(shell)
            checks.append(
                (
                    "Completion Scripts",
                    completion_check["summary"],
                    completion_check["status"],
                )
            )
            if not completion_check["ok"]:
                issues.extend(completion_check.get("issues", []))

            # 7. 插件健康检查
            plugin_check = self._check_plugins()
            checks.append(
                ("Plugin System", plugin_check["summary"], plugin_check["status"])
            )
            if not plugin_check["ok"]:
                issues.extend(plugin_check.get("issues", []))
            warnings.extend(plugin_check.get("warnings", []))

            # 8. 文件权限检查
            perm_check = self._check_permissions()
            checks.append(
                ("File Permissions", perm_check["summary"], perm_check["status"])
            )
            if not perm_check["ok"]:
                issues.extend(perm_check.get("issues", []))

            # 构建输出
            output_lines = []
            output_lines.append("=" * 60)
            output_lines.append(
                "🏥 Global Scripts System Diagnostics"
                if not self.chinese
                else "🏥 Global Scripts 系统诊断"
            )
            output_lines.append("=" * 60)
            output_lines.append("")

            # 检查结果表格
            output_lines.append(
                "📋 " + ("Check Results:" if not self.chinese else "检查结果:")
            )
            output_lines.append("")
            for check_name, check_value, check_status in checks:
                status_icon = (
                    "✅"
                    if check_status == "ok"
                    else ("⚠️" if check_status == "warning" else "❌")
                )
                output_lines.append(f"  {status_icon} {check_name:.<40} {check_value}")
            output_lines.append("")

            # 问题汇总
            if issues:
                output_lines.append(
                    "❌ " + ("Issues Found:" if not self.chinese else "发现问题:")
                )
                output_lines.append("")
                for i, issue in enumerate(issues, 1):
                    output_lines.append(f"  {i}. {issue}")
                output_lines.append("")

            # 警告汇总
            if warnings:
                output_lines.append(
                    "⚠️  " + ("Warnings:" if not self.chinese else "警告:")
                )
                output_lines.append("")
                for i, warning in enumerate(warnings, 1):
                    output_lines.append(f"  {i}. {warning}")
                output_lines.append("")

            # 整体状态
            output_lines.append("=" * 60)
            if not issues:
                overall_status = "✅ " + (
                    "All systems operational!"
                    if not self.chinese
                    else "所有系统运行正常！"
                )
            else:
                overall_status = "❌ " + (
                    f"Found {len(issues)} issue(s) that need attention"
                    if not self.chinese
                    else f"发现 {len(issues)} 个需要处理的问题"
                )
            output_lines.append(overall_status)
            output_lines.append("=" * 60)

            took = duration(start_ts)
            logger.info(
                f"cid={cid} doctor ok took_ms={took} checks={len(checks)} issues={len(issues)} warnings={len(warnings)}"
            )

            return CommandResult(
                success=len(issues) == 0,
                output="\n".join(output_lines),
                exit_code=0 if len(issues) == 0 else 1,
            )

        except Exception as e:
            cid = correlation_id()
            logger.error(f"cid={cid} doctor fail error={type(e).__name__}: {e}")
            return CommandResult(
                success=False,
                error=self.i18n.get_message("errors.execution_failed", error=str(e)),
                exit_code=self.constants.exit_execution_error,
            )

    async def system_refresh(self) -> CommandResult:
        """系统刷新 - 重新生成补全和env文件"""
        try:
            cid = correlation_id()
            from time import monotonic

            start_ts = monotonic()
            logger.debug(f"cid={cid} refresh enter")
            logger.info(self.i18n.get_message("commands.refresh"))

            # 直接使用setup.py来生成补全
            await self._regenerate_completion_with_setup()

            # 生成 router index
            await self._generate_router_index()

            # 重新加载环境提示
            logger.info(self.i18n.get_message("commands.loading_plugins"))

            # 检测当前 shell 环境
            shell = detect_current_shell()

            if shell == "fish":
                env_file_name = "env.fish"
            else:
                env_file_name = self.constants.env_sh_file_name

            env_path = self.project_root / env_file_name

            # 仅当缺少 env 文件时才生成，避免覆盖用户已有配置
            if not env_path.exists():
                await self._regenerate_env_sh()

            if env_path.exists():
                try:
                    # 直接在当前shell中source env文件
                    import subprocess

                    # 根据shell类型选择命令
                    if shell == "fish":
                        source_cmd = (
                            f"fish -c 'source {env_path}' >/dev/null 2>&1 && echo 'OK'"
                        )
                    else:
                        source_cmd = (
                            f"bash -c 'source {env_path} >/dev/null 2>&1 && echo OK'"
                        )

                    result = subprocess.run(
                        [shell if shell != "unknown" else "bash", "-c", source_cmd],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )

                    if result.returncode == 0:
                        success_message = self.i18n.get_message(
                            "commands.command_success"
                        )
                    else:
                        success_message = self.i18n.get_message(
                            "setup.source_instruction"
                        )

                except Exception:
                    success_message = self.i18n.get_message("setup.source_instruction")

                took = duration(start_ts)
                logger.info(
                    f"cid={cid} refresh ok took_ms={took} sourced={env_path.exists()} shell={shell}"
                )
                return CommandResult(success=True, output=success_message)
            else:
                logger.warning(f"cid={cid} refresh missing_env path={env_path}")
                return CommandResult(
                    success=False,
                    error=self.i18n.get_message(
                        "errors.file_not_found", file=str(env_path)
                    ),
                    exit_code=self.constants.exit_general_error,
                )

        except Exception as e:
            cid = correlation_id()
            logger.error(f"cid={cid} refresh fail error={type(e).__name__}: {e}")
            return CommandResult(
                success=False,
                error=self.i18n.get_message("errors.execution_failed", error=str(e)),
                exit_code=self.constants.exit_execution_error,
            )

    # ========== 辅助方法 ==========

    def _load_router_index(self) -> Dict[str, Any]:
        """从router index加载插件信息"""
        try:
            gs_home = GlobalConstants.gs_home
            router_index_path = gs_home / "cache" / "router.json"

            if not router_index_path.exists():
                logger.warning(f"Router index not found at {router_index_path}")
                return {}

            with open(router_index_path, "r", encoding="utf-8") as f:
                index = json.load(f)

            return index.get("plugins", {})
        except Exception as e:
            logger.error(f"Failed to load router index: {e}")
            return {}

    def _check_python_version(self) -> Dict[str, Any]:
        """检查Python版本"""
        major, minor = sys.version_info.major, sys.version_info.minor
        if major >= 3 and minor >= 8:
            return {"ok": True, "status": "ok", "message": ""}
        else:
            msg = (
                f"Python 3.8+ required, found {major}.{minor}"
                if not self.chinese
                else f"需要 Python 3.8+，当前版本 {major}.{minor}"
            )
            return {"ok": False, "status": "error", "message": msg}

    def _check_command(self, cmd: str) -> Dict[str, Any]:
        """检查命令是否可用"""
        try:
            result = subprocess.run(
                [cmd, "--version"], capture_output=True, text=True, timeout=2
            )
            if result.returncode == 0:
                version = result.stdout.strip().split("\n")[0][:30]
                return {"ok": True, "status": "ok", "version": version}
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        msg = (
            f"{cmd} not found - install with: brew install {cmd}"
            if not self.chinese
            else f"{cmd} 未安装 - 请安装: brew install {cmd}"
        )
        return {
            "ok": False,
            "status": "error",
            "version": "Not installed",
            "message": msg,
        }

    def _check_shell_config(self, shell: str) -> Dict[str, Any]:
        """检查Shell配置"""
        if shell == "unknown":
            msg = "Could not detect shell" if not self.chinese else "无法检测Shell环境"
            return {"ok": False, "status": "warning", "message": msg}

        env_file = "env.fish" if shell == "fish" else self.constants.env_sh_file_name
        env_path = self.project_root / env_file

        if not env_path.exists():
            msg = (
                f"{env_file} not found - run 'gs refresh'"
                if not self.chinese
                else f"{env_file} 不存在 - 请运行 'gs refresh'"
            )
            return {"ok": False, "status": "error", "message": msg}

        return {"ok": True, "status": "ok", "message": ""}

    def _check_config_files(self) -> Dict[str, Any]:
        """检查配置文件"""
        issues = []
        warnings = []

        # 检查主配置文件
        user_config = Path.home() / ".config" / "global-scripts" / "config" / "gs.json"
        project_config = self.project_root / "config" / "gs.json"

        if not user_config.exists() and not project_config.exists():
            issues.append(
                "No gs.json found - run 'gs refresh'"
                if not self.chinese
                else "未找到 gs.json - 请运行 'gs refresh'"
            )
            return {
                "ok": False,
                "status": "error",
                "summary": "Missing",
                "issues": issues,
            }

        # 尝试解析JSON
        config_path = user_config if user_config.exists() else project_config
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                json.load(f)
        except json.JSONDecodeError as e:
            issues.append(
                f"Invalid JSON in {config_path.name}: {e}"
                if not self.chinese
                else f"{config_path.name} JSON格式错误: {e}"
            )
            return {
                "ok": False,
                "status": "error",
                "summary": "Invalid",
                "issues": issues,
            }

        return {
            "ok": True,
            "status": "ok",
            "summary": "Valid",
            "issues": issues,
            "warnings": warnings,
        }

    def _check_router_index(self) -> Dict[str, Any]:
        """检查Router Index"""
        gs_home = GlobalConstants.gs_home
        router_path = gs_home / "cache" / "router.json"

        if not router_path.exists():
            msg = (
                "router.json not found - run 'gs refresh'"
                if not self.chinese
                else "router.json 不存在 - 请运行 'gs refresh'"
            )
            return {
                "ok": False,
                "status": "error",
                "summary": "Missing",
                "message": msg,
            }

        try:
            with open(router_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            plugin_count = len(data.get("plugins", {}))
            return {
                "ok": True,
                "status": "ok",
                "summary": f"{plugin_count} plugins",
                "message": "",
            }
        except json.JSONDecodeError as e:
            msg = f"Invalid JSON: {e}" if not self.chinese else f"JSON格式错误: {e}"
            return {
                "ok": False,
                "status": "error",
                "summary": "Invalid",
                "message": msg,
            }

    def _check_completions(self, shell: str) -> Dict[str, Any]:
        """检查补全脚本"""
        issues = []
        # Completions are in GS_HOME (user config), not project config
        comp_dir = GlobalConstants.gs_home / "completions"

        if not comp_dir.exists():
            issues.append(
                "Completion directory missing" if not self.chinese else "补全目录不存在"
            )
            return {
                "ok": False,
                "status": "error",
                "summary": "Missing",
                "issues": issues,
            }

        # 检查对应shell的补全文件
        shell_files = {"bash": "gs.bash", "zsh": "gs.zsh", "fish": "gs.fish"}

        comp_file = shell_files.get(shell)
        if comp_file:
            comp_path = comp_dir / comp_file
            if not comp_path.exists():
                issues.append(
                    f"{comp_file} not found"
                    if not self.chinese
                    else f"{comp_file} 不存在"
                )
                return {
                    "ok": False,
                    "status": "warning",
                    "summary": "Incomplete",
                    "issues": issues,
                }

        return {"ok": True, "status": "ok", "summary": "Installed", "issues": issues}

    def _check_plugins(self) -> Dict[str, Any]:
        """检查插件系统"""
        issues = []
        warnings = []

        try:
            # 检查插件目录
            plugins_dir = self.config_manager.get_plugins_dir()
            if not plugins_dir.exists():
                issues.append(
                    f"Plugin directory not found: {plugins_dir}"
                    if not self.chinese
                    else f"插件目录不存在: {plugins_dir}"
                )
                return {
                    "ok": False,
                    "status": "error",
                    "summary": "Error",
                    "issues": issues,
                }

            # 统计插件
            plugins = self.plugin_service.get_loaded_plugins()
            total_plugins = len(plugins)
            enabled_count = sum(
                1 for p_name, p_data in plugins.items() if p_data.get("enabled", True)
            )

            if total_plugins == 0:
                warnings.append(
                    "No plugins loaded" if not self.chinese else "未加载任何插件"
                )
                return {
                    "ok": True,
                    "status": "warning",
                    "summary": "No plugins",
                    "warnings": warnings,
                }

            return {
                "ok": True,
                "status": "ok",
                "summary": f"{enabled_count}/{total_plugins} enabled",
                "issues": issues,
                "warnings": warnings,
            }
        except Exception as e:
            issues.append(
                f"Plugin check failed: {e}"
                if not self.chinese
                else f"插件检查失败: {e}"
            )
            return {
                "ok": False,
                "status": "error",
                "summary": "Error",
                "issues": issues,
            }

    def _check_permissions(self) -> Dict[str, Any]:
        """检查文件权限"""
        issues = []

        # 检查关键目录的读写权限
        critical_dirs = [
            GlobalConstants.gs_home,
            GlobalConstants.get_config_dir(),
            self.project_root / "plugins",
        ]

        for dir_path in critical_dirs:
            if dir_path.exists():
                if not os.access(dir_path, os.R_OK):
                    issues.append(
                        f"No read permission: {dir_path}"
                        if not self.chinese
                        else f"无读取权限: {dir_path}"
                    )
                if not os.access(dir_path, os.W_OK):
                    issues.append(
                        f"No write permission: {dir_path}"
                        if not self.chinese
                        else f"无写入权限: {dir_path}"
                    )

        if issues:
            return {
                "ok": False,
                "status": "error",
                "summary": "Permission denied",
                "issues": issues,
            }

        return {"ok": True, "status": "ok", "summary": "OK", "issues": issues}

    async def _regenerate_completion_with_setup(self) -> CommandResult:
        """使用setup.py重新生成补全脚本"""
        try:
            cid = correlation_id()
            from time import monotonic

            start_ts = monotonic()
            from ..utils.process_executor import get_process_executor

            setup_py = self.project_root / "scripts" / "setup.py"

            # 使用ProcessExecutor重新生成补全
            executor = get_process_executor()
            result = await executor.execute(
                ["python3", str(setup_py), "--generate-completion", "--auto"],
                cwd=str(self.project_root),
            )

            if not result.success:
                logger.error(
                    f"cid={cid} completion regen fail code={result.exit_code} error={result.error.strip()[:200]}"
                )
                return CommandResult(
                    success=False,
                    error=self.i18n.get_message(
                        "errors.execution_failed", error=result.error
                    ),
                    exit_code=result.exit_code,
                )
            took = duration(start_ts)
            logger.info(f"cid={cid} completion regen ok took_ms={took}")
            return CommandResult(
                success=True,
                message=self.i18n.get_message("setup.completion_generated"),
            )

        except Exception as e:
            cid = correlation_id()
            logger.error(
                f"cid={cid} completion regen exception error={type(e).__name__}: {e}"
            )
            return CommandResult(
                success=False,
                error=self.i18n.get_message("errors.execution_failed", error=str(e)),
                exit_code=self.constants.exit_execution_error,
            )

    async def _generate_router_index(self) -> CommandResult:
        """生成 router index 用于 shell/json 命令分发"""
        try:
            cid = correlation_id()
            from time import monotonic

            start_ts = monotonic()
            logger.debug(f"cid={cid} router_index enter")

            from ..router.indexer import build_router_index, write_router_index

            # 构建 router index
            plugins = self.plugin_service.get_loaded_plugins()
            index = build_router_index(plugins)

            # 写入 router index
            index_path = write_router_index(index)

            took = duration(start_ts)
            logger.info(
                f"cid={cid} router_index ok took_ms={took} path={index_path} plugins={len(index)}"
            )

            return CommandResult(
                success=True, message=f"Router index generated at {index_path}"
            )
        except Exception as e:
            cid = correlation_id()
            logger.error(f"cid={cid} router_index fail error={type(e).__name__}: {e}")
            return CommandResult(
                success=False,
                error=self.i18n.get_message("errors.execution_failed", error=str(e)),
                exit_code=self.constants.exit_execution_error,
            )

    async def _regenerate_env_sh(self) -> CommandResult:
        """重新生成env.sh或env.fish文件"""
        try:
            cid = correlation_id()
            from time import monotonic

            start_ts = monotonic()
            import re

            setup_py = self.project_root / "scripts" / "setup.py"

            # 检测当前 shell 环境
            shell = detect_current_shell()

            if shell == "fish":
                env_file_name = "env.fish"
                shell_arg = "fish"
            else:
                env_file_name = self.constants.env_sh_file_name
                shell_arg = "bash"

            env_path = self.project_root / env_file_name

            # 读取当前语言与示例显示配置
            lang = os.getenv("GS_LANGUAGE")
            show_examples_env = os.getenv("GS_CONFIG_SHOW_EXAMPLES")
            if (lang is None or show_examples_env is None) and env_path.exists():
                try:
                    content = env_path.read_text(encoding="utf-8")
                    m_lang = re.search(
                        r'^export\s+GS_LANGUAGE="?([a-zA-Z_-]+)"?',
                        content,
                        re.MULTILINE,
                    )
                    m_examples = re.search(
                        r'^export\s+GS_CONFIG_SHOW_EXAMPLES="?(true|false|1|0)"?',
                        content,
                        re.MULTILINE | re.IGNORECASE,
                    )
                    if lang is None and m_lang:
                        lang = m_lang.group(1)
                    if show_examples_env is None and m_examples:
                        show_examples_env = m_examples.group(1)
                except Exception:
                    pass

            if not lang:
                lang = "zh"
            show_examples_bool = (
                str(show_examples_env).lower() in ("1", "true", "yes", "y")
                if show_examples_env is not None
                else False
            )
            examples_flag = "true" if show_examples_bool else "false"

            # 使用ProcessExecutor重新生成env文件
            from ..utils.process_executor import get_process_executor

            executor = get_process_executor()
            result = await executor.execute(
                [
                    "python3",
                    str(setup_py),
                    "--auto",
                    "--shell",
                    shell_arg,
                    "--lang",
                    lang,
                    "--examples",
                    examples_flag,
                ],
                cwd=str(self.project_root),
            )

            if not result.success:
                logger.error(
                    f"cid={cid} envsh regen fail code={result.exit_code} error={result.error.strip()[:200]}"
                )
                return CommandResult(
                    success=False,
                    error=self.i18n.get_message(
                        "errors.execution_failed", error=result.error
                    ),
                    exit_code=result.exit_code,
                )
            took = duration(start_ts)
            logger.info(
                f"cid={cid} envsh regen ok took_ms={took} lang={lang} examples={examples_flag}"
            )
            return CommandResult(
                success=True, message=self.i18n.get_message("setup.source_instruction")
            )

        except Exception as e:
            cid = correlation_id()
            logger.error(
                f"cid={cid} envsh regen exception error={type(e).__name__}: {e}"
            )
            return CommandResult(
                success=False,
                error=self.i18n.get_message("errors.execution_failed", error=str(e)),
                exit_code=self.constants.exit_execution_error,
            )
