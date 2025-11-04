#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Global Scripts - 命令处理器 (重构版)
使用 Command 模式和 CommandRegistry，职责单一

Phase 2.5: 拆分 CommandHandler
- 从 1345 行减少到 ~150 行
- 删除所有具体命令实现（迁移到 command_classes/）
- 使用 CommandRegistry 管理命令
- 保留核心路由和插件执行逻辑
"""

from typing import List, Optional

from .command_classes import create_command_registry
from .formatters import OutputFormatter
from ..core.config_manager import ConfigManager
from ..models.result import CommandResult
from ..infrastructure.adapters.plugin_manager_adapter import (
    PluginManagerAdapter as PluginManager,
)
from ..core.constants import GlobalConstants
from ..utils.i18n import I18nManager

from ..core.logger import get_logger
from ..utils.logging_utils import correlation_id, duration

# Module-level logger
logger = get_logger(tag="CLI.COMMANDS", name=__name__)


class CommandHandler:
    """
    命令处理器 - 核心职责：
    1. 路由命令到 CommandRegistry 或 PluginManager
    2. 处理插件函数执行
    3. 处理命令未找到的情况

    不再包含：
    - 具体命令实现（已迁移到 command_classes/）
    - 补全生成逻辑
    - 格式化逻辑（已在 command_classes 中）
    """

    def __init__(
        self,
        config_manager: ConfigManager,
        plugin_manager: PluginManager,
        chinese: bool = True,
    ):
        self.config_manager = config_manager
        self.plugin_manager = plugin_manager
        self.chinese = chinese
        self.formatter = OutputFormatter(chinese=chinese)
        self.constants = GlobalConstants()
        self.i18n = I18nManager(chinese=chinese)

        # 初始化 CommandRegistry
        self.command_registry = create_command_registry(
            config_manager, plugin_manager, chinese
        )

    async def handle_command(self, args: List[str]) -> CommandResult:
        """
        处理命令 - 核心路由逻辑

        优先级：
        1. 系统命令 (help, version, status, doctor, refresh, plugin)
        2. 插件命令 (plugin function)
        3. 单个命令回退处理
        """
        from time import monotonic

        start_ts = monotonic()
        cid = correlation_id()

        try:
            if not args:
                logger.debug(f"cid={cid} empty_args -> help")
                return await self._execute_system_command("help", [])

            command = args[0]
            logger.info(
                f"cid={cid} enter handle_command command={command} args={args[1:]}"
            )

            # 1. 尝试作为系统命令
            if self._is_system_command(command):
                logger.debug(f"cid={cid} route=system_command command={command}")
                return await self._execute_system_command(command, args[1:])

            # 2. 尝试作为插件命令 (plugin subcommand)
            if command == "plugin":
                logger.debug(f"cid={cid} route=plugin_subcommand args={args[1:]}")
                return await self._handle_plugin_subcommand(args[1:])

            # 3. 尝试作为插件函数 (plugin function / plugin sub function)
            if len(args) >= 2:
                result = await self._try_execute_plugin_function(args)
                if result:
                    return result

            # 4. 单个命令 - 尝试作为插件名
            logger.debug(f"cid={cid} route=single_command command={command}")
            return await self._handle_single_command(command)

        finally:
            took = duration(start_ts)
            logger.debug(f"cid={cid} leave handle_command took_ms={took}")

    def _is_system_command(self, command: str) -> bool:
        """检查是否为系统命令"""
        return self.command_registry.has_command(command)

    async def _execute_system_command(
        self, command: str, args: List[str]
    ) -> CommandResult:
        """执行系统命令"""
        cmd = self.command_registry.get(command)
        if cmd is None:
            return CommandResult(
                success=False,
                error=f"Unknown command: {command}",
                exit_code=self.constants.exit_command_not_found,
            )

        return await cmd.execute(args)

    async def _handle_plugin_subcommand(self, args: List[str]) -> CommandResult:
        """
        处理 plugin 子命令
        gs plugin list
        gs plugin info <name>
        gs plugin enable <name>
        gs plugin disable <name>
        """
        if not args:
            # 默认显示 plugin list
            return await self._execute_system_command("plugin:list", [])

        subcommand = args[0]

        # 映射 plugin 子命令到 CommandRegistry
        command_map = {
            "list": "plugin:list",
            "info": "plugin:info",
            "enable": "plugin:enable",
            "disable": "plugin:disable",
        }

        if subcommand in command_map:
            command_name = command_map[subcommand]
            if self.command_registry.has_command(command_name):
                return await self._execute_system_command(command_name, args[1:])

        # 未知的 plugin 子命令
        return CommandResult(
            success=False,
            error=self.i18n.get_message(
                "errors.unknown_plugin_command", command=subcommand
            ),
            exit_code=self.constants.exit_command_not_found,
        )

    async def _try_execute_plugin_function(
        self, args: List[str]
    ) -> Optional[CommandResult]:
        """
        尝试执行插件函数

        支持：
        - gs plugin function arg1 arg2
        - gs plugin sub function arg1 arg2
        """
        cid = correlation_id()

        # 3层: plugin sub function
        if len(args) >= 3:
            plugin_name, subplugin_name, function_name = args[0], args[1], args[2]
            logger.debug(
                f"cid={cid} try_plugin depth=3 plugin={plugin_name} "
                f"sub={subplugin_name} func={function_name}"
            )

            if plugin_name in self.plugin_manager.plugins:
                plugin = self.plugin_manager.plugins[plugin_name]
                functions = plugin.get("functions", {})

                # 尝试: "sub function" 复合名 (with space, like router.json)
                composite_function_name = f"{subplugin_name} {function_name}"
                if composite_function_name in functions:
                    return await self._execute_plugin_function(
                        plugin_name, composite_function_name, args[3:]
                    )

                # 回退: sub 作为函数名，function 作为参数
                if subplugin_name in functions:
                    logger.debug(
                        f"cid={cid} fallback=2layer plugin={plugin_name} func={subplugin_name}"
                    )
                    return await self._execute_plugin_function(
                        plugin_name, subplugin_name, [function_name] + args[3:]
                    )

        # 2层: plugin function
        elif len(args) >= 2:
            plugin_name, function_name = args[0], args[1]
            logger.debug(
                f"cid={cid} try_plugin depth=2 plugin={plugin_name} func={function_name}"
            )

            if plugin_name in self.plugin_manager.plugins:
                return await self._execute_plugin_function(
                    plugin_name, function_name, args[2:]
                )

        return None

    async def _execute_plugin_function(
        self, plugin_name: str, function_name: str, args: List[str]
    ) -> CommandResult:
        """执行插件函数 - 委托给 PluginManager"""
        cid = correlation_id()
        logger.debug(
            f"cid={cid} exec_plugin plugin={plugin_name} "
            f"func={function_name} args={args}"
        )

        return await self.plugin_manager.execute_plugin_function(
            plugin_name, function_name, args
        )

    async def _handle_single_command(self, command: str) -> CommandResult:
        """
        处理单个命令
        可能是插件名，尝试执行默认函数或显示插件信息
        """
        cid = correlation_id()

        # 如果是插件名，可以显示插件信息或执行默认函数
        if command in self.plugin_manager.plugins:
            logger.debug(f"cid={cid} single_command is_plugin={command}")
            # 可以选择执行插件的默认函数或显示信息
            # 这里选择显示信息
            return await self._execute_system_command("plugin:info", [command])

        # 完全未知的命令
        logger.warning(f"cid={cid} command_not_found command={command}")
        return CommandResult(
            success=False,
            error=self.i18n.get_message("errors.command_not_found", command=command),
            exit_code=self.constants.exit_command_not_found,
        )
