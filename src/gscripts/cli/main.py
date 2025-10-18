#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Global Scripts - CLI主入口
处理命令行接口和快捷命令路由，支持中文显示
"""

import asyncio
import os
import sys
import time
from pathlib import Path
from typing import List, Optional

# 添加项目根目录到sys.path以支持导入
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.cli.commands import CommandHandler
from gscripts.cli.formatters import OutputFormatter
from gscripts.core.config_manager import ConfigManager, CommandResult
from gscripts.core.plugin_manager import PluginManager
from gscripts.core.constants import GlobalConstants
from gscripts.utils.i18n import get_i18n_manager
from gscripts.core.logger import setup_logging, get_logger
from gscripts.utils.logging_utils import (
    redact, ctx, correlation_id, set_correlation_id, duration, trunc, sanitize_path
)


# 模块级别的logger
logger = get_logger(tag="CLI.MAIN", name=__name__)


class GlobalScriptsCLI:
    """Global Scripts CLI主程序"""
    
    def __init__(self, chinese: bool = None):
        start_time = time.monotonic()
        
        # 生成新的关联ID用于这次CLI会话
        cid = correlation_id()
        logger.info(
            f"CLI initializing, correlation_id={cid}, python_version={sys.version}, "
            f"project_root={sanitize_path(project_root)}"
        )
        
        # 尽早初始化集中式日志，确保后续模块日志统一写入文件
        try:
            setup_logging()
            logger.debug("Central logging initialized successfully")
        except Exception as e:
            # 避免日志初始化失败影响CLI启动
            logger.warning(f"Failed to initialize central logging: {e}")
            pass
            
        # 从环境变量读取语言设置，默认为中文
        if chinese is None:
            language = os.getenv('GS_LANGUAGE', 'zh')
            chinese = language == 'zh'
            logger.debug(f"Language detected from env: {language}, chinese={chinese}")

        self.chinese = chinese
        
        logger.debug("Initializing ConfigManager")
        self.config_manager = ConfigManager()
        
        plugins_dir = self.config_manager.get_plugins_dir()
        logger.debug(f"Initializing PluginManager with plugins_root={sanitize_path(plugins_dir)}")
        self.plugin_manager = PluginManager(
            plugins_root=plugins_dir,
            config_manager=self.config_manager
        )
        
        logger.debug("Initializing CommandHandler")
        self.command_handler = CommandHandler(
            config_manager=self.config_manager,
            plugin_manager=self.plugin_manager,
            chinese=self.chinese
        )
        
        self.formatter = OutputFormatter(chinese=self.chinese)
        self._initialized = False
        self.constants = GlobalConstants()
        self.i18n = get_i18n_manager()
        self.i18n.set_language('zh' if self.chinese else 'en')
        
        elapsed_ms = duration(start_time)
        logger.info(
            f"CLI initialized successfully, duration_ms={elapsed_ms}, "
            f"language={'zh' if self.chinese else 'en'}"
        )
    
    async def initialize(self):
        """初始化CLI系统"""
        if self._initialized:
            logger.debug("CLI already initialized, skipping")
            return
        
        start_time = time.monotonic()
        logger.info("Starting CLI system initialization")
        
        try:
            await self.plugin_manager.initialize()
            self._initialized = True
            
            elapsed_ms = duration(start_time)
            logger.info(
                f"CLI system initialization completed, duration_ms={elapsed_ms}, "
                f"plugins_loaded={len(self.plugin_manager.plugins)}"
            )
        except Exception as e:
            logger.exception(f"Failed to initialize CLI system: {e}")
            raise
    
    async def run(self, args: List[str] = None):
        """运行CLI命令"""
        if args is None:
            args = sys.argv[1:]
        
        start_time = time.monotonic()
        logger.info(f"CLI run started, args={redact(args)}, arg_count={len(args)}")
        
        # 确保初始化
        await self.initialize()
        
        try:
            # 解析并记录命令
            command_name = args[0] if args else 'help'
            logger.debug(f"Processing command: {command_name}, full_args={redact(args)}")
            
            # 处理命令
            result = await self.command_handler.handle_command(args)
            
            elapsed_ms = duration(start_time)
            
            # 处理结果
            if result.success:
                logger.info(
                    f"Command completed successfully, command={command_name}, "
                    f"duration_ms={elapsed_ms}, exit_code=0"
                )

                # 优先显示output，如果没有则显示stdout
                output_text = result.output or getattr(result, 'stdout', '') or ''
                if output_text:
                    logger.debug(f"Output length={len(output_text)} bytes")
                    print(output_text.rstrip())  # 移除末尾的换行符避免重复
                sys.exit(0)
            else:
                logger.error(
                    f"Command failed, command={command_name}, duration_ms={elapsed_ms}, "
                    f"exit_code={result.exit_code}, error={trunc(result.error, 200)}"
                )

                # 如果有output，优先显示output（例如doctor命令的诊断结果）
                # 否则显示error或stderr
                if result.output:
                    print(result.output.rstrip())
                else:
                    error_text = result.error or getattr(result, 'stderr', '') or self.i18n.get_message('commands.command_failed')
                    prefix = '错误' if self.chinese else 'Error'
                    print(f"{prefix}: {error_text}", file=sys.stderr)
                sys.exit(result.exit_code or self.constants.exit_general_error)
                
        except KeyboardInterrupt:
            elapsed_ms = duration(start_time)
            logger.warning(f"Command interrupted by user, duration_ms={elapsed_ms}")
            
            msg = self.i18n.get_message('commands.command_failed')
            print(f"\n{msg}", file=sys.stderr)
            sys.exit(self.constants.exit_interrupted)
            
        except Exception as e:
            elapsed_ms = duration(start_time)
            logger.exception(
                f"Unexpected error in CLI run, command={args[0] if args else 'unknown'}, "
                f"duration_ms={elapsed_ms}, error={e}"
            )
            
            # 使用通用执行失败消息
            print(self.i18n.get_message('errors.execution_failed', error=str(e)), file=sys.stderr)
            sys.exit(self.constants.exit_general_error)
    
    def handle_shell_function(self, function_name: str, args: List[str] = None):
        """处理Shell函数调用"""
        if args is None:
            args = []
        
        logger.debug(
            f"Handling shell function: function_name={function_name}, "
            f"args={redact(args)}, arg_count={len(args)}"
        )
        
        # 从函数名推断插件和命令
        if function_name.startswith('gs_') or function_name.startswith('gs-'):
            # 移除前缀
            clean_name = function_name[3:] if function_name.startswith('gs_') else function_name[3:]
            logger.debug(f"Cleaned function name: {clean_name}")
            
            # 处理特殊的系统命令
            if clean_name in ['help', 'version']:
                command_args = [clean_name]
                logger.debug(f"Resolved as system command: {clean_name}")
            elif clean_name.startswith('system-'):
                command_args = ['system', clean_name[7:]]
                logger.debug(f"Resolved as system subcommand: {command_args}")
            elif clean_name.startswith('plugin-'):
                command_args = ['plugin', clean_name[7:]] + args
                logger.debug(f"Resolved as plugin command: {command_args[0]} {command_args[1]}")
            else:
                # 尝试解析插件命令
                parts = clean_name.replace('-', '_').split('_', 1)
                if len(parts) == 2:
                    command_args = parts + args
                    logger.debug(f"Resolved as plugin function: plugin={parts[0]}, function={parts[1]}")
                else:
                    command_args = [clean_name] + args
                    logger.debug(f"Resolved as direct command: {clean_name}")
            
            logger.info(
                f"Shell function resolved successfully, function={function_name} -> "
                f"command={' '.join(command_args[:2] if len(command_args) > 1 else command_args)}"
            )
            
            # 运行命令
            return asyncio.run(self.run(command_args))

        # 如果不是gs函数，返回错误
        logger.error(f"Unknown shell function format: {function_name}")
        msg = self.i18n.get_message('errors.command_not_found', command=function_name)
        print(msg, file=sys.stderr)
        sys.exit(self.constants.exit_command_not_found)


def main():
    """主入口函数"""
    # 设置新的关联ID
    set_correlation_id(None)  # 清除任何旧的ID
    cid = correlation_id()  # 生成新ID
    
    logger.info(f"Main entry point started, correlation_id={cid}, args={sys.argv[1:]}")
    
    try:
        cli = GlobalScriptsCLI()
        asyncio.run(cli.run())
    except Exception as e:
        logger.exception(f"Fatal error in main: {e}")
        sys.exit(1)


def create_shell_function_handler():
    """创建Shell函数处理器"""
    def shell_handler(function_name: str, *args):
        # 设置新的关联ID
        set_correlation_id(None)
        cid = correlation_id()
        
        logger.debug(
            f"Shell function handler invoked, correlation_id={cid}, "
            f"function={function_name}, args={redact(args)}"
        )
        
        # 从环境变量读取语言设置
        language = os.getenv('GS_LANGUAGE', 'zh')
        chinese = language == 'zh'
        cli = GlobalScriptsCLI(chinese=chinese)
        cli.handle_shell_function(function_name, list(args))
    
    return shell_handler


if __name__ == '__main__':
    main()
