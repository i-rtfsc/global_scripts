"""
插件管理器
负责插件的生命周期管理、路由和执行
"""

import asyncio
from pathlib import Path
from typing import Dict, List, Optional, Any, Union

from .plugin_loader import PluginLoader, SimplePlugin
from .config_manager import ConfigManager
from ..models import CommandResult
from ..utils.process_executor import get_process_executor
from .constants import GlobalConstants
from ..utils.i18n import I18nManager
from ..plugins.interfaces import (
    IPluginObserver,
    PluginEvent,
    PluginEventData
)



from ..core.logger import get_logger
from ..utils.logging_utils import (
    redact, redact_kv, redact_command, ctx, correlation_id, 
    duration, trunc, sanitize_path, format_size, safe_repr,
    log_context, format_exception, measure_time
)

# Module-level logger
logger = get_logger(tag="CORE.PLUGIN_MANAGER", name=__name__)

class PluginManager:
    """插件管理器"""
    
    def __init__(self, plugins_root: Union[str, Path] = None, config_manager: ConfigManager = None):
        self.constants = GlobalConstants()
        # 如果没有指定插件根目录，使用常量中的默认目录
        if plugins_root is None:
            self.plugins_root = self.constants.get_plugins_dir()
        else:
            self.plugins_root = Path(plugins_root)
        # Fallback: if resolved path does not exist but GS_ROOT set, try GS_ROOT/plugins
        if not self.plugins_root.exists():
            import os
            gs_root = os.environ.get('GS_ROOT')
            if gs_root:
                candidate = Path(gs_root) / 'plugins'
                if candidate.exists():
                    self.plugins_root = candidate
        # If current root is project root and contains a plugins subdir, use that
        if self.plugins_root.exists() and (self.plugins_root / 'plugins').exists() and (self.plugins_root / 'plugin.json').exists() is False:
            # Heuristic: top-level project directory; switch to plugins folder
            self.plugins_root = self.plugins_root / 'plugins'
        # 自动创建配置管理器以适配新 JSON 架构 (system_plugins/custom_plugins)
        if config_manager is None:
            try:
                self.config_manager = ConfigManager()
            except Exception:
                self.config_manager = None
        else:
            self.config_manager = config_manager
        self.loader = PluginLoader(self.plugins_root)
        self.plugins: Dict[str, SimplePlugin] = {}
        self.enabled_plugins: Dict[str, bool] = {}
        self._initialized = False
        self.i18n = I18nManager()

        # Observer 模式支持
        self._observers: List[IPluginObserver] = []
    
    async def initialize(self):
        """初始化插件管理器"""
        cid = correlation_id()
        from time import monotonic
        start_ts = monotonic()
        if self._initialized:
            logger.debug(f"cid={cid} init skip already_initialized=True")
            return
        logger.debug(f"cid={cid} init enter root={self.plugins_root}")
        try:
            await self.load_all_plugins()
            self._load_plugin_states()
            self._initialized = True
            took = duration(start_ts)
            logger.info(
                f"cid={cid} init ok took_ms={took} plugins_total={len(self.plugins)} enabled={len([p for p,v in self.enabled_plugins.items() if v])}"
            )
        except Exception as e:
            took = duration(start_ts)
            logger.error(f"cid={cid} init fail took_ms={took} error={type(e).__name__}: {e}")
            raise
    
    async def load_all_plugins(self):
        """加载所有插件"""
        cid = correlation_id()
        from time import monotonic
        start_ts = monotonic()
        logger.debug(f"cid={cid} load_all enter root={self.plugins_root}")
        self.plugins = await self.loader.load_all_plugins()
        took = duration(start_ts)
        logger.info(
            f"cid={cid} load_all ok took_ms={took} discovered={len(self.plugins)} failed={len(self.loader.failed_plugins)}"
        )
        # 状态加载在 initialize 内执行
    
    async def reload_plugin(self, plugin_name: str) -> bool:
        """重新加载指定插件"""
        cid = correlation_id()
        from time import monotonic
        start_ts = monotonic()
        logger.debug(f"cid={cid} reload enter plugin={plugin_name}")
        try:
            plugin = await self.loader.load_plugin(plugin_name)
            if plugin:
                self.plugins[plugin_name] = plugin
                took = duration(start_ts)
                logger.info(f"cid={cid} reload ok plugin={plugin_name} took_ms={took}")

                # 通知观察者：插件已重新加载
                self._notify(PluginEvent.RELOADED, plugin_name, plugin=plugin)

                return True
            else:
                if plugin_name in self.plugins:
                    del self.plugins[plugin_name]
                took = duration(start_ts)
                logger.warning(f"cid={cid} reload missing plugin={plugin_name} removed=True took_ms={took}")

                # 通知观察者：插件已卸载
                self._notify(PluginEvent.UNLOADED, plugin_name)

                return False
        except Exception as e:
            took = duration(start_ts)
            logger.error(f"cid={cid} reload fail plugin={plugin_name} took_ms={took} error={type(e).__name__}: {e}")
            return False
    
    async def execute_plugin_function(self, plugin_name: str, function_name: str, args: List[str] = None) -> CommandResult:
        """
        执行插件函数 - Delegates to PluginExecutor

        This method now serves as a facade that:
        1. Validates plugin is loaded and enabled
        2. Delegates actual execution to PluginExecutor (new architecture)
        """
        args = args or []
        cid = correlation_id()
        from time import monotonic
        start_ts = monotonic()
        logger.debug(f"cid={cid} exec enter plugin={plugin_name} func={function_name} args={args}")

        # 校验插件
        if plugin_name not in self.plugins:
            logger.warning(f"cid={cid} exec plugin_missing plugin={plugin_name} func={function_name}")
            return CommandResult(
                success=False,
                error=self.i18n.get_message("errors.plugin_not_found", plugin=plugin_name),
                exit_code=self.constants.EXIT_COMMAND_NOT_FOUND
            )
        if not self.is_plugin_enabled(plugin_name):
            logger.warning(f"cid={cid} exec plugin_disabled plugin={plugin_name} func={function_name}")
            return CommandResult(
                success=False,
                error=self.i18n.get_message("errors.plugin_disabled", name=plugin_name),
                exit_code=self.constants.EXIT_GENERAL_ERROR
            )

        # Lazy initialization of PluginExecutor using new architecture
        if not hasattr(self, '_plugin_executor') or self._plugin_executor is None:
            # Create a simple wrapper to make old loader compatible with new interface
            class LoaderWrapper:
                def __init__(self, plugin_manager):
                    self._pm = plugin_manager

                def get_loaded_plugins(self):
                    # Convert SimplePlugin objects to dict format expected by PluginExecutor
                    result = {}
                    for name, plugin in self._pm.plugins.items():
                        result[name] = {
                            'name': name,
                            'functions': plugin.functions,
                            'type': getattr(plugin, 'plugin_type', 'unknown')
                        }
                    return result

                def get_failed_plugins(self):
                    return {}

            from ..infrastructure.execution import ProcessExecutor
            from ..application.services import PluginExecutor

            loader_wrapper = LoaderWrapper(self)
            process_executor = ProcessExecutor()

            # Create PluginExecutor directly with compatible loader
            executor = PluginExecutor(loader_wrapper, process_executor)

            # Copy observers from PluginManager to PluginExecutor
            for observer in self._observers:
                executor.register_observer(observer)

            self._plugin_executor = executor

        # Delegate to PluginExecutor
        result = await self._plugin_executor.execute_plugin_function(plugin_name, function_name, args)

        took = duration(start_ts)
        if result.success:
            logger.info(
                f"cid={cid} exec ok plugin={plugin_name} func={function_name} took_ms={took} exit={result.exit_code}"
            )
        else:
            logger.error(
                f"cid={cid} exec fail plugin={plugin_name} func={function_name} took_ms={took} error={result.error}"
            )

        return result

    def enable_plugin(self, plugin_name: str) -> CommandResult:
        """启用插件"""
        if plugin_name not in self.plugins:
            return CommandResult(
                success=False,
                error=self.i18n.get_message('errors.plugin_not_found', plugin=plugin_name),
                exit_code=1
            )

        self.enabled_plugins[plugin_name] = True
        self._save_plugin_states()
        self._generate_router_index()  # 重新生成 router index
        self._regenerate_completions()  # 重新生成补全

        success_message = self.i18n.get_message('success.plugin_enabled', plugin=plugin_name)

        # 通知观察者：插件已启用
        plugin = self.plugins.get(plugin_name)
        self._notify(PluginEvent.ENABLED, plugin_name, plugin=plugin)

        return CommandResult(
            success=True,
            message=success_message,
            output=success_message
        )

    def disable_plugin(self, plugin_name: str) -> CommandResult:
        """禁用插件"""
        if plugin_name not in self.plugins:
            return CommandResult(
                success=False,
                error=self.i18n.get_message('errors.plugin_not_found', plugin=plugin_name),
                exit_code=1
            )

        self.enabled_plugins[plugin_name] = False
        self._save_plugin_states()
        self._generate_router_index()  # 重新生成 router index
        self._regenerate_completions()  # 重新生成补全

        success_message = self.i18n.get_message('success.plugin_disabled', plugin=plugin_name)

        # 通知观察者：插件已禁用
        plugin = self.plugins.get(plugin_name)
        self._notify(PluginEvent.DISABLED, plugin_name, plugin=plugin)

        return CommandResult(
            success=True,
            message=success_message,
            output=success_message
        )
    
    def is_plugin_enabled(self, plugin_name: str) -> bool:
        """检查插件是否启用"""
        val = self.enabled_plugins.get(plugin_name)
        if val is not None:
            return val
        # 回退：如果未在enabled_plugins中，尝试直接读取配置映射
        try:
            if self.config_manager:
                cfg = self.config_manager.get_config() or {}
                for key in ('system_plugins','custom_plugins'):
                    m = cfg.get(key, {}) or {}
                    if isinstance(m, dict) and plugin_name in m:
                        return bool(m[plugin_name])
        except Exception as e:
            pass
        return False
    
    def list_plugins(self) -> Dict[str, dict]:
        """列出所有插件信息"""
        plugins_info = {}
        
        for plugin_name, plugin in self.plugins.items():
            plugins_info[plugin_name] = {
                'name': plugin_name,
                'type': plugin.plugin_type.value,
                'enabled': self.is_plugin_enabled(plugin_name),
                'functions_count': len(plugin.functions),
                'functions': list(plugin.functions.keys()),
                'path': str(plugin.plugin_dir)
            }
        
        return plugins_info
    
    def get_plugin_info(self, plugin_name: str) -> Optional[dict]:
        """获取插件详细信息"""
        if plugin_name not in self.plugins:
            return None
        
        plugin = self.plugins[plugin_name]
        
        return {
            'name': plugin_name,
            'type': plugin.plugin_type.value,
            'enabled': self.is_plugin_enabled(plugin_name),
            'path': str(plugin.plugin_dir),
            'functions_count': len(plugin.functions),
            'functions': {
                name: {
                    'name': info['name'],
                    'description': info['description'],
                    'type': info['type']
                }
                for name, info in plugin.functions.items()
            }
        }
    
    def search_functions(self, keyword: str) -> List[dict]:
        """搜索函数"""
        results = []
        
        for plugin_name, plugin in self.plugins.items():
            if not self.is_plugin_enabled(plugin_name):
                continue
            
            for func_name, func_info in plugin.functions.items():
                if (keyword.lower() in func_name.lower() or 
                    keyword.lower() in func_info.get('description', '').lower()):
                    
                    results.append({
                        'plugin': plugin_name,
                        'function': func_name,
                        'description': func_info.get('description', ''),
                        'type': func_info.get('type', ''),
                        'command': f"gs {plugin_name} {func_name}",
                        'shortcut': f"gs-{plugin_name}-{func_name}"
                    })
        
        return results
    
    def get_all_shortcuts(self) -> Dict[str, str]:
        """获取所有快捷命令映射"""
        return self.loader.get_plugin_shortcuts()
    
    def generate_shell_functions(self, output_file: Path):
        """生成Shell函数文件"""
        self.loader.generate_shell_functions(output_file)
    
    def _load_plugin_states(self):
        """从新JSON配置(system_plugins/custom_plugins)加载启用状态"""
        try:
            if not self.config_manager:
                raise RuntimeError("ConfigManager not initialized")
            
            cfg = self.config_manager.get_config() or {}
            system_map = cfg.get('system_plugins', {}) or {}
            custom_map = cfg.get('custom_plugins', {}) or {}

            for name, plugin in self.plugins.items():
                if name in system_map:
                    self.enabled_plugins[name] = bool(system_map[name])
                elif name in custom_map:
                    self.enabled_plugins[name] = bool(custom_map[name])
                else:
                    # 不在配置中的插件默认禁用（保持显式控制）
                    self.enabled_plugins[name] = False
        except Exception as e:
            logger.error(f"Failed to load plugin states: {e}")
            import traceback
            traceback.print_exc()
            # 失败则全部禁用
            for name in self.plugins.keys():
                self.enabled_plugins[name] = False


    def _save_plugin_states(self):
        """保存启用状态回 system_plugins/custom_plugins 映射"""
        try:
            if not self.config_manager:
                return
            cfg = self.config_manager.get_config() or {}
            system_map = cfg.get('system_plugins', {}) or {}
            custom_map = cfg.get('custom_plugins', {}) or {}

            for name, enabled in self.enabled_plugins.items():
                if name in system_map:
                    system_map[name] = bool(enabled)
                elif name in custom_map:
                    custom_map[name] = bool(enabled)
                # 不自动添加新键，保持显式；如需新增应在其它命令里完成

            cfg['system_plugins'] = system_map
            cfg['custom_plugins'] = custom_map
            self.config_manager.save_config(cfg)
        except Exception as e:
            logger.error(f"Failed to save plugin states: {e}")
    
    async def health_check(self) -> Dict[str, Any]:
        """插件系统健康检查"""
        health = {
            'status': 'healthy',
            'plugins_total': len(self.plugins),
            'plugins_enabled': len([p for p in self.enabled_plugins.values() if p]),
            'plugins_disabled': len([p for p in self.enabled_plugins.values() if not p]),
            'functions_total': sum(len(p.functions) for p in self.plugins.values()),
            'failed_plugins': len(self.loader.failed_plugins),
            'issues': []
        }
        
        # 检查失败的插件
        if self.loader.failed_plugins:
            health['issues'].extend([
                f"Failed to load plugin {name}: {error}"
                for name, error in self.loader.failed_plugins.items()
            ])
        
        # 检查插件目录
        if not self.plugins_root.exists():
            health['status'] = 'unhealthy'
            health['issues'].append(f"Plugins directory does not exist: {self.plugins_root}")
        
        return health
    
    def _regenerate_completions(self):
        """重新生成tab补全脚本并提示用户重载环境"""
        try:
            import subprocess
            import os
            from pathlib import Path

            # 获取项目根目录
            project_root = Path(__file__).resolve().parents[3]
            setup_py = project_root / "scripts" / "setup.py"

            if not setup_py.exists():
                from gscripts.utils.i18n import I18nManager
                i18n = I18nManager()
                logger.info(i18n.get_message('errors.file_not_found', file=str(setup_py)))
                return

            # 重新生成补全文件
            try:
                result = subprocess.run([
                    "python3", str(setup_py), "--generate-completion", "--auto"
                ], cwd=project_root, capture_output=True, text=True, timeout=30)

                if result.returncode == 0:
                    from gscripts.utils.i18n import I18nManager
                    i18n = I18nManager()
                    logger.info(i18n.get_message('commands.command_success'))

                    # 生成 router index
                    self._generate_router_index()

                    logger.info(i18n.get_message('setup.source_instruction'))
                else:
                    logger.info(i18n.get_message('errors.execution_failed', error=f"completion rc={result.returncode}"))
                    logger.info(i18n.get_message('setup.source_instruction'))

            except subprocess.TimeoutExpired:
                from gscripts.utils.i18n import I18nManager
                i18n = I18nManager()
                logger.info(i18n.get_message('errors.timeout', timeout=30))
            except Exception as e:
                from gscripts.utils.i18n import I18nManager
                i18n = I18nManager()
                logger.info(i18n.get_message('errors.execution_failed', error=str(e)))

        except Exception as e:
            from gscripts.utils.i18n import I18nManager
            i18n = I18nManager()
            logger.info(i18n.get_message('errors.execution_failed', error=str(e)))

    def _generate_router_index(self):
        """生成 router index 用于 shell/json 命令分发"""
        try:
            from ..router.indexer import build_router_index, write_router_index

            # 构建 router index
            index = build_router_index(self.plugins)

            # 写入 router index
            index_path = write_router_index(index)

            logger.info(f"router_index generated path={index_path} plugins={len(index)}")
        except Exception as e:
            logger.error(f"router_index generation failed error={type(e).__name__}: {e}")

    # ============= Observer 模式实现 =============

    def register_observer(self, observer: IPluginObserver) -> None:
        """
        注册插件观察者

        Args:
            observer: 观察者实例，实现 IPluginObserver 接口
        """
        if observer not in self._observers:
            self._observers.append(observer)
            logger.debug(f"observer registered name={observer.observer_name}")

    def unregister_observer(self, observer: IPluginObserver) -> None:
        """
        取消注册插件观察者

        Args:
            observer: 观察者实例
        """
        if observer in self._observers:
            self._observers.remove(observer)
            logger.debug(f"observer unregistered name={observer.observer_name}")

    def notify_observers(self, event_data: PluginEventData) -> None:
        """
        通知所有观察者插件事件

        Args:
            event_data: 事件数据
        """
        if not self._observers:
            return

        cid = correlation_id()
        logger.debug(
            f"cid={cid} notify_observers event={event_data.event.value} "
            f"plugin={event_data.plugin_name} observers={len(self._observers)}"
        )

        for observer in self._observers:
            try:
                observer.on_plugin_event(event_data)
            except Exception as e:
                # 观察者异常不应影响主流程
                logger.error(
                    f"cid={cid} observer error observer={observer.observer_name} "
                    f"event={event_data.event.value} error={type(e).__name__}: {e}"
                )

    def _notify(self, event: PluginEvent, plugin_name: str, **kwargs) -> None:
        """
        便捷方法：创建事件数据并通知观察者

        Args:
            event: 事件类型
            plugin_name: 插件名称
            **kwargs: 额外的事件数据字段
        """
        event_data = PluginEventData(
            event=event,
            plugin_name=plugin_name,
            plugin=kwargs.get('plugin'),
            function_name=kwargs.get('function_name'),
            result=kwargs.get('result'),
            error=kwargs.get('error'),
            metadata=kwargs.get('metadata')
        )
        self.notify_observers(event_data)
