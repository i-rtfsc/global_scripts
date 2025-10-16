"""
插件加载器
支持四种插件类型的自动检测和加载
"""

import asyncio
import json
import importlib.util
import sys
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Type
from dataclasses import dataclass, field
from enum import Enum

from .config_manager import CommandResult
from .constants import GlobalConstants
from ..utils.i18n import I18nManager
from ..utils.cache import load_plugin_json as load_cached_plugin_json


from ..core.logger import get_logger
from ..utils.logging_utils import (
    redact, redact_kv, redact_command, ctx, correlation_id,
    duration, trunc, sanitize_path, format_size, safe_repr,
    log_context, format_exception, measure_time
)

# Module-level logger
logger = get_logger(tag="CORE.PLUGIN_LOADER", name=__name__)


class PluginType(Enum):
    """插件类型枚举"""
    PYTHON = "python"
    CONFIG = "config"
    SCRIPT = "script"
    HYBRID = "hybrid"


@dataclass
class PluginScanResult:
    """插件扫描结果"""
    plugin_dir: Path
    plugin_type: PluginType
    has_python: bool = False
    has_config: bool = False
    has_scripts: bool = False
    python_file: Optional[Path] = None
    config_files: List[Path] = field(default_factory=list)
    script_files: List[Path] = field(default_factory=list)
    metadata_files: List[Path] = field(default_factory=list)


class SimplePlugin:
    """简化的插件基类"""
    
    def __init__(self, plugin_dir: Path, plugin_type: PluginType):
        self.constants = GlobalConstants()
        self.plugin_dir = plugin_dir
        self.name = plugin_dir.name
        self.plugin_type = plugin_type
        self.functions: Dict[str, dict] = {}
        self.is_example = False  # 标记是否为示例插件
        self.enabled = True
        self.i18n = I18nManager()

        # 从plugin.json加载的元数据
        self.version = "1.0.0"
        self.author = "Unknown"
        self.description = {"zh": f"{self.name}插件", "en": f"{self.name} plugin"}
        self.priority = 50
        self.requirements = {"system": [], "python": []}
        self.tags: List[str] = []
        self.subplugins: List[str] = []  # 兼容旧代码，保存子插件名称列表
        self.subplugins_full: List[Dict[str, Any]] = []  # 保存完整的子插件信息（含描述）

        # 尝试加载plugin.json配置
        self._load_plugin_config()
    
    def _load_plugin_config(self):
        """从plugin.json加载插件配置"""
        plugin_json = self.plugin_dir / self.constants.PLUGIN_JSON_FILE
        if plugin_json.exists():
            try:
                # 使用缓存加载plugin.json
                config = load_cached_plugin_json(plugin_json)
                if not config:
                    logger.warning(f"Empty or invalid plugin.json file for plugin {self.name}")
                    return

                # 更新插件元数据
                self.name = config.get('name', self.name)  # 从plugin.json加载真实名称
                self.version = config.get('version', self.version)
                self.author = config.get('author', self.author)
                self.description = config.get('description', self.description)
                self.priority = config.get('priority', self.priority)
                self.enabled = config.get('enabled', self.enabled)
                self.requirements = config.get('requirements', self.requirements)
                self.tags = config.get('tags', self.tags)

                # 处理 subplugins - 支持字符串数组或字典数组
                subplugins_raw = config.get('subplugins', [])
                if subplugins_raw:
                    self.subplugins = []
                    self.subplugins_full = []
                    for sp in subplugins_raw:
                        if isinstance(sp, str):
                            # 字符串格式：直接使用
                            self.subplugins.append(sp)
                            self.subplugins_full.append({
                                "name": sp,
                                "description": {"zh": "", "en": ""}
                            })
                        elif isinstance(sp, dict):
                            # 字典格式：保存完整信息并提取 name
                            name = sp.get('name', '')
                            if name:
                                self.subplugins.append(name)
                                # 标准化 description
                                desc = sp.get('description', {})
                                if isinstance(desc, str):
                                    desc = {"zh": desc, "en": desc}
                                elif not isinstance(desc, dict):
                                    desc = {"zh": "", "en": ""}
                                self.subplugins_full.append({
                                    "name": name,
                                    "description": desc
                                })
                    # 过滤空字符串
                    self.subplugins = [sp for sp in self.subplugins if sp]
                    self.subplugins_full = [sp for sp in self.subplugins_full if sp.get('name')]
                
                # 保存完整配置，以便后续处理commands字段
                self._plugin_json_config = config

            except Exception as e:
                logger.warning(f"Failed to load config for plugin {self.name} (file: {plugin_json}): {e}")
    
    def get_display_info(self, language='zh'):
        """获取插件显示信息"""
        # 确定语言
        self.i18n.set_language(language)
        desc = self.description
        if isinstance(desc, dict):
            # 字典描述，按当前语言选择
            desc = desc.get(language) or desc.get('zh') or desc.get('en') or f"{self.name}"
        elif not isinstance(desc, str):
            desc = f"{self.name}"
        
        # 获取来源类型（用于插件列表）
        plugin_source_type = self._get_plugin_source_type_text(language)
        
        # 获取实现类型（用于插件详情）
        plugin_impl_type = self._get_plugin_implementation_type_text(language)
            
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": desc,
            "enabled": self.enabled,
            "priority": self.priority,
            "directory": str(self.plugin_dir),
            "tags": self.tags,
            "requirements": self.requirements,
            "type": plugin_source_type,  # 默认返回来源类型（用于插件列表）
            "source_type": plugin_source_type,
            "implementation_type": plugin_impl_type
        }
    
    def _get_plugin_source_type_text(self, language='zh'):
        """获取插件来源类型的多语言文本（系统插件 vs 第三方插件）"""
        self.i18n.set_language(language)
        # 首先检查是否为示例插件
        if self.is_example:
            return 'Example Plugin' if language == 'en' else '示例插件'
            
        plugin_path_str = str(self.plugin_dir)
        # 检查路径是否包含examples
        if '/examples/' in plugin_path_str or 'examples' in plugin_path_str.split('/'):
            return 'Example Plugin' if language == 'en' else '示例插件'
        elif '/plugins/' in plugin_path_str or 'plugins' in plugin_path_str.split('/'):
            return self.i18n.get_message('plugin_source_types.system')
        elif '/custom/' in plugin_path_str or 'custom' in plugin_path_str.split('/'):
            return self.i18n.get_message('plugin_source_types.third_party')
        else:
            # 没有定义未知类型的i18n，保持简单回退
            return 'Unknown Plugin' if language == 'en' else '未知插件'
    
    def _get_plugin_implementation_type_text(self, language='zh'):
        """获取插件实现类型的多语言文本（Python插件 vs Shell插件 etc）"""
        self.i18n.set_language(language)
        # 判断实现类型
        has_python = (self.plugin_dir / self.constants.PLUGIN_PY_FILE).exists()
        has_json = (self.plugin_dir / self.constants.PLUGIN_JSON_FILE).exists()
        has_shell = len(list(self.plugin_dir.glob("*.sh"))) > 0
        
        # 确定实现类型
        if has_python and has_json and has_shell:
            return self.i18n.get_message('plugin_implementation_types.hybrid')
        elif has_python:
            return self.i18n.get_message('plugin_implementation_types.python')
        elif has_shell:
            return self.i18n.get_message('plugin_implementation_types.script')
        elif has_json:
            return self.i18n.get_message('plugin_implementation_types.config')
        else:
            return "Unknown Plugin" if language == 'en' else "未知插件"
    
    def get_shortcut_commands(self) -> Dict[str, str]:
        """生成快捷命令映射"""
        shortcuts = {}
        for func_name in self.functions:
            shortcuts[f"gs-{self.name}-{func_name}"] = f"{self.name} {func_name}"
        return shortcuts


class PluginLoader:
    """智能插件加载器"""
    
    def __init__(self, plugins_root: Union[str, Path]):
        self.plugins_root = Path(plugins_root)
        if not self.plugins_root.exists():
            gs_root = os.environ.get('GS_ROOT')
            if gs_root:
                candidate = Path(gs_root) / 'plugins'
                if candidate.exists():
                    self.plugins_root = candidate
        # If pointing to project root, shift into its plugins subdirectory
        if self.plugins_root.exists() and (self.plugins_root / 'plugins').exists() and self.plugins_root.name != 'plugins':
            potential = self.plugins_root / 'plugins'
            if potential.is_dir():
                self.plugins_root = potential
        self.loaded_plugins: Dict[str, SimplePlugin] = {}
        self.failed_plugins: Dict[str, str] = {}
    
    async def load_all_plugins(self) -> Dict[str, SimplePlugin]:
        """加载所有插件"""
        import os
        
        if not self.plugins_root.exists():
            logger.warning(f"Plugins directory {self.plugins_root} does not exist")
            return {}
        
        # 扫描所有插件目录
        plugin_dirs = [p for p in self.plugins_root.iterdir() if p.is_dir()]
        
        # 检查是否启用示例插件显示
        # 优先从环境变量读取；未设置再从 ConfigManager 的最终合并配置读取 (config.config_data)
        env_flag = os.getenv('GS_CONFIG_SHOW_EXAMPLES')
        if env_flag is not None:
            show_examples = env_flag.lower() in ('1', 'true', 'yes', 'y')
        else:
            try:
                from .config_manager import ConfigManager
                cfgm = ConfigManager()
                show_examples = bool(cfgm.config_data.get('show_examples', False))
            except Exception:
                show_examples = False

        if show_examples:
            examples_root = self.plugins_root.parent / 'examples'
            if examples_root.exists():
                example_dirs = [p for p in examples_root.iterdir() if p.is_dir()]
                plugin_dirs.extend(example_dirs)

        # 扫描自定义插件目录（支持嵌套结构）
        custom_root = self.plugins_root.parent / 'custom'
        if custom_root.exists():
            custom_plugin_dirs = await self._discover_custom_plugins_recursive(custom_root)
            plugin_dirs.extend(custom_plugin_dirs)

        # 收集所有待加载的插件信息
        plugin_tasks = []

        for plugin_dir in plugin_dirs:
            # 只从plugin.json读取插件名，不使用fallback
            plugin_json = plugin_dir / "plugin.json"

            if not plugin_json.exists():
                logger.debug(f"跳过没有plugin.json的目录: {plugin_dir}")
                continue

            try:
                # 使用缓存加载plugin.json
                config = load_cached_plugin_json(plugin_json)
                if not config:
                    logger.warning(f"读取plugin.json失败，跳过目录 {plugin_dir}")
                    continue

                plugin_name = config.get('name')

                if not plugin_name:
                    logger.warning(f"跳过plugin.json缺少name字段的目录: {plugin_dir}")
                    continue

                # 判断是否为自定义插件
                is_custom_plugin = custom_root.exists() and custom_root in plugin_dir.parents

                # 判断是否为示例插件
                is_example = show_examples and 'examples' in str(plugin_dir)

                # 收集加载任务
                plugin_tasks.append({
                    'name': plugin_name,
                    'dir': plugin_dir,
                    'is_example': is_example,
                    'is_custom': is_custom_plugin
                })

            except Exception as e:
                logger.warning(f"读取plugin.json失败，跳过目录 {plugin_dir}: {e}")
                continue

        # 并发加载所有插件
        async def load_single_plugin(task_info):
            """加载单个插件的辅助函数"""
            try:
                plugin = await self.load_plugin(
                    task_info['name'],
                    is_example=task_info['is_example'],
                    is_custom=task_info['is_custom'],
                    plugin_dir=task_info['dir']
                )
                if plugin:
                    return task_info['name'], plugin, None
                return task_info['name'], None, "Failed to load"
            except Exception as e:
                return task_info['name'], None, str(e)

        # 使用asyncio.gather并发加载（限制并发数为10）
        batch_size = 10
        for i in range(0, len(plugin_tasks), batch_size):
            batch = plugin_tasks[i:i+batch_size]
            results = await asyncio.gather(*[load_single_plugin(task) for task in batch], return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    logger.error(f"插件加载异常: {result}")
                    continue

                plugin_name, plugin, error = result
                if plugin:
                    self.loaded_plugins[plugin_name] = plugin
                elif error:
                    self.failed_plugins[plugin_name] = error
                    logger.error(f"Failed to load plugin {plugin_name}: {error}")
        
        return self.loaded_plugins
    
    async def load_plugin(self, plugin_name: str, is_example: bool = False, is_custom: bool = False, plugin_dir: Optional[Path] = None) -> Optional[SimplePlugin]:
        """加载单个插件"""
        if plugin_dir is None:
            # 传统模式：根据插件名构建路径
            plugin_dir = self.plugins_root / plugin_name
            if not plugin_dir.exists() or not plugin_dir.is_dir():
                # 如果在plugins目录下找不到，尝试在examples目录下找
                if is_example:
                    examples_root = Path(os.environ.get('GS_CONFIG_BASE_DIR', os.getcwd())) / "examples"
                    plugin_dir = examples_root / plugin_name
                    if not plugin_dir.exists() or not plugin_dir.is_dir():
                        return None
                else:
                    return None
        else:
            # 新模式：直接使用提供的目录路径
            if not plugin_dir.exists() or not plugin_dir.is_dir():
                return None
        
        # 扫描插件目录
        scan_result = self._scan_plugin_directory(plugin_dir)
        
        # 创建插件实例并发现函数
        plugin = SimplePlugin(plugin_dir, scan_result.plugin_type)
        plugin.is_example = is_example

        # 对于自定义插件，保存插件ID（完整路径）但保持显示名称不变
        if is_custom:
            plugin.plugin_id = plugin_name  # 保存完整路径用于调用
        else:
            plugin.plugin_id = plugin.name   # 系统插件使用简单名称

        await self._discover_functions(plugin, scan_result)
        
        return plugin if plugin.functions else None
    
    def _scan_plugin_directory(self, plugin_dir: Path) -> PluginScanResult:
        """扫描插件目录，确定插件类型"""
        result = PluginScanResult(plugin_dir=plugin_dir, plugin_type=PluginType.PYTHON)

        # 检查Python文件
        plugin_py = plugin_dir / "plugin.py"
        if plugin_py.exists():
            result.has_python = True
            result.python_file = plugin_py

        # 检查配置文件 - 根据 plugin.json 的 entry 字段或扫描常见名称
        plugin_json = plugin_dir / "plugin.json"
        config_entry = None

        if plugin_json.exists():
            try:
                # 使用缓存加载plugin.json
                data = load_cached_plugin_json(plugin_json)
                if data:
                    # 如果 type 是 json/config，检查 entry 字段
                    if data.get('type') in ('json', 'config'):
                        config_entry = data.get('entry')
            except Exception:
                pass

        # 根据 entry 字段或扫描默认配置文件
        if config_entry:
            config_file = plugin_dir / config_entry
            if config_file.exists() and config_file.is_file():
                result.has_config = True
                result.config_files.append(config_file)
        else:
            # 扫描常见配置文件名
            for config_pattern in ["**/config.json", "**/commands.json"]:
                for config_file in plugin_dir.glob(config_pattern):
                    if config_file.is_file():
                        result.has_config = True
                        result.config_files.append(config_file)
        
        # 检查脚本文件
        for script_file in plugin_dir.glob("**/*.sh"):
            if script_file.is_file():
                result.has_scripts = True
                result.script_files.append(script_file)
        
        # 确定插件类型
        type_count = sum([result.has_python, result.has_config, result.has_scripts])
        
        if type_count > 1:
            result.plugin_type = PluginType.HYBRID
        elif result.has_python:
            result.plugin_type = PluginType.PYTHON
        elif result.has_config:
            result.plugin_type = PluginType.CONFIG
        elif result.has_scripts:
            result.plugin_type = PluginType.SCRIPT
        
        return result
    
    async def _discover_functions(self, plugin: SimplePlugin, scan_result: PluginScanResult):
        """发现插件函数 - 支持新的子插件目录结构"""
        try:
            # 子插件目录结构：同时发现子插件与主插件的python函数（若存在）
            if plugin.subplugins:
                await self._discover_subplugin_functions(plugin)
                if scan_result.python_file and scan_result.python_file.exists():
                    await self._discover_python_functions(plugin, scan_result.python_file)
            # 传统方式：仅主插件python
            elif scan_result.python_file:
                await self._discover_python_functions(plugin, scan_result.python_file)
            
            # 同时处理配置文件和脚本（仅限插件根目录，子插件已经在上面处理过）
            for config_file in scan_result.config_files:
                await self._discover_config_functions(plugin, config_file)
            
            # 只处理插件根目录的脚本文件，避免重复处理子插件目录的脚本
            for script_file in scan_result.script_files:
                # 检查脚本文件是否在子插件目录中
                is_in_subplugin = any(subplugin in str(script_file) for subplugin in plugin.subplugins)
                if not is_in_subplugin:
                    self._discover_script_functions(plugin, script_file)
            
            # 对于纯JSON插件，从plugin.json的commands字段加载函数
            if hasattr(plugin, '_plugin_json_config') and 'commands' in plugin._plugin_json_config:
                await self._discover_commands_from_plugin_json(plugin)
        
        except Exception as e:
            logger.error(f"Error discovering functions for {plugin.name}: {e}")
    
    async def _discover_subplugin_functions(self, plugin: SimplePlugin):
        """发现子插件目录中的函数"""
        for subplugin_name in plugin.subplugins:
            subplugin_dir = plugin.plugin_dir / subplugin_name
            if not subplugin_dir.exists() or not subplugin_dir.is_dir():
                logger.debug(f"Subplugin directory {subplugin_dir} not found")
                continue
            
            # 查找子插件目录中的plugin.py文件
            subplugin_python = subplugin_dir / "plugin.py"
            if subplugin_python.exists():
                await self._discover_python_functions_in_subplugin(plugin, subplugin_python, subplugin_name)
            
            # 查找其他类型的文件
            for config_file in subplugin_dir.glob("*.json"):
                if config_file.name != "plugin.json":  # 排除配置文件
                    await self._discover_config_functions_in_subplugin(plugin, config_file, subplugin_name)
            
            for script_file in subplugin_dir.glob("*.sh"):
                self._discover_script_functions_in_subplugin(plugin, script_file, subplugin_name)
    
    async def _discover_python_functions_in_subplugin(self, plugin: SimplePlugin, python_file: Path, subplugin_name: str):
        """在子插件目录中发现Python函数"""
        try:
            with open(python_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            import re
            
            # 查找@plugin_function装饰器和相关信息（支持async def与def）
            # 更复杂的正则表达式来提取name和description，支持多行装饰器
            func_pattern = r'@plugin_function\s*\(([\s\S]*?)\)\s*(?:@\w+[\s\S]*?)*(?:async\s+def|def)\s+(\w+)'
            matches = re.findall(func_pattern, content)
            
            for decorator_content, method_name in matches:
                # 解析装饰器参数
                func_info = self._parse_plugin_function_decorator(decorator_content)

                if func_info and 'name' in func_info:
                    func_name = func_info['name']
                    function_key = f'{subplugin_name}-{func_name}'
                    
                    # 获取描述，支持中英文
                    description = func_info.get('description', f"{func_name}命令")
                    
                    plugin.functions[function_key] = {
                        'name': func_name,
                        'subplugin': subplugin_name,
                        'method': method_name,
                        'description': description,
                        'usage': func_info.get('usage', ''),
                        'examples': func_info.get('examples', []),
                        'args': func_info.get('args', []),
                        'command': f"python3 {python_file.resolve()} {func_name}",
                        'type': 'python_decorated',
                        'python_file': python_file
                    }
        
        except Exception as e:
            logger.error(f"Error parsing subplugin Python file {python_file}: {e}")
            import traceback
            traceback.print_exc()
    
    def _parse_plugin_function_decorator(self, decorator_content: str) -> dict:
        """解析@plugin_function装饰器内容"""
        import re
        func_info = {}

        # 移除多余的空白字符和换行符，便于解析
        cleaned_content = re.sub(r'\s+', ' ', decorator_content.strip())
        
        # 提取name参数
        name_match = re.search(r'name\s*=\s*["\']([^"\']+)["\']', cleaned_content)
        if name_match:
            func_info['name'] = name_match.group(1)
        
        # 提取description参数 - 支持字典格式的多语言描述
        # 首先尝试匹配字典格式: description={"zh": "中文", "en": "English"}
        desc_dict_match = re.search(r'description\s*=\s*\{\s*["\']zh["\']\s*:\s*["\']([^"\']*)["\'],?\s*["\']en["\']\s*:\s*["\']([^"\']*)["\']', cleaned_content)
        if desc_dict_match:
            func_info['description'] = {
                'zh': desc_dict_match.group(1),
                'en': desc_dict_match.group(2)
            }
        else:
            # 如果不是字典格式，尝试简单字符串格式
            desc_match = re.search(r'description\s*=\s*["\']([^"\']*)["\']', cleaned_content)
            if desc_match:
                func_info['description'] = desc_match.group(1)
        
        # 提取usage参数
        usage_match = re.search(r'usage\s*=\s*["\']([^"\']+)["\']', decorator_content)
        if usage_match:
            func_info['usage'] = usage_match.group(1)
        
        # 提取examples参数（列表形式）
        examples_match = re.search(r'examples\s*=\s*\[([\s\S]*?)\]', decorator_content)
        if examples_match:
            examples_str = examples_match.group(1)
            examples = re.findall(r'["\']([^"\']+)["\']', examples_str)
            func_info['examples'] = examples

        # 提取args参数（列表形式,包含字典）
        # 需要正确处理嵌套括号
        args_start_match = re.search(r'args\s*=\s*\[', decorator_content)
        if args_start_match:
            # 从args=[ 开始,手动匹配括号
            start_pos = args_start_match.end() - 1  # 包含 [
            bracket_count = 0

            for i in range(start_pos, len(decorator_content)):
                char = decorator_content[i]
                if char == '[':
                    bracket_count += 1
                elif char == ']':
                    bracket_count -= 1
                    if bracket_count == 0:
                        # 找到匹配的 ]
                        args_str = decorator_content[start_pos:i+1]
                        try:
                            import ast
                            parsed_args = ast.literal_eval(args_str)
                            func_info['args'] = parsed_args
                        except (SyntaxError, ValueError):
                            # 解析失败,设为空列表
                            func_info['args'] = []
                        break

        return func_info
    
    async def _discover_config_functions_in_subplugin(self, plugin: SimplePlugin, config_file: Path, subplugin_name: str):
        """在子插件目录中发现配置文件函数"""
        try:
            if config_file.suffix == '.json':
                # 使用缓存加载plugin.json
                data = load_cached_plugin_json(config_file)
                if data and 'commands' in data:
                    for cmd_name, cmd_info in data['commands'].items():
                        function_key = f'{subplugin_name}-{cmd_name}'
                        plugin.functions[function_key] = {
                            'name': cmd_name,
                            'subplugin': subplugin_name,
                            'description': cmd_info.get('description', f'{cmd_name}命令'),
                            'command': cmd_info.get('command', f'echo "No command defined for {cmd_name}"'),
                            'type': 'config',
                            'config_file': config_file
                        }
        except Exception as e:
            logger.error(f"Error parsing subplugin config file {config_file}: {e}")
    
    def _discover_script_functions_in_subplugin(self, plugin: SimplePlugin, script_file: Path, subplugin_name: str):
        """在子插件目录中发现脚本文件函数 - 支持Shell注解"""
        try:
            # 尝试解析Shell注解
            shell_functions = self._parse_shell_function_annotations(script_file, subplugin_name)
            
            if shell_functions:
                # 找到Shell注解，添加所有注解函数
                for func_info in shell_functions:
                    function_key = f"{subplugin_name}-{func_info['name']}"
                    plugin.functions[function_key] = func_info
            else:
                # 没有找到注解，回退到基于文件名的方法
                script_name = script_file.stem  
                function_key = f'{subplugin_name}-{script_name}'
                plugin.functions[function_key] = {
                    'name': script_name,
                    'subplugin': subplugin_name,
                    'description': f'{script_name}脚本',
                    'command': f'bash {script_file}',
                    'type': 'script',
                    'script_file': script_file
                }
        except Exception as e:
            logger.error(f"Error processing subplugin script file {script_file}: {e}")
    
    def _parse_shell_function_annotations(self, script_file: Path, subplugin_name: str) -> List[dict]:
        """解析Shell脚本中的@plugin_function注解"""
        try:
            with open(script_file, 'r', encoding='utf-8') as f:
                content = f.read()
            
            import re
            
            functions = []
            
            # 使用正则表达式查找所有 @plugin_function 注解块
            # 匹配模式: # @plugin_function 开头，到函数定义结束，支持多行description
            annotation_pattern = r'# @plugin_function\s*\n((?:# .*\n)*)((?:# examples:\s*\n(?:# {2,}- .*\n)*)?)\s*(\w+)\s*\(\s*\)\s*\{'
            
            matches = re.findall(annotation_pattern, content, re.MULTILINE)
            
            for metadata_lines, examples_block, function_name in matches:
                # 构建正确的usage字符串
                plugin_name = script_file.parent.parent.name if script_file.parent.name != 'plugins' else script_file.parent.name
                if subplugin_name:
                    usage = f'gs {plugin_name} {subplugin_name} {function_name}'
                else:
                    usage = f'gs {plugin_name} {function_name}'

                func_info = {
                    'name': function_name,
                    'subplugin': subplugin_name,
                    'description': f'{function_name}函数',
                    'usage': usage,
                    'examples': [],
                    'command': f'bash {script_file} {function_name}',
                    'type': 'shell_annotated',
                    'script_file': script_file
                }
                
                # 解析元数据行
                description_dict = {}
                current_section = None
                
                for line in metadata_lines.strip().split('\n'):
                    line = line.strip()
                    if not line or not line.startswith('#'):
                        continue
                    
                    line_content = line[1:].strip()  # 移除开头的 #
                    
                    if line_content.startswith('name:'):
                        # 注解中的name会覆盖函数名（用于别名）
                        annotated_name = line_content.split(':', 1)[1].strip()
                        if annotated_name:
                            func_info['name'] = annotated_name
                    elif line_content.startswith('description:'):
                        current_section = 'description'
                        # 如果description后面直接有内容，则是单行格式
                        desc_value = line_content.split(':', 1)[1].strip()
                        if desc_value:
                            func_info['description'] = desc_value
                            current_section = None
                    elif line_content.startswith('usage:'):
                        func_info['usage'] = line_content.split(':', 1)[1].strip()
                        current_section = None
                    elif current_section == 'description':
                        # 处理多行description格式
                        if line_content.startswith('zh:'):
                            description_dict['zh'] = line_content.split(':', 1)[1].strip()
                        elif line_content.startswith('en:'):
                            description_dict['en'] = line_content.split(':', 1)[1].strip()
                
                # 如果有多语言描述，则使用字典格式
                if description_dict:
                    func_info['description'] = description_dict
                
                # 解析examples
                if examples_block:
                    example_lines = re.findall(r'# {2,}- (.+)', examples_block)
                    func_info['examples'] = example_lines
                
                # 更新命令以调用特定函数 - 确保使用绝对路径
                absolute_script_path = script_file.resolve()
                func_info['command'] = f'bash {absolute_script_path} {func_info["name"]}'
                
                functions.append(func_info)
            
            return functions
            
        except Exception as e:
            logger.error(f"Error parsing shell annotations in {script_file}: {e}")
            return []
    
    async def _discover_config_functions(self, plugin: SimplePlugin, config_file: Path):
        """发现配置文件中的函数"""
        try:
            if config_file.suffix == '.json':
                # 使用缓存加载plugin.json
                data = load_cached_plugin_json(config_file)
                if not data:
                    logger.warning(f"无法加载配置文件: {config_file}")
                    return []
            else:
                # 只支持JSON格式
                logger.warning(f"不支持的配置文件格式: {config_file}")
                return []

            # 支持 functions 或 commands 键
            functions_config = data.get('functions', data.get('commands', {}))

            # 生成函数前缀
            relative_path = config_file.relative_to(plugin.plugin_dir)
            prefix = str(relative_path.parent) if relative_path.parent != Path('.') else ''

            for func_name, func_config in functions_config.items():
                if isinstance(func_config, str):
                    command = func_config
                    description = f"Execute: {command}"
                else:
                    command = func_config.get('command', '')
                    description = func_config.get('description', f"Execute: {command}")

                full_name = f"{prefix}-{func_name}" if prefix else func_name
                plugin.functions[full_name] = {
                    'name': func_name,  # 保持原始函数名
                    'subplugin': prefix if prefix else "",  # 根级命令subplugin为空字符串
                    'description': description,
                    'command': command,
                    'type': 'config',
                    'config_file': config_file
                }

        except Exception as e:
            logger.error(f"Error loading config file {config_file}: {e}")
    
    def _discover_script_functions(self, plugin: SimplePlugin, script_file: Path):
        """发现脚本文件中的函数 - 支持Shell注解"""
        try:
            # 尝试解析Shell注解
            # 对于根级函数，subplugin应为空字符串
            shell_functions = self._parse_shell_function_annotations(script_file, "")
            
            if shell_functions:
                # 找到Shell注解，添加所有注解函数
                for func_info in shell_functions:
                    function_key = func_info['name']
                    plugin.functions[function_key] = func_info
            else:
                # 没有找到注解，回退到基于文件名的方法
                relative_path = script_file.relative_to(plugin.plugin_dir)
                if relative_path.parent != Path('.'):
                    func_name = f"{relative_path.parent}-{script_file.stem}"
                else:
                    func_name = script_file.stem
                
                plugin.functions[func_name] = {
                    'name': func_name,
                    'description': f"Execute script: {script_file.name}",
                    'command': str(script_file),
                    'type': 'script',
                    'script_file': script_file
                }
        
        except Exception as e:
            logger.error(f"Error processing script file {script_file}: {e}")
    
    async def _discover_commands_from_plugin_json(self, plugin: SimplePlugin):
        """从plugin.json的commands字段发现函数（用于纯JSON插件）"""
        try:
            commands = plugin._plugin_json_config.get('commands', {})
            
            for cmd_name, cmd_config in commands.items():
                if isinstance(cmd_config, dict):
                    # 获取命令信息
                    command = cmd_config.get('command', '')
                    description = cmd_config.get('description', f"{cmd_name} command")
                    usage = cmd_config.get('usage', f"gs {plugin.name} {cmd_name}")
                    examples = cmd_config.get('examples', [])
                    
                    # 处理多语言描述
                    if isinstance(description, dict):
                        # 保持字典格式，供后续使用
                        pass
                    elif not description:
                        description = f"{cmd_name} command"
                    
                    # 添加到插件函数列表
                    plugin.functions[cmd_name] = {
                        'name': cmd_name,
                        'subplugin': "",  # 根级命令subplugin为空字符串
                        'description': description,
                        'command': command,
                        'usage': usage,
                        'examples': examples,
                        'type': 'config',
                        'config_file': plugin.plugin_dir / 'plugin.json'
                    }
                    
                    logger.debug(f"Discovered command '{cmd_name}' from plugin.json for plugin {plugin.name}")
            
            if commands:
                logger.info(f"Loaded {len(commands)} commands from plugin.json for plugin {plugin.name}")
                
        except Exception as e:
            logger.error(f"Error loading commands from plugin.json for {plugin.name}: {e}")
            logger.error(f"Error loading commands from plugin.json for {plugin.name}: {e}")
    
    async def _discover_python_functions(self, plugin: SimplePlugin, python_file: Path):
        """发现Python文件中的函数 - 解析装饰器"""
        try:
            with open(python_file, 'r', encoding='utf-8') as f:
                content = f.read()

            import re

            # 查找所有@plugin_function装饰器及其后的函数定义
            # 匹配模式：@plugin_function( ... ) 后跟 async def 或 def
            # 使用非贪婪匹配和处理嵌套括号
            decorator_pattern = r'(@plugin_function\s*\([\s\S]*?\n\s*\))\s*(?:async\s+def|def)\s+(\w+)'
            matches = re.findall(decorator_pattern, content)

            for decorator_content, method_name in matches:
                # 解析装饰器内容
                func_info = self._parse_plugin_function_decorator(decorator_content)
                func_name = func_info.get('name', method_name)

                # 获取描述
                description = func_info.get('description', f"{func_name}命令")

                plugin.functions[func_name] = {
                    'name': func_name,
                    'subplugin': '',
                    'method': method_name,
                    'description': description,
                    'usage': func_info.get('usage', ''),
                    'examples': func_info.get('examples', []),
                    'args': func_info.get('args', []),
                    'command': f"python3 {python_file} {func_name}",
                    'type': 'python_decorated',
                    'python_file': python_file
                }

            # 如果没有找到装饰器函数，回退到简单的main函数
            if not plugin.functions:
                plugin.functions['main'] = {
                    'name': 'main',
                    'description': f"Execute Python plugin: {python_file.name}",
                    'command': f"python3 {python_file}",
                    'type': 'python',
                    'python_file': python_file
                }
                
        except Exception as e:
            logger.error(f"Error parsing Python plugin {python_file}: {e}")
            # 回退到简单实现
            plugin.functions['main'] = {
                'name': 'main',
                'description': f"Execute Python plugin: {python_file.name}",
                'command': f"python3 {python_file}",
                'type': 'python',
                'python_file': python_file
            }
                
        except Exception as e:
            logger.error(f"Error parsing Python plugin {python_file}: {e}")
            # 回退到简单实现
            plugin.functions['main'] = {
                'name': 'main',
                'description': f"Execute Python plugin: {python_file.name}",
                'command': f"python3 {python_file}",
                'type': 'python',
                'python_file': python_file
            }
            
            # 如果没有找到装饰器函数，回退到简单的main函数
            if not plugin.functions:
                plugin.functions['main'] = {
                    'name': 'main',
                    'description': f"Execute Python plugin: {python_file.name}",
                    'command': f"python3 {python_file}",
                    'type': 'python',
                    'python_file': python_file
                }
                
        except Exception as e:
            logger.error(f"Error parsing Python plugin {python_file}: {e}")
            # 回退到简单实现
            plugin.functions['main'] = {
                'name': 'main',
                'description': f"Execute Python plugin: {python_file.name}",
                'command': f"python3 {python_file}",
                'type': 'python',
                'python_file': python_file
            }
    
    def get_plugin_shortcuts(self) -> Dict[str, str]:
        """生成所有插件的Shell函数快捷命令"""
        shortcuts = {}
        
        for plugin_name, plugin in self.loaded_plugins.items():
            plugin_shortcuts = plugin.get_shortcut_commands()
            shortcuts.update(plugin_shortcuts)
        
        return shortcuts
    
    def generate_shell_functions(self, output_file: Path):
        """生成Shell函数文件"""
        shortcuts = self.get_plugin_shortcuts()

        # 获取项目根目录 (新结构: src/gscripts/core/plugin_loader.py → 向上4级)
        project_root = Path(__file__).parent.parent.parent.parent.resolve()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("#!/bin/bash\n")
            f.write("# Global Scripts - 自动生成的Shell函数\n\n")
            
            # 基础环境变量
            f.write('# 设置环境变量\n')
            f.write(f'export GS_PROJECT_ROOT="{project_root}"\n')
            f.write('export GS_ROOT="$HOME/.config/global-scripts"\n')
            f.write('export PYTHONPATH="$GS_PROJECT_ROOT:$PYTHONPATH"\n\n')
            
            # 主命令函数
            f.write('# 主命令函数\n')
            f.write('gs() {\n')
            f.write('    cd "$GS_PROJECT_ROOT" && python3 -m gscripts.cli.main "$@"\n')
            f.write('}\n\n')
            
            # 核心命令函数
            f.write('# 核心命令函数\n')
            core_commands = ['help', 'version', 'list', 'health']
            for cmd in core_commands:
                f.write(f'gs-{cmd}() {{ gs {cmd} "$@"; }}\n')
            f.write('\n')
            
            # 插件快捷函数
            f.write('# 插件快捷函数\n')
            for shortcut_name, command_path in sorted(shortcuts.items()):
                f.write(f'{shortcut_name}() {{ gs {command_path} "$@"; }}\n')
            
            f.write('\n')
            f.write(self._generate_env_functions())
            f.write(self._generate_completion_functions())
            
            f.write('\necho "🚀 Global Scripts 环境已加载"\n')
            f.write('echo "   使用 \'gs help\' 查看帮助"\n')            
    
    def _generate_env_functions(self) -> str:
        """生成环境相关函数"""
        return '''
# 环境检查函数
gs-env-check() {
    echo "🔍 Global Scripts 环境检查"
    echo "GS_ROOT: $GS_ROOT"
    echo "Python: $GS_PYTHON"
    
    if [[ -x "$GS_PYTHON" ]]; then
        echo "✅ Python环境: $($GS_PYTHON --version)"
    else
        echo "❌ Python环境未找到"
    fi
    
    if [[ -f "$GS_ROOT/bin/gs" ]]; then
        echo "✅ 主程序已安装"
    else
        echo "❌ 主程序未找到"
    fi
    
    local plugin_count=$(find "$GS_ROOT/plugins" -type d -mindepth 1 -maxdepth 1 2>/dev/null | wc -l)
    echo "📦 已安装插件: ${plugin_count} 个"
}

# 环境更新函数
gs-env-update() {
    echo "🔄 更新 Global Scripts 环境..."
    source "$GS_ROOT/env.sh"
    echo "✅ 环境已重新加载"
}

'''

    async def _discover_custom_plugins_recursive(self, custom_root: Path, parent_path: str = "") -> List[Path]:
        """递归发现自定义插件目录，支持嵌套结构"""
        plugin_dirs = []

        if not custom_root.exists():
            return plugin_dirs

        for item in custom_root.iterdir():
            if not item.is_dir() or item.name.startswith('.'):
                continue

            # 检查是否是插件目录
            is_plugin = any((item / f).exists() for f in ("plugin.json", "plugin.py", "plugin.sh"))

            if is_plugin:
                # 这是一个插件目录，添加到列表
                plugin_dirs.append(item)
            else:
                # 这是一个普通目录，递归搜索
                nested_plugins = await self._discover_custom_plugins_recursive(item, f"{parent_path}/{item.name}" if parent_path else item.name)
                plugin_dirs.extend(nested_plugins)

        return plugin_dirs

    def _generate_completion_functions(self) -> str:
        """生成命令补全函数"""
        return '''
# 命令补全函数
_gs_completion() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    
    case ${COMP_CWORD} in
        1)
            opts="help version plugin system android docker git"
            COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
            ;;
        2)
            case ${prev} in
                plugin)
                    opts="list info enable disable"
                    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
                    ;;
                android)
                    opts="logcat dump input"
                    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
                    ;;
                docker)
                    opts="container image system"
                    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
                    ;;
                git)
                    opts="repo branch remote"
                    COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
                    ;;
            esac
            ;;
    esac
}

# 启用补全
complete -F _gs_completion gs

'''
