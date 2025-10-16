"""
配置管理器 - 纯 JSON 配置管理，支持用户/项目级别配置
"""

import json
import os
import logging
from pathlib import Path
from typing import Dict, Any

from .constants import GlobalConstants
# 使用新的统一数据模型
from ..models import CommandResult, ConfigSchema
from ..utils.cache import load_plugin_json, get_plugin_config_cache

from ..core.logger import get_logger
from ..utils.logging_utils import (
    redact, redact_kv, redact_command, ctx, correlation_id,
    duration, trunc, sanitize_path, format_size, safe_repr,
    log_context, format_exception, measure_time
)

# Module-level logger
logger = get_logger(tag="CORE.CONFIG_MANAGER", name=__name__)

# 向后兼容:保留旧的logger
_compat_logger = logging.getLogger(__name__)
    

    
class ConfigChangeHandler:
    """配置文件变化监控处理器"""
    
    def __init__(self, config_manager):
        self.config_manager = config_manager
        
    def on_modified(self, event):
        if event.is_directory:
            return
            
        file_path = Path(event.src_path)
        if file_path.suffix == '.json':
            logger.info(f"检测到配置文件变化: {file_path}")


class ConfigManager:
    """配置管理器 - 纯 JSON 配置系统"""
    
    def __init__(self):
        self.constants = GlobalConstants()
        self.config_data: Dict[str, Any] = {}
        self.project_root = self._detect_project_root()
        
        # 自动加载用户配置文件
        self._load_user_config()

    def _detect_project_root(self) -> Path:
        """检测项目根目录：
        1) 优先 GS_ROOT 环境变量
        2) 其次：从当前文件向上寻找包含 config/gs.json 或 src/gscripts 目录的路径
        3) 回退：当前文件的上两级目录
        """
        # 1) GS_ROOT
        gs_root = os.environ.get('GS_ROOT')
        if gs_root:
            p = Path(gs_root).expanduser().resolve()
            if (p / 'config').exists():  # 目录存在即可
                return p
        # 2) 向上搜索
        here = Path(__file__).resolve()
        for parent in here.parents:
            if (parent / 'config' / 'gs.json').exists() or (parent / 'src' / 'gscripts').exists():
                return parent
        # 3) 回退
        return Path(__file__).resolve().parents[2]
    
    def _get_config_dir(self) -> Path:
        """获取配置目录路径"""
        return Path.home() / ".config" / "global-scripts"
    
    def get_plugins_dir(self) -> Path:
        """获取插件目录路径
        优先：GS_ROOT/plugins 其次：项目根目录/plugins
        """
        gs_root = os.environ.get('GS_ROOT')
        if gs_root:
            p = Path(gs_root).expanduser().resolve() / 'plugins'
            if p.exists() and p.is_dir():
                return p
        return self.project_root / 'plugins'
    
    def set(self, key: str, value: Any):
        """设置配置值"""
        keys = key.split('.')
        current = self.config_data
        
        for k in keys[:-1]:
            current = current.setdefault(k, {})
        
        current[keys[-1]] = value
    
    def save_config(self, config: Dict[str, Any]):
        """保存配置到适当的配置文件"""
        try:
            cfg_file = self._get_config_file(create_if_missing=True)
            with open(cfg_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=4, ensure_ascii=False)
            logger.info(f"JSON配置已保存到: {cfg_file}")
            self.config_data = config
            
            # 清除配置缓存，确保下次加载时读取最新的文件内容
            cache = get_plugin_config_cache()
            cache.invalidate(cfg_file)
            logger.debug(f"已清除配置缓存: {cfg_file}")
        except Exception as e:
            logger.error(f"保存配置失败: {e}")
            raise
    
    def _generate_default_config(self) -> Dict[str, Any]:
        """生成默认配置（基于实际存在的插件目录）"""
        config: Dict[str, Any] = {
            'system_plugins': {},  # plugin_name: true/false
            'custom_plugins': {},
            # New unified logging level (E/W/I/D/V/NANO or full names). Defaults to INFO.
            # Legacy keys config_debug/config_verbose are deprecated and will be migrated automatically.
            'logging_level': 'INFO',
            'prompt_theme': 'minimalist'
        }
        
        plugins_dir = self.project_root / "plugins"
        custom_dir = self.project_root / "custom"

        # 系统插件 - 从plugin.json读取name字段
        if plugins_dir.exists():
            for plugin_path in plugins_dir.iterdir():
                if plugin_path.is_dir() and not plugin_path.name.startswith('.'):
                    plugin_json = plugin_path / "plugin.json"
                    if plugin_json.exists():
                        try:
                            # 使用缓存加载plugin.json
                            plugin_config = load_plugin_json(plugin_json)
                            if plugin_config:
                                plugin_name = plugin_config.get('name')
                                if plugin_name:
                                    config['system_plugins'][plugin_name] = True
                                else:
                                    logger.warning(f"系统插件 {plugin_path} 的 plugin.json 缺少 name 字段")
                        except Exception as e:
                            logger.warning(f"读取系统插件配置失败 {plugin_json}: {e}")
                    else:
                        # 没有plugin.json的插件跳过
                        logger.warning(f"系统插件 {plugin_path} 缺少 plugin.json")

        # 自定义插件（支持嵌套结构）- 从plugin.json读取name字段
        if custom_dir.exists():
            custom_plugins = self._discover_custom_plugins_recursive(custom_dir)
            for plugin_name in custom_plugins:
                config['custom_plugins'][plugin_name] = True

        logger.info(f"生成默认配置，检测到系统插件: {list(config['system_plugins'].keys())}")
        return config
    
    def _load_user_config(self):
        """加载用户配置文件（优先级：用户gs.json > 项目gs.json > 创建）"""
        try:
            # 路径准备
            user_cfg_dir = self._get_config_dir() / 'config'
            project_cfg_dir = self.project_root / 'config'
            user_json = user_cfg_dir / 'gs.json'
            project_json = project_cfg_dir / 'gs.json'

            user_data: Dict[str, Any] = {}
            project_data: Dict[str, Any] = {}

            # 读取项目配置（作为基础）
            if project_json.exists():
                try:
                    # 使用缓存加载配置
                    project_data = load_plugin_json(project_json) or {}
                except json.JSONDecodeError as je:
                    logger.error(f"项目配置解析失败 {project_json}: {je}")
                    project_data = {}

            # 读取用户配置（作为覆盖）
            if user_json.exists():
                try:
                    # 使用缓存加载配置
                    user_data = load_plugin_json(user_json) or {}
                except json.JSONDecodeError as je:
                    logger.error(f"用户配置解析失败 {user_json}: {je}")
                    user_data = {}

            # 如果都不存在，创建项目默认配置
            if not project_json.exists() and not user_json.exists():
                default_cfg = self._generate_default_config()
                project_json.parent.mkdir(parents=True, exist_ok=True)
                with open(project_json, 'w', encoding='utf-8') as f:
                    json.dump(default_cfg, f, indent=2, ensure_ascii=False)
                project_data = default_cfg
                logger.info(f"创建默认配置: {project_json}")

            # 合并逻辑：项目为基础，用户覆盖；插件映射需要特殊处理
            merged = self._merge_configs(project_data, user_data)
            merged = self._prune_missing_plugins(merged)
            # Migration: if unified logging_level absent, derive from legacy flags
            if 'logging_level' not in merged:
                try:
                    if merged.get('config_debug'):
                        merged['logging_level'] = 'DEBUG'
                    elif merged.get('config_verbose'):
                        # Treat verbose legacy flag as VERBOSE custom level
                        merged['logging_level'] = 'VERBOSE'
                    else:
                        merged['logging_level'] = 'INFO'
                except Exception:
                    merged['logging_level'] = 'INFO'
            # Remove legacy keys to avoid confusion going forward
            if 'config_debug' in merged:
                merged.pop('config_debug', None)
            if 'config_verbose' in merged:
                merged.pop('config_verbose', None)


            self.config_data = merged
            logger.info("JSON配置已加载 (合并 project + user)：系统插件=%s", list(merged.get('system_plugins', {}).keys()))
        except Exception as e:
            logger.error(f"加载配置失败: {e}")
            self.config_data = {}

    def _deep_merge(self, base: Any, override: Any) -> Any:
        """深度合并两个值（递归合并嵌套字典）

        规则：
        1. 如果两个值都是字典，递归合并（用户配置优先）
        2. 如果两个值都是列表，使用用户配置的列表（覆盖）
        3. 其他情况，如果 override 不为 None，使用 override，否则使用 base
        """
        # 如果 override 为 None，返回 base
        if override is None:
            return base

        # 如果两个都是字典，递归合并
        if isinstance(base, dict) and isinstance(override, dict):
            result = dict(base)  # 复制 base
            for key, value in override.items():
                if key in result:
                    # 递归合并
                    result[key] = self._deep_merge(result[key], value)
                else:
                    # 新键，直接添加
                    result[key] = value
            return result

        # 其他情况（包括列表、基本类型等），用户配置优先
        return override

    def _merge_configs(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """合并配置：base(项目) + override(用户)，使用深度合并策略

        用户配置的优先级高于项目配置，但会递归合并嵌套的字典结构。
        """
        if not base:
            base = {}
        if not override:
            override = {}

        # 使用深度合并
        result = self._deep_merge(base, override)

        # 确保返回的是字典
        if not isinstance(result, dict):
            logger.warning(f"配置合并结果不是字典类型，使用空字典")
            return {}

        return result

    def _get_config_file(self, create_if_missing: bool = False) -> Path:
        """获取主配置文件路径，优先级：
        1) ~/.config/global-scripts/config/gs.json (存在即使用)
        2) 项目根目录 ./config/gs.json (如果用户配置不存在)
        若都不存在且 create_if_missing=True，则创建项目级文件并写入默认配置
        """
        user_cfg_dir = self._get_config_dir() / 'config'
        project_cfg_dir = self.project_root / 'config'
        user_json = user_cfg_dir / 'gs.json'
        project_json = project_cfg_dir / 'gs.json'

        if user_json.exists():
            return user_json
        if project_json.exists():
            return project_json

        target = project_json
        if create_if_missing and not target.exists():
            target.parent.mkdir(parents=True, exist_ok=True)
            default_cfg = self._generate_default_config()
            with open(target, 'w', encoding='utf-8') as f:
                json.dump(default_cfg, f, indent=2, ensure_ascii=False)
            logger.info(f"创建默认配置: {target}")
        return target

    def _prune_missing_plugins(self, cfg: Dict[str, Any]) -> Dict[str, Any]:
        """移除 system_plugins/custom_plugins 中物理不存在的插件目录条目"""
        try:
            root = os.environ.get('GS_ROOT') or str(self.project_root)

            # 检查系统插件
            plugins_dir = Path(root) / 'plugins'
            system_existing: set[str] = set()
            if plugins_dir.exists():
                for p in plugins_dir.iterdir():
                    if p.is_dir() and not p.name.startswith('.') and any((p / f).exists() for f in ("plugin.json", "plugin.py","plugin.sh")):
                        system_existing.add(p.name)

            # 检查自定义插件（支持嵌套结构）
            custom_dir = Path(root) / 'custom'
            custom_existing: set[str] = set()
            if custom_dir.exists():
                custom_existing = self._discover_custom_plugins_recursive(custom_dir)

            # 清理系统插件
            if 'system_plugins' in cfg and isinstance(cfg['system_plugins'], dict):
                removed = [name for name in list(cfg['system_plugins'].keys()) if name not in system_existing]
                for name in removed:
                    cfg['system_plugins'].pop(name, None)
                if removed:
                    logger.info(f"移除不存在的系统插件条目: {removed}")

            # 清理自定义插件
            if 'custom_plugins' in cfg and isinstance(cfg['custom_plugins'], dict):
                removed = [name for name in list(cfg['custom_plugins'].keys()) if name not in custom_existing]
                for name in removed:
                    cfg['custom_plugins'].pop(name, None)
                if removed:
                    logger.info(f"移除不存在的自定义插件条目: {removed}")

        except Exception as e:
            logger.debug(f"插件清理失败: {e}")
        return cfg

    def _discover_custom_plugins_recursive(self, custom_dir: Path, parent_path: str = ""):
        """递归发现自定义插件，只返回从plugin.json读取的插件名"""
        plugins = set()

        if not custom_dir.exists():
            return plugins

        for item in custom_dir.iterdir():
            if not item.is_dir() or item.name.startswith('.'):
                continue

            # 检查是否是插件目录（有plugin.json）
            plugin_json = item / "plugin.json"
            if plugin_json.exists():
                # 这是一个插件目录，读取插件名
                try:
                    # 使用缓存加载plugin.json
                    config = load_plugin_json(plugin_json)
                    if config:
                        plugin_name = config.get('name')
                        if plugin_name:
                            plugins.add(plugin_name)
                        else:
                            logger.warning(f"自定义插件 {item} 的 plugin.json 缺少 name 字段")
                except Exception as e:
                    logger.warning(f"读取自定义插件配置失败 {plugin_json}: {e}")
            else:
                # 这是一个普通目录，递归搜索
                nested_path = f"{parent_path}/{item.name}" if parent_path else item.name
                nested_plugins = self._discover_custom_plugins_recursive(item, nested_path)
                plugins.update(nested_plugins)

        return plugins



    def get_config(self) -> Dict[str, Any]:
        """获取完整配置（兼容性方法）"""
        return self.config_data