"""
国际化(i18n)工具类
用于处理多语言字符串
"""

import json
import os
from pathlib import Path
from typing import Dict, Any, Optional



from ..core.logger import get_logger

# Module-level logger
logger = get_logger(tag="UTILS.I18N", name=__name__)

class I18nManager:
    """国际化管理器"""
    
    def __init__(self, config_path: Optional[Path] = None, chinese: bool = None):
        if config_path is None:
            # 默认配置文件路径
            # 新结构: 使用包内资源文件
            config_path = Path(__file__).parent.parent / "resources" / "i18n" / "i18n.json"
        
        self.config_path = config_path
        # 存储整个配置文件的数据，便于访问顶层keys与messages下的keys
        self._data: Dict[str, Any] = {}
        self.current_language = "en"
        self._load_config()
        
        # 如果指定了chinese参数，设置相应的语言
        if chinese is not None:
            if chinese:
                self.set_language("zh")
            else:
                self.set_language("en")
    
    def _load_config(self):
        """加载国际化配置"""
        try:
            if self.config_path.exists():
                with open(self.config_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self._data = data
                    # 语言优先从环境获取，其次从配置的locale.default，默认en
                    self.current_language = os.environ.get('GS_LANGUAGE', data.get('locale', {}).get('default', 'en'))
        except Exception as e:
            logger.warning(f"Failed to load i18n config: {e}")
            # 使用默认英文配置
            self._data = {}
            self.current_language = "en"
    
    def set_language(self, language: str):
        """设置当前语言"""
        self.current_language = language
        os.environ['GS_LANGUAGE'] = language
    
    def get_message(self, key: str, **kwargs) -> str:
        """获取本地化消息，支持顶层与messages.*命名空间，自动回退"""
        def resolve(path: str) -> Optional[Any]:
            cur: Any = self._data
            for part in path.split('.'):
                if isinstance(cur, dict) and part in cur:
                    cur = cur[part]
                else:
                    return None
            return cur
        
        # 优先尝试顶层路径，其次尝试messages.*命名空间
        node = resolve(key)
        if node is None:
            node = resolve(f"messages.{key}")
        
        # 仍未找到则返回key本身
        if node is None:
            return key
        
        # 如果节点是字典，按语言选择
        if isinstance(node, dict):
            message = node.get(self.current_language) or node.get('en') or node.get('zh')
            if not isinstance(message, str):
                # 无法解析为字符串则返回key
                return key
        else:
            message = str(node)
        
        try:
            return message.format(**kwargs) if kwargs else message
        except Exception:
            # 参数格式化失败时返回未格式化的消息
            return message
    
    def get_plugin_type_text(self, plugin_type: str) -> str:
        """获取插件类型的本地化文本（实现类型）"""
        return self.get_message(f'plugin_implementation_types.{plugin_type}')
    
    def format_error(self, error_key: str, **kwargs) -> str:
        """格式化错误消息"""
        return self.get_message(f'errors.{error_key}', **kwargs)
    
    def format_success(self, success_key: str, **kwargs) -> str:
        """格式化成功消息"""
        return self.get_message(f'success.{success_key}', **kwargs)


# 全局i18n实例
_i18n_manager = None

def get_i18n_manager() -> I18nManager:
    """获取全局i18n管理器实例"""
    global _i18n_manager
    if _i18n_manager is None:
        _i18n_manager = I18nManager()
    return _i18n_manager

def t(key: str, **kwargs) -> str:
    """快捷的翻译函数"""
    return get_i18n_manager().get_message(key, **kwargs)

def set_language(language: str):
    """设置全局语言"""
    get_i18n_manager().set_language(language)