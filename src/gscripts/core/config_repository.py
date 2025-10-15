"""
配置仓库模块
统一配置访问，消除重复的配置读取代码
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional
from abc import ABC, abstractmethod

from .logger import get_logger

logger = get_logger(tag="CORE.CONFIG_REPO", name=__name__)


class ConfigRepository(ABC):
    """配置仓库抽象基类"""

    @abstractmethod
    def load(self) -> Dict[str, Any]:
        """加载配置"""
        pass

    @abstractmethod
    def save(self, config: Dict[str, Any]) -> bool:
        """保存配置"""
        pass

    @abstractmethod
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项"""
        pass

    @abstractmethod
    def set(self, key: str, value: Any) -> bool:
        """设置配置项"""
        pass


class JsonConfigRepository(ConfigRepository):
    """JSON 配置仓库"""

    def __init__(self, config_file: Path, user_config_file: Optional[Path] = None):
        """
        初始化配置仓库

        Args:
            config_file: 项目配置文件路径
            user_config_file: 用户配置文件路径（可选）
        """
        self.config_file = config_file
        self.user_config_file = user_config_file
        self._cache: Optional[Dict[str, Any]] = None

    def load(self) -> Dict[str, Any]:
        """
        加载配置（合并项目配置和用户配置）

        Returns:
            Dict[str, Any]: 合并后的配置
        """
        if self._cache is not None:
            return self._cache

        config = {}

        # 加载项目配置
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load config from {self.config_file}: {e}")

        # 加载并合并用户配置
        if self.user_config_file and self.user_config_file.exists():
            try:
                with open(self.user_config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    config.update(user_config)
            except Exception as e:
                logger.warning(f"Failed to load user config from {self.user_config_file}: {e}")

        self._cache = config
        return config

    def save(self, config: Dict[str, Any]) -> bool:
        """
        保存配置到用户配置文件

        Args:
            config: 配置字典

        Returns:
            bool: 是否保存成功
        """
        target_file = self.user_config_file or self.config_file

        try:
            target_file.parent.mkdir(parents=True, exist_ok=True)

            with open(target_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)

            self._cache = config
            return True
        except Exception as e:
            logger.error(f"Failed to save config to {target_file}: {e}")
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """
        获取配置项

        Args:
            key: 配置键
            default: 默认值

        Returns:
            Any: 配置值
        """
        config = self.load()
        return config.get(key, default)

    def set(self, key: str, value: Any) -> bool:
        """
        设置配置项

        Args:
            key: 配置键
            value: 配置值

        Returns:
            bool: 是否设置成功
        """
        config = self.load()
        config[key] = value
        return self.save(config)

    def reload(self):
        """重新加载配置"""
        self._cache = None
        return self.load()


class ConfigService:
    """
    配置服务（Facade）

    提供统一的配置访问接口
    """

    def __init__(self, repository: ConfigRepository):
        """
        初始化配置服务

        Args:
            repository: 配置仓库实例
        """
        self.repository = repository

    def get(self, key: str, default: Any = None) -> Any:
        """获取配置"""
        return self.repository.get(key, default)

    def set(self, key: str, value: Any) -> bool:
        """设置配置"""
        return self.repository.set(key, value)

    def get_all(self) -> Dict[str, Any]:
        """获取所有配置"""
        return self.repository.load()

    def reload(self):
        """重新加载配置"""
        return self.repository.reload()


# 全局配置服务单例
_config_service: Optional[ConfigService] = None


def get_config_service(
    config_file: Optional[Path] = None,
    user_config_file: Optional[Path] = None
) -> ConfigService:
    """
    获取全局配置服务单例

    Args:
        config_file: 项目配置文件
        user_config_file: 用户配置文件

    Returns:
        ConfigService: 配置服务实例
    """
    global _config_service

    if _config_service is None:
        # 默认路径
        if config_file is None:
            from pathlib import Path
            project_root = Path.cwd()
            config_file = project_root / "config" / "gs.json"

        if user_config_file is None:
            user_home = Path.home()
            user_config_file = user_home / ".config" / "global-scripts" / "config" / "gs.json"

        repository = JsonConfigRepository(config_file, user_config_file)
        _config_service = ConfigService(repository)

    return _config_service
