"""
环境变量抽象实现
提供真实和模拟环境变量，用于测试隔离
"""

import os
from typing import Dict, Optional

from ...domain.interfaces import IEnvironment


class SystemEnvironment(IEnvironment):
    """系统环境变量实现"""

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """获取环境变量"""
        return os.environ.get(key, default)

    def set(self, key: str, value: str) -> None:
        """设置环境变量"""
        os.environ[key] = value

    def all(self) -> Dict[str, str]:
        """获取所有环境变量"""
        return dict(os.environ)


class MockEnvironment(IEnvironment):
    """模拟环境变量实现（用于测试）"""

    def __init__(self, initial_env: Optional[Dict[str, str]] = None):
        self._env: Dict[str, str] = initial_env or {}

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """获取环境变量"""
        return self._env.get(key, default)

    def set(self, key: str, value: str) -> None:
        """设置环境变量"""
        self._env[key] = value

    def all(self) -> Dict[str, str]:
        """获取所有环境变量"""
        return self._env.copy()

    def clear(self):
        """清空环境变量（测试用）"""
        self._env.clear()


__all__ = ['SystemEnvironment', 'MockEnvironment']
