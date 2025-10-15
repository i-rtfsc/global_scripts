"""
执行器接口定义
定义命令执行和进程执行的抽象接口
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any, Protocol
from pathlib import Path


class IProcessExecutor(Protocol):
    """进程执行器接口 (使用 Protocol 实现结构化子类型)"""

    async def execute(
        self,
        command: List[str],
        timeout: int = 30,
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
        capture_output: bool = True
    ) -> Any:  # 返回 CommandResult
        """执行命令（列表形式）"""
        ...

    async def execute_shell(
        self,
        command: str,
        timeout: int = 30,
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None
    ) -> Any:  # 返回 CommandResult
        """执行 Shell 命令（字符串形式）"""
        ...


class ICommandExecutor(ABC):
    """命令执行器接口"""

    @abstractmethod
    async def execute(
        self,
        command: List[str] | str,
        args: Optional[List[str]] = None,
        timeout: Optional[int] = None,
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
        skip_security_check: bool = False
    ) -> Any:  # 返回 CommandResult
        """执行命令（带安全检查）"""
        pass

    @abstractmethod
    async def execute_safe(
        self,
        command: List[str] | str,
        args: Optional[List[str]] = None,
        **kwargs
    ) -> Any:  # 返回 CommandResult
        """安全执行命令（仅白名单）"""
        pass


class IFileSystem(ABC):
    """文件系统接口（用于测试隔离）"""

    @abstractmethod
    def exists(self, path: Path) -> bool:
        """检查路径是否存在"""
        pass

    @abstractmethod
    def read_text(self, path: Path, encoding: str = 'utf-8') -> str:
        """读取文本文件"""
        pass

    @abstractmethod
    def write_text(self, path: Path, content: str, encoding: str = 'utf-8') -> None:
        """写入文本文件"""
        pass

    @abstractmethod
    def read_json(self, path: Path) -> Dict[str, Any]:
        """读取 JSON 文件"""
        pass

    @abstractmethod
    def write_json(self, path: Path, data: Dict[str, Any]) -> None:
        """写入 JSON 文件"""
        pass

    @abstractmethod
    def list_dir(self, path: Path) -> List[Path]:
        """列出目录内容"""
        pass


class IEnvironment(ABC):
    """环境变量接口（用于测试隔离）"""

    @abstractmethod
    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """获取环境变量"""
        pass

    @abstractmethod
    def set(self, key: str, value: str) -> None:
        """设置环境变量"""
        pass

    @abstractmethod
    def all(self) -> Dict[str, str]:
        """获取所有环境变量"""
        pass


__all__ = [
    'IProcessExecutor',
    'ICommandExecutor',
    'IFileSystem',
    'IEnvironment',
]
