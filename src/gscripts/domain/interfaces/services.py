"""
执行器接口定义
定义命令执行和进程执行的抽象接口
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any, Protocol, Union
from pathlib import Path


class IProcessExecutor(Protocol):
    """进程执行器接口 (使用 Protocol 实现结构化子类型)

    签名与 :class:`gscripts.utils.process_executor.ProcessExecutor` 保持一致：
    命令以字符串或列表形式给出，可选的 ``config`` 对象承载超时/工作目录/环境
    等设置，额外的覆盖项通过关键字参数传入。``config`` 使用 ``Any`` 以避免领域
    层反向依赖 utils 层的 ``ProcessConfig``。
    """

    async def execute(
        self,
        command: Union[str, List[str]],
        config: Optional[Any] = None,
        **kwargs: Any,
    ) -> Any:  # 返回 CommandResult
        """执行命令（字符串或列表形式）"""
        ...

    async def execute_shell(
        self,
        command: str,
        config: Optional[Any] = None,
        **kwargs: Any,
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
        skip_security_check: bool = False,
    ) -> Any:  # 返回 CommandResult
        """执行命令（带安全检查）"""
        pass

    @abstractmethod
    async def execute_safe(
        self, command: List[str] | str, args: Optional[List[str]] = None, **kwargs
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
    def read_text(self, path: Path, encoding: str = "utf-8") -> str:
        """读取文本文件"""
        pass

    @abstractmethod
    def write_text(self, path: Path, content: str, encoding: str = "utf-8") -> None:
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
    "IProcessExecutor",
    "ICommandExecutor",
    "IFileSystem",
    "IEnvironment",
]
