"""
命令执行结果相关数据结构
"""

from dataclasses import dataclass, field
from typing import Dict, Any, Optional


@dataclass
class ExecutionMetadata:
    """命令执行元数据"""
    command: Optional[str] = None
    pid: Optional[int] = None
    cwd: Optional[str] = None
    timeout: bool = False
    exception: Optional[str] = None


@dataclass
class CommandResult:
    """命令执行结果

    统一的命令执行结果数据结构,用于所有命令执行返回值

    Attributes:
        success: 命令是否执行成功
        stdout: 标准输出内容
        stderr: 标准错误输出内容
        message: 执行消息(用于用户提示)
        output: 输出内容(优先使用此字段)
        error: 错误信息(优先使用此字段)
        exit_code: 退出码(0表示成功)
        execution_time: 执行耗时(秒)
        metadata: 额外的元数据信息
    """
    success: bool
    stdout: str = ""
    stderr: str = ""
    message: str = ""
    output: str = ""
    error: str = ""
    exit_code: int = 0
    execution_time: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """初始化后处理:确保output和error字段有值"""
        if not self.output and self.stdout:
            self.output = self.stdout
        if not self.error and self.stderr:
            self.error = self.stderr

    @property
    def failed(self) -> bool:
        """命令是否失败"""
        return not self.success

    def with_metadata(self, **kwargs) -> 'CommandResult':
        """添加元数据并返回自身(链式调用)"""
        self.metadata.update(kwargs)
        return self
