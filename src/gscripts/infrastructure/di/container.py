"""
依赖注入容器
轻量级的DI容器实现，用于管理依赖关系
"""

from typing import Any, Callable, Dict, Optional, Type, TypeVar
from dataclasses import dataclass

T = TypeVar("T")


@dataclass
class ServiceDescriptor:
    """服务描述符"""

    service_type: Type
    factory: Callable
    singleton: bool = True
    instance: Optional[Any] = None


class DIContainer:
    """轻量级依赖注入容器"""

    def __init__(self):
        self._services: Dict[Type, ServiceDescriptor] = {}

    def register(
        self, service_type: Type[T], factory: Callable[[], T], singleton: bool = True
    ) -> None:
        """注册服务

        Args:
            service_type: 服务类型（通常是接口）
            factory: 创建服务实例的工厂函数
            singleton: 是否为单例模式
        """
        self._services[service_type] = ServiceDescriptor(
            service_type=service_type, factory=factory, singleton=singleton
        )

    def register_instance(self, service_type: Type[T], instance: T) -> None:
        """注册已有实例

        Args:
            service_type: 服务类型
            instance: 服务实例
        """
        self._services[service_type] = ServiceDescriptor(
            service_type=service_type,
            factory=lambda: instance,
            singleton=True,
            instance=instance,
        )

    def resolve(self, service_type: Type[T]) -> T:
        """解析服务

        Args:
            service_type: 服务类型

        Returns:
            服务实例

        Raises:
            KeyError: 服务未注册
        """
        if service_type not in self._services:
            raise KeyError(f"Service {service_type.__name__} not registered")

        descriptor = self._services[service_type]

        # 单例模式：返回已有实例或创建新实例
        if descriptor.singleton:
            if descriptor.instance is None:
                descriptor.instance = descriptor.factory()
            return descriptor.instance

        # 每次创建新实例
        return descriptor.factory()

    def clear(self) -> None:
        """清空所有注册的服务（用于测试）"""
        self._services.clear()


# 全局容器实例
_global_container: Optional[DIContainer] = None


def get_container() -> DIContainer:
    """获取全局DI容器"""
    global _global_container
    if _global_container is None:
        _global_container = DIContainer()
    return _global_container


def reset_container() -> None:
    """重置全局容器（用于测试）"""
    global _global_container
    _global_container = None


__all__ = [
    "DIContainer",
    "ServiceDescriptor",
    "get_container",
    "reset_container",
]
