"""
Lightweight Dependency Injection Container
轻量级依赖注入容器 - 零外部依赖

提供简单但强大的依赖注入功能：
1. 单例注册和解析
2. 工厂函数注册
3. 自动依赖解析
4. 类型提示支持

设计原则：
- 简单易用，不需要外部依赖
- 支持类型提示和IDE自动完成
- 线程安全
"""

import threading
from typing import Any, Callable, Dict, Type, TypeVar, Optional, get_type_hints
from functools import wraps

T = TypeVar('T')


class Container:
    """
    依赖注入容器

    用法示例:
    ```python
    container = Container()

    # 注册单例
    container.register_singleton(ConfigManager, config_manager_instance)

    # 注册工厂
    container.register_factory(PluginLoader, lambda: PluginLoader(plugins_root))

    # 自动解析
    loader = container.resolve(PluginLoader)
    ```
    """

    def __init__(self):
        self._singletons: Dict[Type, Any] = {}
        self._factories: Dict[Type, Callable] = {}
        self._lock = threading.Lock()

    def register_singleton(self, interface: Type[T], instance: T) -> None:
        """
        注册单例实例

        Args:
            interface: 接口类型
            instance: 实例对象
        """
        with self._lock:
            self._singletons[interface] = instance

    def register_factory(
        self,
        interface: Type[T],
        factory: Callable[..., T],
        singleton: bool = False
    ) -> None:
        """
        注册工厂函数

        Args:
            interface: 接口类型
            factory: 工厂函数
            singleton: 是否缓存结果（单例模式）
        """
        with self._lock:
            if singleton:
                # 包装为延迟单例
                _instance = None
                _created = False

                def lazy_singleton(*args, **kwargs):
                    nonlocal _instance, _created
                    if not _created:
                        _instance = factory(*args, **kwargs)
                        _created = True
                    return _instance

                self._factories[interface] = lazy_singleton
            else:
                self._factories[interface] = factory

    def register_type(
        self,
        interface: Type[T],
        implementation: Type[T],
        singleton: bool = False
    ) -> None:
        """
        注册类型（自动创建工厂）

        Args:
            interface: 接口类型
            implementation: 实现类型
            singleton: 是否单例
        """
        def factory():
            # 尝试自动注入依赖
            return self._auto_inject(implementation)

        self.register_factory(interface, factory, singleton=singleton)

    def resolve(self, interface: Type[T]) -> T:
        """
        解析依赖

        Args:
            interface: 接口类型

        Returns:
            T: 实例对象

        Raises:
            KeyError: 接口未注册
        """
        # 检查单例缓存
        if interface in self._singletons:
            return self._singletons[interface]

        # 检查工厂
        if interface in self._factories:
            return self._factories[interface]()

        # 未找到
        raise KeyError(f"Interface {interface.__name__} not registered in container")

    def resolve_optional(self, interface: Type[T]) -> Optional[T]:
        """
        解析可选依赖

        Args:
            interface: 接口类型

        Returns:
            Optional[T]: 实例对象，未注册返回None
        """
        try:
            return self.resolve(interface)
        except KeyError:
            return None

    def _auto_inject(self, cls: Type[T]) -> T:
        """
        自动注入依赖（通过__init__参数）

        Args:
            cls: 类型

        Returns:
            T: 实例
        """
        try:
            # 获取__init__的类型提示
            hints = get_type_hints(cls.__init__)

            # 构建参数
            kwargs = {}
            for param_name, param_type in hints.items():
                if param_name == 'return':
                    continue

                # 尝试解析依赖
                instance = self.resolve_optional(param_type)
                if instance is not None:
                    kwargs[param_name] = instance

            # 创建实例
            return cls(**kwargs)

        except Exception:
            # 回退到无参构造
            return cls()

    def has(self, interface: Type) -> bool:
        """检查接口是否已注册"""
        return interface in self._singletons or interface in self._factories

    def clear(self) -> None:
        """清空容器"""
        with self._lock:
            self._singletons.clear()
            self._factories.clear()

    def clone(self) -> 'Container':
        """克隆容器（浅拷贝）"""
        new_container = Container()
        new_container._singletons = self._singletons.copy()
        new_container._factories = self._factories.copy()
        return new_container


# 全局容器实例
_global_container: Optional[Container] = None
_container_lock = threading.Lock()


def get_container() -> Container:
    """获取全局容器单例"""
    global _global_container

    if _global_container is None:
        with _container_lock:
            if _global_container is None:
                _global_container = Container()

    return _global_container


def reset_container() -> None:
    """重置全局容器（主要用于测试）"""
    global _global_container
    with _container_lock:
        _global_container = None


# ============= 装饰器 =============

def injectable(singleton: bool = False):
    """
    可注入装饰器

    将类标记为可注入，并自动注册到全局容器

    用法:
    ```python
    @injectable(singleton=True)
    class MyService:
        def __init__(self, dependency: IDependency):
            self.dependency = dependency
    ```
    """
    def decorator(cls: Type[T]) -> Type[T]:
        container = get_container()

        if singleton:
            # 延迟创建单例
            _instance = None

            def get_instance():
                nonlocal _instance
                if _instance is None:
                    _instance = container._auto_inject(cls)
                return _instance

            container.register_factory(cls, get_instance, singleton=True)
        else:
            container.register_type(cls, cls, singleton=False)

        return cls

    return decorator


def inject(interface: Type[T]) -> T:
    """
    注入依赖（用于函数参数默认值）

    用法:
    ```python
    def my_function(service: IService = inject(IService)):
        service.do_something()
    ```
    """
    container = get_container()
    return container.resolve(interface)


# ============= 上下文管理器 =============

class ContainerScope:
    """
    容器作用域

    用于临时覆盖依赖，完成后自动恢复

    用法:
    ```python
    with ContainerScope() as scope:
        scope.register_singleton(IService, mock_service)
        # 在此作用域内使用mock
        ...
    # 作用域外自动恢复
    ```
    """

    def __init__(self, container: Optional[Container] = None):
        self.container = container or get_container()
        self.backup: Optional[Container] = None

    def __enter__(self) -> Container:
        # 备份当前容器
        self.backup = self.container.clone()
        return self.container

    def __exit__(self, exc_type, exc_val, exc_tb):
        # 恢复容器
        if self.backup:
            self.container._singletons = self.backup._singletons
            self.container._factories = self.backup._factories


__all__ = [
    'Container',
    'get_container',
    'reset_container',
    'injectable',
    'inject',
    'ContainerScope',
]
