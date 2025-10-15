"""
DI容器的单元测试
"""

import pytest

from src.gscripts.infrastructure.di import DIContainer, reset_container


class TestDIContainer:
    """DIContainer 单元测试"""

    def test_register_and_resolve_singleton(self):
        """测试注册和解析单例服务"""
        container = DIContainer()

        class TestService:
            pass

        container.register(TestService, lambda: TestService(), singleton=True)

        instance1 = container.resolve(TestService)
        instance2 = container.resolve(TestService)

        assert instance1 is instance2

    def test_register_and_resolve_transient(self):
        """测试注册和解析瞬态服务"""
        container = DIContainer()

        class TestService:
            pass

        container.register(TestService, lambda: TestService(), singleton=False)

        instance1 = container.resolve(TestService)
        instance2 = container.resolve(TestService)

        assert instance1 is not instance2

    def test_register_instance(self):
        """测试注册已有实例"""
        container = DIContainer()

        class TestService:
            def __init__(self, value: str):
                self.value = value

        instance = TestService("test")
        container.register_instance(TestService, instance)

        resolved = container.resolve(TestService)

        assert resolved is instance
        assert resolved.value == "test"

    def test_resolve_unregistered_service_raises_error(self):
        """测试解析未注册的服务抛出异常"""
        container = DIContainer()

        class UnregisteredService:
            pass

        with pytest.raises(KeyError):
            container.resolve(UnregisteredService)

    def test_clear_removes_all_services(self):
        """测试清空所有服务"""
        container = DIContainer()

        class TestService:
            pass

        container.register(TestService, lambda: TestService())
        container.clear()

        with pytest.raises(KeyError):
            container.resolve(TestService)

    def test_reset_container_creates_new_instance(self):
        """测试重置容器创建新实例"""
        from src.gscripts.infrastructure.di import get_container

        container1 = get_container()
        reset_container()
        container2 = get_container()

        assert container1 is not container2
