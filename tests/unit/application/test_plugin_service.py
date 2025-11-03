"""
Unit Tests for PluginService

Tests for new methods added in Phase 1 (Tasks 3.2-3.9):
- enable_plugin()
- disable_plugin()
- health_check()
- get_enabled_plugins()
- get_disabled_plugins()
- get_plugins_by_type()
- Observer pattern methods
"""

import pytest
from typing import Dict, Any, List
from unittest.mock import Mock, AsyncMock, MagicMock

from src.gscripts.application.services import PluginService
from src.gscripts.application.services.plugin_service import IPluginObserver
from src.gscripts.models.plugin import PluginMetadata, PluginType
from src.gscripts.domain.interfaces import IPluginLoader, IPluginRepository


# Mock Implementations
class MockPluginLoader:
    """Mock plugin loader for testing"""

    def __init__(self):
        self._loaded_plugins: Dict[str, Any] = {}
        self._failed_plugins: Dict[str, str] = {}

    async def load_all_plugins(self, include_examples: bool = False) -> Dict[str, Any]:
        return self._loaded_plugins

    async def load_plugin(self, plugin_name: str):
        return self._loaded_plugins.get(plugin_name)

    def get_loaded_plugins(self) -> Dict[str, Any]:
        return self._loaded_plugins

    def get_failed_plugins(self) -> Dict[str, str]:
        return self._failed_plugins

    def set_loaded_plugins(self, plugins: Dict[str, Any]) -> None:
        """Helper to set loaded plugins"""
        self._loaded_plugins = plugins

    def set_failed_plugins(self, plugins: Dict[str, str]) -> None:
        """Helper to set failed plugins"""
        self._failed_plugins = plugins


class MockPluginRepository:
    """Mock plugin repository for testing"""

    def __init__(self):
        self._plugins: Dict[str, PluginMetadata] = {}

    async def get_all(self) -> List[PluginMetadata]:
        return list(self._plugins.values())

    async def get_by_name(self, name: str):
        return self._plugins.get(name)

    async def save(self, plugin: PluginMetadata) -> None:
        self._plugins[plugin.name] = plugin

    def add_plugin(self, plugin: PluginMetadata) -> None:
        """Helper to add plugin to repository"""
        self._plugins[plugin.name] = plugin


class MockObserver:
    """Mock observer for testing observer pattern"""

    def __init__(self):
        self.loaded_calls = []
        self.enabled_calls = []
        self.disabled_calls = []
        self.error_calls = []

    def on_plugin_loaded(self, plugin_name: str) -> None:
        self.loaded_calls.append(plugin_name)

    def on_plugin_enabled(self, plugin_name: str) -> None:
        self.enabled_calls.append(plugin_name)

    def on_plugin_disabled(self, plugin_name: str) -> None:
        self.disabled_calls.append(plugin_name)

    def on_plugin_error(self, plugin_name: str, error: str) -> None:
        self.error_calls.append((plugin_name, error))


# Fixtures
@pytest.fixture
def mock_loader():
    """Provide mock plugin loader"""
    return MockPluginLoader()


@pytest.fixture
def mock_repository():
    """Provide mock plugin repository"""
    return MockPluginRepository()


@pytest.fixture
def plugin_service(mock_loader, mock_repository):
    """Provide PluginService instance"""
    return PluginService(
        plugin_loader=mock_loader,
        plugin_repository=mock_repository
    )


@pytest.fixture
def sample_plugin():
    """Provide sample plugin metadata"""
    return PluginMetadata(
        name="test_plugin",
        version="1.0.0",
        author="Test Author",
        description={"en": "Test plugin", "zh": "测试插件"},
        type=PluginType.PYTHON,
        enabled=True
    )


@pytest.fixture
def sample_plugins():
    """Provide multiple sample plugins"""
    return [
        PluginMetadata(
            name="plugin_python",
            version="1.0.0",
            author="Author",
            description={"en": "Python plugin"},
            type=PluginType.PYTHON,
            enabled=True
        ),
        PluginMetadata(
            name="plugin_shell",
            version="1.0.0",
            author="Author",
            description={"en": "Shell plugin"},
            type=PluginType.SHELL,
            enabled=True
        ),
        PluginMetadata(
            name="plugin_disabled",
            version="1.0.0",
            author="Author",
            description={"en": "Disabled plugin"},
            type=PluginType.PYTHON,
            enabled=False
        ),
    ]


# Tests for enable_plugin()
class TestEnablePlugin:
    """Tests for enable_plugin method"""

    @pytest.mark.asyncio
    async def test_enable_plugin_success(
        self,
        plugin_service,
        mock_repository,
        sample_plugin
    ):
        """
        WHEN enabling an existing plugin
        THEN plugin is marked as enabled and saved
        AND method returns True
        """
        # Setup: Add disabled plugin
        sample_plugin.enabled = False
        mock_repository.add_plugin(sample_plugin)

        # Execute
        result = await plugin_service.enable_plugin("test_plugin")

        # Assert
        assert result is True
        updated_plugin = await mock_repository.get_by_name("test_plugin")
        assert updated_plugin.enabled is True

    @pytest.mark.asyncio
    async def test_enable_plugin_nonexistent(
        self,
        plugin_service,
        mock_repository
    ):
        """
        WHEN enabling a non-existent plugin
        THEN method returns False
        """
        result = await plugin_service.enable_plugin("nonexistent")

        assert result is False

    @pytest.mark.asyncio
    async def test_enable_plugin_notifies_observers(
        self,
        plugin_service,
        mock_repository,
        sample_plugin
    ):
        """
        WHEN enabling a plugin
        THEN registered observers are notified
        """
        # Setup
        sample_plugin.enabled = False
        mock_repository.add_plugin(sample_plugin)

        observer = MockObserver()
        plugin_service.register_observer(observer)

        # Execute
        await plugin_service.enable_plugin("test_plugin")

        # Assert
        assert observer.enabled_calls == ["test_plugin"]


# Tests for disable_plugin()
class TestDisablePlugin:
    """Tests for disable_plugin method"""

    @pytest.mark.asyncio
    async def test_disable_plugin_success(
        self,
        plugin_service,
        mock_repository,
        sample_plugin
    ):
        """
        WHEN disabling an enabled plugin
        THEN plugin is marked as disabled and saved
        AND method returns True
        """
        # Setup: Add enabled plugin
        sample_plugin.enabled = True
        mock_repository.add_plugin(sample_plugin)

        # Execute
        result = await plugin_service.disable_plugin("test_plugin")

        # Assert
        assert result is True
        updated_plugin = await mock_repository.get_by_name("test_plugin")
        assert updated_plugin.enabled is False

    @pytest.mark.asyncio
    async def test_disable_plugin_nonexistent(
        self,
        plugin_service,
        mock_repository
    ):
        """
        WHEN disabling a non-existent plugin
        THEN method returns False
        """
        result = await plugin_service.disable_plugin("nonexistent")

        assert result is False

    @pytest.mark.asyncio
    async def test_disable_plugin_notifies_observers(
        self,
        plugin_service,
        mock_repository,
        sample_plugin
    ):
        """
        WHEN disabling a plugin
        THEN registered observers are notified
        """
        # Setup
        sample_plugin.enabled = True
        mock_repository.add_plugin(sample_plugin)

        observer = MockObserver()
        plugin_service.register_observer(observer)

        # Execute
        await plugin_service.disable_plugin("test_plugin")

        # Assert
        assert observer.disabled_calls == ["test_plugin"]


# Tests for health_check()
class TestHealthCheck:
    """Tests for health_check method"""

    @pytest.mark.asyncio
    async def test_health_check_healthy_status(
        self,
        plugin_service,
        mock_repository,
        mock_loader,
        sample_plugins
    ):
        """
        WHEN performing health check with no failures
        THEN status is "healthy"
        """
        # Setup
        for plugin in sample_plugins:
            mock_repository.add_plugin(plugin)

        # Execute
        health = await plugin_service.health_check()

        # Assert
        assert health["status"] == "healthy"
        assert health["failed_count"] == 0
        assert health["failed_plugins"] == []

    @pytest.mark.asyncio
    async def test_health_check_degraded_status(
        self,
        plugin_service,
        mock_repository,
        mock_loader,
        sample_plugins
    ):
        """
        WHEN performing health check with failures
        THEN status is "degraded"
        """
        # Setup
        for plugin in sample_plugins:
            mock_repository.add_plugin(plugin)

        mock_loader.set_failed_plugins({"broken_plugin": "Import error"})

        # Execute
        health = await plugin_service.health_check()

        # Assert
        assert health["status"] == "degraded"
        assert health["failed_count"] == 1
        assert "broken_plugin" in health["failed_plugins"]

    @pytest.mark.asyncio
    async def test_health_check_counts(
        self,
        plugin_service,
        mock_repository,
        mock_loader,
        sample_plugins
    ):
        """
        WHEN performing health check
        THEN correct counts are returned
        """
        # Setup: 2 enabled, 1 disabled
        for plugin in sample_plugins:
            mock_repository.add_plugin(plugin)

        mock_loader.set_loaded_plugins({
            "plugin_python": {},
            "plugin_shell": {},
        })

        # Execute
        health = await plugin_service.health_check()

        # Assert
        assert health["total_plugins"] == 3
        assert health["enabled_count"] == 2
        assert health["disabled_count"] == 1
        assert health["loaded_count"] == 2


# Tests for get_enabled_plugins()
class TestGetEnabledPlugins:
    """Tests for get_enabled_plugins method"""

    @pytest.mark.asyncio
    async def test_get_enabled_plugins_filters_correctly(
        self,
        plugin_service,
        mock_repository,
        sample_plugins
    ):
        """
        WHEN getting enabled plugins
        THEN only enabled plugins are returned
        """
        # Setup
        for plugin in sample_plugins:
            mock_repository.add_plugin(plugin)

        # Execute
        enabled = await plugin_service.get_enabled_plugins()

        # Assert
        assert len(enabled) == 2
        assert all(p.enabled for p in enabled)
        plugin_names = [p.name for p in enabled]
        assert "plugin_python" in plugin_names
        assert "plugin_shell" in plugin_names
        assert "plugin_disabled" not in plugin_names

    @pytest.mark.asyncio
    async def test_get_enabled_plugins_empty_when_none(
        self,
        plugin_service,
        mock_repository
    ):
        """
        WHEN no enabled plugins exist
        THEN empty list is returned
        """
        # Setup: Add only disabled plugin
        disabled_plugin = PluginMetadata(
            name="disabled",
            version="1.0.0",
            author="Author",
            description={"en": "Disabled"},
            type=PluginType.PYTHON,
            enabled=False
        )
        mock_repository.add_plugin(disabled_plugin)

        # Execute
        enabled = await plugin_service.get_enabled_plugins()

        # Assert
        assert enabled == []


# Tests for get_disabled_plugins()
class TestGetDisabledPlugins:
    """Tests for get_disabled_plugins method"""

    @pytest.mark.asyncio
    async def test_get_disabled_plugins_filters_correctly(
        self,
        plugin_service,
        mock_repository,
        sample_plugins
    ):
        """
        WHEN getting disabled plugins
        THEN only disabled plugins are returned
        """
        # Setup
        for plugin in sample_plugins:
            mock_repository.add_plugin(plugin)

        # Execute
        disabled = await plugin_service.get_disabled_plugins()

        # Assert
        assert len(disabled) == 1
        assert all(not p.enabled for p in disabled)
        assert disabled[0].name == "plugin_disabled"


# Tests for get_plugins_by_type()
class TestGetPluginsByType:
    """Tests for get_plugins_by_type method"""

    @pytest.mark.asyncio
    async def test_get_plugins_by_type_python(
        self,
        plugin_service,
        mock_repository,
        sample_plugins
    ):
        """
        WHEN filtering by PYTHON type
        THEN only Python plugins are returned
        """
        # Setup
        for plugin in sample_plugins:
            mock_repository.add_plugin(plugin)

        # Execute
        python_plugins = await plugin_service.get_plugins_by_type(PluginType.PYTHON)

        # Assert
        assert len(python_plugins) == 2  # plugin_python and plugin_disabled
        assert all(p.type == PluginType.PYTHON for p in python_plugins)

    @pytest.mark.asyncio
    async def test_get_plugins_by_type_shell(
        self,
        plugin_service,
        mock_repository,
        sample_plugins
    ):
        """
        WHEN filtering by SHELL type
        THEN only Shell plugins are returned
        """
        # Setup
        for plugin in sample_plugins:
            mock_repository.add_plugin(plugin)

        # Execute
        shell_plugins = await plugin_service.get_plugins_by_type(PluginType.SHELL)

        # Assert
        assert len(shell_plugins) == 1
        assert shell_plugins[0].name == "plugin_shell"
        assert shell_plugins[0].type == PluginType.SHELL

    @pytest.mark.asyncio
    async def test_get_plugins_by_type_empty(
        self,
        plugin_service,
        mock_repository,
        sample_plugins
    ):
        """
        WHEN filtering by type with no matches
        THEN empty list is returned
        """
        # Setup
        for plugin in sample_plugins:
            mock_repository.add_plugin(plugin)

        # Execute
        config_plugins = await plugin_service.get_plugins_by_type(PluginType.CONFIG)

        # Assert
        assert config_plugins == []


# Tests for Observer Pattern
class TestObserverPattern:
    """Tests for observer pattern methods"""

    def test_register_observer(self, plugin_service):
        """
        WHEN registering an observer
        THEN observer is added to observers list
        """
        observer = MockObserver()

        plugin_service.register_observer(observer)

        assert observer in plugin_service._observers

    def test_register_observer_prevents_duplicates(self, plugin_service):
        """
        WHEN registering same observer twice
        THEN observer is only added once
        """
        observer = MockObserver()

        plugin_service.register_observer(observer)
        plugin_service.register_observer(observer)

        assert plugin_service._observers.count(observer) == 1

    def test_unregister_observer(self, plugin_service):
        """
        WHEN unregistering an observer
        THEN observer is removed from observers list
        """
        observer = MockObserver()
        plugin_service.register_observer(observer)

        plugin_service.unregister_observer(observer)

        assert observer not in plugin_service._observers

    def test_unregister_nonexistent_observer_safe(self, plugin_service):
        """
        WHEN unregistering non-existent observer
        THEN no error is raised
        """
        observer = MockObserver()

        # Should not raise
        plugin_service.unregister_observer(observer)

    def test_notify_observers_loaded(self, plugin_service):
        """
        WHEN notifying loaded event
        THEN all observers receive notification
        """
        observer1 = MockObserver()
        observer2 = MockObserver()

        plugin_service.register_observer(observer1)
        plugin_service.register_observer(observer2)

        plugin_service.notify_observers_loaded("test_plugin")

        assert observer1.loaded_calls == ["test_plugin"]
        assert observer2.loaded_calls == ["test_plugin"]

    def test_notify_observers_enabled(self, plugin_service):
        """
        WHEN notifying enabled event
        THEN all observers receive notification
        """
        observer = MockObserver()
        plugin_service.register_observer(observer)

        plugin_service.notify_observers_enabled("test_plugin")

        assert observer.enabled_calls == ["test_plugin"]

    def test_notify_observers_disabled(self, plugin_service):
        """
        WHEN notifying disabled event
        THEN all observers receive notification
        """
        observer = MockObserver()
        plugin_service.register_observer(observer)

        plugin_service.notify_observers_disabled("test_plugin")

        assert observer.disabled_calls == ["test_plugin"]

    def test_notify_observers_error(self, plugin_service):
        """
        WHEN notifying error event
        THEN all observers receive notification
        """
        observer = MockObserver()
        plugin_service.register_observer(observer)

        plugin_service.notify_observers_error("test_plugin", "Test error")

        assert observer.error_calls == [("test_plugin", "Test error")]

    def test_notify_observers_handles_observer_exceptions(self, plugin_service):
        """
        WHEN observer raises exception during notification
        THEN other observers still get notified
        """
        class BrokenObserver:
            def __init__(self):
                self.called = False

            def on_plugin_enabled(self, plugin_name: str) -> None:
                raise RuntimeError("Observer error")

            def on_plugin_loaded(self, plugin_name: str) -> None:
                pass

            def on_plugin_disabled(self, plugin_name: str) -> None:
                pass

            def on_plugin_error(self, plugin_name: str, error: str) -> None:
                pass

        broken_observer = BrokenObserver()
        good_observer = MockObserver()

        plugin_service.register_observer(broken_observer)
        plugin_service.register_observer(good_observer)

        # Should not raise exception
        plugin_service.notify_observers_enabled("test_plugin")

        # Good observer should still be notified
        assert good_observer.enabled_calls == ["test_plugin"]

    def test_observers_notified_in_registration_order(self, plugin_service):
        """
        WHEN multiple observers registered
        THEN they are notified in registration order
        """
        call_order = []

        class OrderedObserver:
            def __init__(self, id: int):
                self.id = id

            def on_plugin_enabled(self, plugin_name: str) -> None:
                call_order.append(self.id)

            def on_plugin_loaded(self, plugin_name: str) -> None:
                pass

            def on_plugin_disabled(self, plugin_name: str) -> None:
                pass

            def on_plugin_error(self, plugin_name: str, error: str) -> None:
                pass

        observer1 = OrderedObserver(1)
        observer2 = OrderedObserver(2)
        observer3 = OrderedObserver(3)

        plugin_service.register_observer(observer1)
        plugin_service.register_observer(observer2)
        plugin_service.register_observer(observer3)

        plugin_service.notify_observers_enabled("test")

        assert call_order == [1, 2, 3]


# Integration-style tests
class TestPluginServiceIntegration:
    """Integration tests combining multiple methods"""

    @pytest.mark.asyncio
    async def test_enable_disable_workflow(
        self,
        plugin_service,
        mock_repository,
        sample_plugin
    ):
        """
        WHEN enabling then disabling a plugin
        THEN state changes are persisted correctly
        """
        # Setup: Add disabled plugin
        sample_plugin.enabled = False
        mock_repository.add_plugin(sample_plugin)

        # Enable
        result = await plugin_service.enable_plugin("test_plugin")
        assert result is True

        enabled_plugins = await plugin_service.get_enabled_plugins()
        assert len(enabled_plugins) == 1

        # Disable
        result = await plugin_service.disable_plugin("test_plugin")
        assert result is True

        disabled_plugins = await plugin_service.get_disabled_plugins()
        assert len(disabled_plugins) == 1

    @pytest.mark.asyncio
    async def test_observer_receives_all_lifecycle_events(
        self,
        plugin_service,
        mock_repository,
        sample_plugin
    ):
        """
        WHEN plugin goes through lifecycle
        THEN observer receives all events
        """
        # Setup
        sample_plugin.enabled = False
        mock_repository.add_plugin(sample_plugin)

        observer = MockObserver()
        plugin_service.register_observer(observer)

        # Trigger events
        plugin_service.notify_observers_loaded("test_plugin")
        await plugin_service.enable_plugin("test_plugin")
        await plugin_service.disable_plugin("test_plugin")
        plugin_service.notify_observers_error("test_plugin", "Test error")

        # Assert all events received
        assert observer.loaded_calls == ["test_plugin"]
        assert observer.enabled_calls == ["test_plugin"]
        assert observer.disabled_calls == ["test_plugin"]
        assert observer.error_calls == [("test_plugin", "Test error")]

    @pytest.mark.asyncio
    async def test_health_check_reflects_current_state(
        self,
        plugin_service,
        mock_repository,
        sample_plugins,
        mock_loader
    ):
        """
        WHEN plugins are enabled/disabled
        THEN health check reflects current state
        """
        # Setup
        for plugin in sample_plugins:
            mock_repository.add_plugin(plugin)

        # Initial health check
        health = await plugin_service.health_check()
        assert health["enabled_count"] == 2
        assert health["disabled_count"] == 1

        # Disable one plugin
        await plugin_service.disable_plugin("plugin_python")

        # Health check should reflect change
        health = await plugin_service.health_check()
        assert health["enabled_count"] == 1
        assert health["disabled_count"] == 2
