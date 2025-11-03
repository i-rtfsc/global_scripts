"""
Test for PluginManagerAdapter

Verifies that the adapter correctly wraps PluginService and PluginExecutor
to provide legacy PluginManager interface.
"""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, Mock, MagicMock

from gscripts.infrastructure.adapters import PluginManagerAdapter
from gscripts.application.services import PluginService, PluginExecutor
from gscripts.models import CommandResult
from gscripts.models.plugin import PluginMetadata, PluginType


@pytest.fixture
def mock_plugin_service():
    """Create mock PluginService"""
    service = Mock(spec=PluginService)
    service.load_all_plugins = AsyncMock(return_value={})
    service.reload_plugin = AsyncMock(return_value=True)
    service.enable_plugin = AsyncMock(return_value=True)
    service.disable_plugin = AsyncMock(return_value=True)
    service.list_all_plugins = AsyncMock(return_value=[])
    service.get_plugin_info = AsyncMock(return_value=None)
    service.search_functions = AsyncMock(return_value=[])
    service.get_all_shortcuts = Mock(return_value={})
    service.health_check = AsyncMock(return_value={
        "status": "healthy",
        "total_plugins": 0
    })
    service.get_plugin_metadata = AsyncMock(return_value=None)
    service.register_observer = Mock()
    service.unregister_observer = Mock()
    service.notify_observers_loaded = Mock()
    service.notify_observers_enabled = Mock()
    service.notify_observers_disabled = Mock()
    service.notify_observers_error = Mock()
    service.get_loaded_plugins = Mock(return_value={})
    service.get_failed_plugins = Mock(return_value={})
    service._loader = Mock()
    return service


@pytest.fixture
def mock_plugin_executor():
    """Create mock PluginExecutor"""
    executor = Mock(spec=PluginExecutor)
    executor.execute_plugin_function = AsyncMock(
        return_value=CommandResult(success=True, output="Test output", exit_code=0)
    )
    return executor


@pytest.fixture
def adapter(mock_plugin_service, mock_plugin_executor):
    """Create PluginManagerAdapter instance"""
    return PluginManagerAdapter(
        plugin_service=mock_plugin_service,
        plugin_executor=mock_plugin_executor,
        plugins_root=Path("/tmp/plugins"),
        config_manager=None
    )


class TestPluginManagerAdapter:
    """Test PluginManagerAdapter functionality"""

    @pytest.mark.asyncio
    async def test_initialize_calls_load_all_plugins(self, adapter, mock_plugin_service):
        """Test that initialize loads all plugins"""
        await adapter.initialize()

        mock_plugin_service.load_all_plugins.assert_called_once()
        assert adapter._initialized is True

    @pytest.mark.asyncio
    async def test_initialize_only_once(self, adapter, mock_plugin_service):
        """Test that initialize only runs once"""
        await adapter.initialize()
        await adapter.initialize()

        # Should only be called once
        mock_plugin_service.load_all_plugins.assert_called_once()

    @pytest.mark.asyncio
    async def test_load_all_plugins_delegates_to_service(self, adapter, mock_plugin_service):
        """Test that load_all_plugins delegates to service"""
        result = await adapter.load_all_plugins()

        mock_plugin_service.load_all_plugins.assert_called_once()
        assert result == {}

    @pytest.mark.asyncio
    async def test_reload_plugin_delegates_to_service(self, adapter, mock_plugin_service):
        """Test that reload_plugin delegates to service"""
        result = await adapter.reload_plugin("test_plugin")

        mock_plugin_service.reload_plugin.assert_called_once_with("test_plugin")
        assert result is True

    @pytest.mark.asyncio
    async def test_execute_plugin_function_delegates_to_executor(
        self, adapter, mock_plugin_executor
    ):
        """Test that execute_plugin_function delegates to executor"""
        result = await adapter.execute_plugin_function(
            "test_plugin",
            "test_function",
            ["arg1", "arg2"]
        )

        mock_plugin_executor.execute_plugin_function.assert_called_once_with(
            "test_plugin",
            "test_function",
            ["arg1", "arg2"]
        )
        assert result.success is True
        assert result.output == "Test output"

    def test_list_plugins_returns_dict_format(self, adapter, mock_plugin_service):
        """Test that list_plugins returns legacy dict format"""
        # Mock list_all_plugins to return PluginMetadata objects
        test_plugin = PluginMetadata(
            name="test",
            version="1.0.0",
            author="Test Author",
            description="Test description",
            enabled=True,
            priority=50
        )
        mock_plugin_service.list_all_plugins.return_value = [test_plugin]

        result = adapter.list_plugins()

        assert isinstance(result, dict)
        assert "test" in result
        assert result["test"]["name"] == "test"
        assert result["test"]["version"] == "1.0.0"
        assert result["test"]["enabled"] is True

    @pytest.mark.asyncio
    async def test_health_check_delegates_to_service(self, adapter, mock_plugin_service):
        """Test that health_check delegates to service"""
        result = await adapter.health_check()

        mock_plugin_service.health_check.assert_called_once()
        assert result["status"] == "healthy"

    def test_register_observer_delegates_to_service(self, adapter, mock_plugin_service):
        """Test that register_observer delegates to service"""
        observer = Mock()
        adapter.register_observer(observer)

        mock_plugin_service.register_observer.assert_called_once_with(observer)

    def test_unregister_observer_delegates_to_service(self, adapter, mock_plugin_service):
        """Test that unregister_observer delegates to service"""
        observer = Mock()
        adapter.unregister_observer(observer)

        mock_plugin_service.unregister_observer.assert_called_once_with(observer)

    def test_get_all_shortcuts_delegates_to_service(self, adapter, mock_plugin_service):
        """Test that get_all_shortcuts delegates to service"""
        mock_plugin_service.get_all_shortcuts.return_value = {"shortcut1": "command1"}

        result = adapter.get_all_shortcuts()

        mock_plugin_service.get_all_shortcuts.assert_called_once()
        assert result == {"shortcut1": "command1"}

    def test_plugins_property_returns_loaded_plugins(self, adapter, mock_plugin_service):
        """Test that plugins property returns loaded plugins"""
        mock_plugin_service.get_loaded_plugins.return_value = {"test": {}}

        result = adapter.plugins

        assert result == {"test": {}}

    def test_failed_plugins_property_returns_failed_plugins(self, adapter, mock_plugin_service):
        """Test that failed_plugins property returns failed plugins"""
        mock_plugin_service.get_failed_plugins.return_value = {"bad_plugin": "error message"}

        result = adapter.failed_plugins

        assert result == {"bad_plugin": "error message"}

    def test_plugin_loader_property_returns_loader(self, adapter, mock_plugin_service):
        """Test that plugin_loader property returns loader"""
        result = adapter.plugin_loader

        assert result == mock_plugin_service._loader


class TestAdapterSyncAsyncConversion:
    """Test that adapter correctly handles sync/async conversions"""

    def test_enable_plugin_returns_command_result(self, adapter, mock_plugin_service):
        """Test that enable_plugin returns CommandResult"""
        mock_plugin_service.enable_plugin.return_value = True

        result = adapter.enable_plugin("test_plugin")

        assert isinstance(result, CommandResult)
        assert result.success is True
        assert "enabled" in result.output.lower()

    def test_disable_plugin_returns_command_result(self, adapter, mock_plugin_service):
        """Test that disable_plugin returns CommandResult"""
        mock_plugin_service.disable_plugin.return_value = True

        result = adapter.disable_plugin("test_plugin")

        assert isinstance(result, CommandResult)
        assert result.success is True
        assert "disabled" in result.output.lower()

    def test_enable_plugin_failure_returns_error(self, adapter, mock_plugin_service):
        """Test that enable_plugin failure returns error CommandResult"""
        mock_plugin_service.enable_plugin.return_value = False

        result = adapter.enable_plugin("nonexistent")

        assert isinstance(result, CommandResult)
        assert result.success is False
        assert result.exit_code == 1

    def test_is_plugin_enabled_returns_bool(self, adapter, mock_plugin_service):
        """Test that is_plugin_enabled returns boolean"""
        test_plugin = PluginMetadata(
            name="test",
            version="1.0.0",
            enabled=True
        )
        mock_plugin_service.get_plugin_metadata.return_value = test_plugin

        result = adapter.is_plugin_enabled("test")

        assert isinstance(result, bool)
        assert result is True

    def test_is_plugin_enabled_returns_false_for_nonexistent(self, adapter, mock_plugin_service):
        """Test that is_plugin_enabled returns False for nonexistent plugin"""
        mock_plugin_service.get_plugin_metadata.return_value = None

        result = adapter.is_plugin_enabled("nonexistent")

        assert result is False
