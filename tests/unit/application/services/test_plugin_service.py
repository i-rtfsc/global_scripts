"""
Tests for PluginService

Tests the application service for plugin management.
"""

import pytest
from unittest.mock import Mock, AsyncMock

from gscripts.application.services.plugin_service import PluginService, IPluginObserver
from gscripts.models.plugin import PluginType
from tests.factories import PluginFactory


class TestPluginServiceInitialization:
    """Tests for PluginService initialization"""

    def test_create_service_with_required_dependencies(self):
        """Test creating PluginService with required dependencies"""
        # Arrange
        mock_loader = Mock()
        mock_repository = Mock()

        # Act
        service = PluginService(mock_loader, mock_repository)

        # Assert
        assert service._loader == mock_loader
        assert service._repository == mock_repository
        assert service._config_manager is None
        assert service._observers == []

    def test_create_service_with_config_manager(self):
        """Test creating PluginService with config manager"""
        # Arrange
        mock_loader = Mock()
        mock_repository = Mock()
        mock_config = Mock()

        # Act
        service = PluginService(mock_loader, mock_repository, mock_config)

        # Assert
        assert service._config_manager == mock_config


class TestLoadPlugins:
    """Tests for plugin loading methods"""

    @pytest.mark.asyncio
    async def test_load_all_plugins_delegates_to_loader(self):
        """Test that load_all_plugins delegates to loader"""
        # Arrange
        mock_loader = Mock()
        mock_loader.load_all_plugins = AsyncMock(
            return_value={"plugin1": {}, "plugin2": {}}
        )
        mock_repository = Mock()

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.load_all_plugins()

        # Assert
        assert len(result) == 2
        mock_loader.load_all_plugins.assert_called_once_with(False, True)

    @pytest.mark.asyncio
    async def test_load_all_plugins_with_examples(self):
        """Test loading plugins with examples included"""
        # Arrange
        mock_loader = Mock()
        mock_loader.load_all_plugins = AsyncMock(return_value={})
        mock_repository = Mock()

        service = PluginService(mock_loader, mock_repository)

        # Act
        await service.load_all_plugins(include_examples=True)

        # Assert
        mock_loader.load_all_plugins.assert_called_once_with(True, True)

    @pytest.mark.asyncio
    async def test_load_all_plugins_including_disabled(self):
        """Test loading all plugins including disabled ones"""
        # Arrange
        mock_loader = Mock()
        mock_loader.load_all_plugins = AsyncMock(return_value={})
        mock_repository = Mock()

        service = PluginService(mock_loader, mock_repository)

        # Act
        await service.load_all_plugins(only_enabled=False)

        # Assert
        mock_loader.load_all_plugins.assert_called_once_with(False, False)

    @pytest.mark.asyncio
    async def test_load_plugin_by_name(self):
        """Test loading single plugin by name"""
        # Arrange
        mock_loader = Mock()
        mock_loader.load_plugin = AsyncMock(return_value={"name": "testplugin"})
        mock_repository = Mock()

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.load_plugin("testplugin")

        # Assert
        assert result is not None
        assert result["name"] == "testplugin"
        mock_loader.load_plugin.assert_called_once_with("testplugin")


class TestPluginMetadata:
    """Tests for plugin metadata retrieval"""

    @pytest.mark.asyncio
    async def test_get_plugin_metadata_success(self):
        """Test getting plugin metadata successfully"""
        # Arrange
        mock_loader = Mock()
        mock_repository = Mock()
        plugin = PluginFactory.create(name="testplugin")
        mock_repository.get_by_name = AsyncMock(return_value=plugin)

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.get_plugin_metadata("testplugin")

        # Assert
        assert result is not None
        assert result.name == "testplugin"
        mock_repository.get_by_name.assert_called_once_with("testplugin")

    @pytest.mark.asyncio
    async def test_get_plugin_metadata_not_found(self):
        """Test getting metadata for nonexistent plugin"""
        # Arrange
        mock_loader = Mock()
        mock_repository = Mock()
        mock_repository.get_by_name = AsyncMock(return_value=None)

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.get_plugin_metadata("nonexistent")

        # Assert
        assert result is None

    @pytest.mark.asyncio
    async def test_list_all_plugins(self):
        """Test listing all plugins"""
        # Arrange
        mock_loader = Mock()
        mock_repository = Mock()
        plugins = [
            PluginFactory.create(name="plugin1"),
            PluginFactory.create(name="plugin2"),
        ]
        mock_repository.get_all = AsyncMock(return_value=plugins)

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.list_all_plugins()

        # Assert
        assert len(result) == 2
        assert result[0].name == "plugin1"
        assert result[1].name == "plugin2"


class TestEnableDisablePlugin:
    """Tests for enable/disable plugin functionality"""

    @pytest.mark.asyncio
    async def test_enable_plugin_success(self):
        """Test enabling a plugin successfully"""
        # Arrange
        mock_loader = Mock()
        mock_loader.update_plugin_enabled_status = Mock()
        mock_repository = Mock()
        plugin = PluginFactory.create(name="testplugin", enabled=False)
        mock_repository.get_by_name = AsyncMock(return_value=plugin)
        mock_repository.save = AsyncMock()

        service = PluginService(mock_loader, mock_repository)

        # Mock _regenerate_router_index
        service._regenerate_router_index = AsyncMock()

        # Act
        result = await service.enable_plugin("testplugin")

        # Assert
        assert result is True
        assert plugin.enabled is True
        mock_repository.save.assert_called_once()
        mock_loader.update_plugin_enabled_status.assert_called_once_with(
            "testplugin", True
        )

    @pytest.mark.asyncio
    async def test_enable_plugin_not_found(self):
        """Test enabling nonexistent plugin"""
        # Arrange
        mock_loader = Mock()
        mock_repository = Mock()
        mock_repository.get_by_name = AsyncMock(return_value=None)

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.enable_plugin("nonexistent")

        # Assert
        assert result is False

    @pytest.mark.asyncio
    async def test_disable_plugin_success(self):
        """Test disabling a plugin successfully"""
        # Arrange
        mock_loader = Mock()
        mock_loader.update_plugin_enabled_status = Mock()
        mock_repository = Mock()
        plugin = PluginFactory.create(name="testplugin", enabled=True)
        mock_repository.get_by_name = AsyncMock(return_value=plugin)
        mock_repository.save = AsyncMock()

        service = PluginService(mock_loader, mock_repository)

        # Mock _regenerate_router_index
        service._regenerate_router_index = AsyncMock()

        # Act
        result = await service.disable_plugin("testplugin")

        # Assert
        assert result is True
        assert plugin.enabled is False
        mock_repository.save.assert_called_once()
        mock_loader.update_plugin_enabled_status.assert_called_once_with(
            "testplugin", False
        )

    @pytest.mark.asyncio
    async def test_disable_plugin_not_found(self):
        """Test disabling nonexistent plugin"""
        # Arrange
        mock_loader = Mock()
        mock_repository = Mock()
        mock_repository.get_by_name = AsyncMock(return_value=None)

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.disable_plugin("nonexistent")

        # Assert
        assert result is False

    @pytest.mark.asyncio
    async def test_enable_plugin_persists_to_config(self):
        """Test that enabling plugin saves to config file"""
        # Arrange
        mock_loader = Mock()
        mock_loader.update_plugin_enabled_status = Mock()
        mock_repository = Mock()
        plugin = PluginFactory.create(name="testplugin", enabled=False)
        mock_repository.get_by_name = AsyncMock(return_value=plugin)
        mock_repository.save = AsyncMock()

        mock_config = Mock()
        mock_config.get_config = Mock(
            return_value={"system_plugins": {"testplugin": False}}
        )
        mock_config.save_config = Mock()

        service = PluginService(mock_loader, mock_repository, mock_config)
        service._regenerate_router_index = AsyncMock()

        # Act
        await service.enable_plugin("testplugin")

        # Assert
        mock_config.save_config.assert_called_once()


class TestPluginInfo:
    """Tests for get_plugin_info method"""

    @pytest.mark.asyncio
    async def test_get_plugin_info_success(self):
        """Test getting detailed plugin info"""
        # Arrange
        mock_loader = Mock()
        mock_loader.get_loaded_plugins = Mock(
            return_value={"testplugin": {"functions": {"func1": {}, "func2": {}}}}
        )
        mock_repository = Mock()
        plugin = PluginFactory.create(name="testplugin", version="1.0.0")
        mock_repository.get_by_name = AsyncMock(return_value=plugin)

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.get_plugin_info("testplugin")

        # Assert
        assert result is not None
        assert result["name"] == "testplugin"
        assert result["version"] == "1.0.0"
        assert result["loaded"] is True
        assert len(result["functions"]) == 2

    @pytest.mark.asyncio
    async def test_get_plugin_info_not_loaded(self):
        """Test getting info for plugin that's not loaded"""
        # Arrange
        mock_loader = Mock()
        mock_loader.get_loaded_plugins = Mock(return_value={})
        mock_repository = Mock()
        plugin = PluginFactory.create(name="unloaded")
        mock_repository.get_by_name = AsyncMock(return_value=plugin)

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.get_plugin_info("unloaded")

        # Assert
        assert result is not None
        assert result["loaded"] is False
        assert result["functions"] == []

    @pytest.mark.asyncio
    async def test_get_plugin_info_not_found(self):
        """Test getting info for nonexistent plugin"""
        # Arrange
        mock_loader = Mock()
        mock_repository = Mock()
        mock_repository.get_by_name = AsyncMock(return_value=None)

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.get_plugin_info("nonexistent")

        # Assert
        assert result is None


class TestPluginFiltering:
    """Tests for plugin filtering methods"""

    @pytest.mark.asyncio
    async def test_get_enabled_plugins(self):
        """Test getting only enabled plugins"""
        # Arrange
        mock_loader = Mock()
        mock_repository = Mock()
        plugins = [
            PluginFactory.create(name="enabled1", enabled=True),
            PluginFactory.create(name="disabled1", enabled=False),
            PluginFactory.create(name="enabled2", enabled=True),
        ]
        mock_repository.get_all = AsyncMock(return_value=plugins)

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.get_enabled_plugins()

        # Assert
        assert len(result) == 2
        assert all(p.enabled for p in result)

    @pytest.mark.asyncio
    async def test_get_disabled_plugins(self):
        """Test getting only disabled plugins"""
        # Arrange
        mock_loader = Mock()
        mock_repository = Mock()
        plugins = [
            PluginFactory.create(name="enabled1", enabled=True),
            PluginFactory.create(name="disabled1", enabled=False),
            PluginFactory.create(name="disabled2", enabled=False),
        ]
        mock_repository.get_all = AsyncMock(return_value=plugins)

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.get_disabled_plugins()

        # Assert
        assert len(result) == 2
        assert all(not p.enabled for p in result)

    @pytest.mark.asyncio
    async def test_get_plugins_by_type(self):
        """Test filtering plugins by type"""
        # Arrange
        mock_loader = Mock()
        mock_repository = Mock()
        plugins = [
            PluginFactory.create_python(name="python1"),
            PluginFactory.create_shell(name="shell1"),
            PluginFactory.create_python(name="python2"),
        ]
        mock_repository.get_all = AsyncMock(return_value=plugins)

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.get_plugins_by_type(PluginType.PYTHON)

        # Assert
        assert len(result) == 2
        assert all(p.type == PluginType.PYTHON for p in result)


class TestHealthCheck:
    """Tests for health_check method"""

    @pytest.mark.asyncio
    async def test_health_check_healthy_system(self):
        """Test health check with healthy system"""
        # Arrange
        mock_loader = Mock()
        mock_loader.get_loaded_plugins = Mock(
            return_value={"plugin1": {}, "plugin2": {}}
        )
        mock_loader.get_failed_plugins = Mock(return_value={})

        mock_repository = Mock()
        plugins = [
            PluginFactory.create(name="plugin1", enabled=True),
            PluginFactory.create(name="plugin2", enabled=True),
        ]
        mock_repository.get_all = AsyncMock(return_value=plugins)

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.health_check()

        # Assert
        assert result["status"] == "healthy"
        assert result["total_plugins"] == 2
        assert result["enabled_count"] == 2
        assert result["loaded_count"] == 2
        assert result["failed_count"] == 0

    @pytest.mark.asyncio
    async def test_health_check_degraded_system(self):
        """Test health check with failed plugins"""
        # Arrange
        mock_loader = Mock()
        mock_loader.get_loaded_plugins = Mock(return_value={"plugin1": {}})
        mock_loader.get_failed_plugins = Mock(return_value={"plugin2": "Error message"})

        mock_repository = Mock()
        plugins = [
            PluginFactory.create(name="plugin1", enabled=True),
            PluginFactory.create(name="plugin2", enabled=True),
        ]
        mock_repository.get_all = AsyncMock(return_value=plugins)

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.health_check()

        # Assert
        assert result["status"] == "degraded"
        assert result["failed_count"] == 1
        assert "plugin2" in result["failed_plugins"]


class TestSearchFunctions:
    """Tests for search_functions method"""

    @pytest.mark.asyncio
    async def test_search_functions_by_name(self):
        """Test searching for functions by name"""
        # Arrange
        mock_loader = Mock()
        mock_loader.get_loaded_plugins = Mock(
            return_value={
                "plugin1": {
                    "functions": {
                        "test_func": {
                            "description": "A test function",
                            "usage": "gs plugin1 test_func",
                        },
                        "other_func": {
                            "description": "Another function",
                            "usage": "gs plugin1 other_func",
                        },
                    }
                }
            }
        )
        mock_repository = Mock()

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.search_functions("test")

        # Assert
        assert len(result) >= 1
        assert any(r["function"] == "test_func" for r in result)

    @pytest.mark.asyncio
    async def test_search_functions_by_description(self):
        """Test searching for functions by description"""
        # Arrange
        mock_loader = Mock()
        mock_loader.get_loaded_plugins = Mock(
            return_value={
                "plugin1": {
                    "functions": {
                        "func1": {
                            "description": "Handles Android development",
                            "usage": "gs plugin1 func1",
                        }
                    }
                }
            }
        )
        mock_repository = Mock()

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.search_functions("android")

        # Assert
        assert len(result) == 1
        assert result[0]["function"] == "func1"


class TestObserverPattern:
    """Tests for observer pattern implementation"""

    def test_register_observer(self):
        """Test registering an observer"""
        # Arrange
        mock_loader = Mock()
        mock_repository = Mock()
        mock_observer = Mock(spec=IPluginObserver)

        service = PluginService(mock_loader, mock_repository)

        # Act
        service.register_observer(mock_observer)

        # Assert
        assert mock_observer in service._observers

    def test_unregister_observer(self):
        """Test unregistering an observer"""
        # Arrange
        mock_loader = Mock()
        mock_repository = Mock()
        mock_observer = Mock(spec=IPluginObserver)

        service = PluginService(mock_loader, mock_repository)
        service.register_observer(mock_observer)

        # Act
        service.unregister_observer(mock_observer)

        # Assert
        assert mock_observer not in service._observers

    def test_notify_observers_enabled(self):
        """Test notifying observers when plugin is enabled"""
        # Arrange
        mock_loader = Mock()
        mock_repository = Mock()
        mock_observer = Mock(spec=IPluginObserver)

        service = PluginService(mock_loader, mock_repository)
        service.register_observer(mock_observer)

        # Act
        service.notify_observers_enabled("testplugin")

        # Assert
        mock_observer.on_plugin_enabled.assert_called_once_with("testplugin")

    def test_observer_errors_dont_break_service(self):
        """Test that observer errors don't break the service"""
        # Arrange
        mock_loader = Mock()
        mock_repository = Mock()
        mock_observer = Mock(spec=IPluginObserver)
        mock_observer.on_plugin_enabled.side_effect = Exception("Observer error")

        service = PluginService(mock_loader, mock_repository)
        service.register_observer(mock_observer)

        # Act - Should not raise exception
        service.notify_observers_enabled("testplugin")

        # Assert - Method was called despite error
        mock_observer.on_plugin_enabled.assert_called_once()


class TestReloadPlugin:
    """Tests for reload_plugin method"""

    @pytest.mark.asyncio
    async def test_reload_plugin_success(self):
        """Test reloading a plugin successfully"""
        # Arrange
        mock_loader = Mock()
        mock_loader.load_plugin = AsyncMock(return_value={"name": "testplugin"})
        mock_repository = Mock()

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.reload_plugin("testplugin")

        # Assert
        assert result is True
        mock_loader.load_plugin.assert_called_once_with("testplugin")

    @pytest.mark.asyncio
    async def test_reload_plugin_failure(self):
        """Test reloading a plugin that fails"""
        # Arrange
        mock_loader = Mock()
        mock_loader.load_plugin = AsyncMock(return_value=None)
        mock_repository = Mock()

        service = PluginService(mock_loader, mock_repository)

        # Act
        result = await service.reload_plugin("badplugin")

        # Assert
        assert result is False
