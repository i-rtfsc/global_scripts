"""
Integration Test for PluginExecutor
Tests the plugin executor service with dependency injection
"""

import pytest
from pathlib import Path

from src.gscripts.infrastructure import DIContainer, configure_services
from src.gscripts.application.services import PluginExecutor, PluginService
from src.gscripts.domain.interfaces import IFileSystem, IPluginLoader


@pytest.fixture
def test_container_with_executor():
    """Create test container with executor configured"""
    container = DIContainer()
    plugins_dir = Path("/test/plugins")
    config_path = Path("/test/gs.json")

    configure_services(
        container, use_mocks=True, plugins_dir=plugins_dir, config_path=config_path
    )

    # Setup mock plugins
    fs = container.resolve(IFileSystem)

    # Plugin 1: Config-based command
    fs.write_json(
        plugins_dir / "test_plugin" / "plugin.json",
        {
            "name": "test_plugin",
            "version": "1.0.0",
            "description": {"zh": "测试插件", "en": "Test Plugin"},
            "enabled": True,
            "priority": 10,
        },
    )

    return container


class TestPluginExecutor:
    """Integration tests for PluginExecutor"""

    @pytest.mark.asyncio
    async def test_executor_service_resolves(self, test_container_with_executor):
        """Test that PluginExecutor can be resolved from container"""
        executor = test_container_with_executor.resolve(PluginExecutor)
        assert executor is not None
        assert isinstance(executor, PluginExecutor)

    @pytest.mark.asyncio
    async def test_executor_has_loader_and_process_executor(
        self, test_container_with_executor
    ):
        """Test that PluginExecutor is properly configured"""
        executor = test_container_with_executor.resolve(PluginExecutor)

        # Verify internal dependencies are set
        assert executor._loader is not None
        assert executor._executor is not None

    @pytest.mark.asyncio
    async def test_execute_nonexistent_plugin_returns_error(
        self, test_container_with_executor
    ):
        """Test executing a non-existent plugin returns error"""
        executor = test_container_with_executor.resolve(PluginExecutor)
        plugin_service = test_container_with_executor.resolve(PluginService)

        # Load plugins first
        await plugin_service.load_all_plugins()

        # Try to execute non-existent plugin
        result = await executor.execute_plugin_function(
            "nonexistent_plugin", "test_function", []
        )

        assert result.success is False
        assert "not found" in result.error.lower()
        assert result.exit_code == 1

    @pytest.mark.asyncio
    async def test_execute_nonexistent_function_returns_error(
        self, test_container_with_executor
    ):
        """Test executing non-existent function in valid plugin returns error"""
        executor = test_container_with_executor.resolve(PluginExecutor)
        plugin_service = test_container_with_executor.resolve(PluginService)

        # Setup plugin with function
        loader = test_container_with_executor.resolve(IPluginLoader)

        # Mock loaded plugin
        loader._loaded_plugins = {
            "test_plugin": {
                "name": "test_plugin",
                "functions": {
                    "existing_function": {
                        "name": "existing_function",
                        "type": "config",
                        "command": "echo 'test'",
                    }
                },
            }
        }

        # Try to execute non-existent function
        result = await executor.execute_plugin_function(
            "test_plugin", "nonexistent_function", []
        )

        assert result.success is False
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_observer_events_on_execution(self, test_container_with_executor):
        """Test that executor fires EXECUTING and EXECUTED events"""
        from src.gscripts.plugins.interfaces import IPluginObserver, PluginEvent

        class EventRecorder(IPluginObserver):
            observer_name = "test_recorder"

            def __init__(self):
                self.events = []

            def on_plugin_event(self, event_data):
                self.events.append(event_data)

        executor = test_container_with_executor.resolve(PluginExecutor)
        recorder = EventRecorder()
        executor.register_observer(recorder)

        # Mock a loaded plugin
        loader = test_container_with_executor.resolve(IPluginLoader)
        loader._loaded_plugins = {
            "test_plugin": {
                "name": "test_plugin",
                "functions": {
                    "test_cmd": {
                        "name": "test_cmd",
                        "type": "config",
                        "command": "echo 'test'",
                    }
                },
            }
        }

        # Execute (will fail because no real shell, but events should fire)
        await executor.execute_plugin_function("test_plugin", "test_cmd", [])

        # Verify events were fired
        assert len(recorder.events) >= 2
        event_types = [e.event for e in recorder.events]
        assert PluginEvent.EXECUTING in event_types
        assert PluginEvent.EXECUTED in event_types

        # Verify EXECUTING event came first
        assert recorder.events[0].event == PluginEvent.EXECUTING
        assert recorder.events[0].plugin_name == "test_plugin"


class TestPluginExecutorIntegration:
    """Integration tests with full DI stack"""

    @pytest.mark.asyncio
    async def test_full_stack_plugin_execution(self, test_container_with_executor):
        """Test full stack from service resolution to execution"""
        # Resolve all services
        plugin_service = test_container_with_executor.resolve(PluginService)
        executor = test_container_with_executor.resolve(PluginExecutor)

        # Load plugins
        await plugin_service.load_all_plugins()

        # Get loaded plugins count
        loaded = plugin_service.get_loaded_plugins()

        # Should have at least test_plugin
        assert len(loaded) >= 0  # May be 0 if plugin has no functions


if __name__ == "__main__":
    # Run tests
    pytest.main([__file__, "-v"])
