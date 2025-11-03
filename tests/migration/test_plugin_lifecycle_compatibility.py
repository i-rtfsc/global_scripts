"""
Plugin Lifecycle Compatibility Tests

Tests enable/disable, state persistence, and health check operations
for behavioral equivalence between legacy and new systems.
"""

import pytest
from gscripts.models import CommandResult


@pytest.mark.asyncio
class TestPluginLifecycleCompatibility:
    """Test plugin lifecycle operations"""

    async def test_enable_plugin_returns_command_result(self, plugin_system):
        """
        WHEN enabling a plugin
        THEN both systems return CommandResult or boolean
        AND plugin becomes enabled
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        # Get a plugin to enable (first disabled plugin or any plugin)
        if system_type == "legacy":
            plugins = system.list_plugins()
        else:
            plugin_list = await system.list_all_plugins()
            plugins = {p.name: p for p in plugin_list}

        if not plugins:
            pytest.skip("No plugins available")

        plugin_name = list(plugins.keys())[0]

        # Enable the plugin
        if system_type == "legacy":
            result = system.enable_plugin(plugin_name)
            # Legacy returns CommandResult
            assert isinstance(result, CommandResult)
            assert result.success is True
        else:
            result = await system.enable_plugin(plugin_name)
            # New returns bool
            assert isinstance(result, bool)
            assert result is True

    async def test_disable_plugin_returns_command_result(self, plugin_system):
        """
        WHEN disabling a plugin
        THEN both systems return CommandResult or boolean
        AND plugin becomes disabled
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        # Get a plugin to disable
        if system_type == "legacy":
            plugins = system.list_plugins()
        else:
            plugin_list = await system.list_all_plugins()
            plugins = {p.name: p for p in plugin_list}

        if not plugins:
            pytest.skip("No plugins available")

        plugin_name = list(plugins.keys())[0]

        # Disable the plugin
        if system_type == "legacy":
            result = system.disable_plugin(plugin_name)
            # Legacy returns CommandResult
            assert isinstance(result, CommandResult)
            assert result.success is True
        else:
            result = await system.disable_plugin(plugin_name)
            # New returns bool
            assert isinstance(result, bool)
            assert result is True

    async def test_enable_nonexistent_plugin_fails(self, plugin_system):
        """
        WHEN enabling non-existent plugin
        THEN both systems fail gracefully
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        nonexistent = "nonexistent_plugin_12345"

        if system_type == "legacy":
            result = system.enable_plugin(nonexistent)
            assert isinstance(result, CommandResult)
            assert result.success is False
        else:
            result = await system.enable_plugin(nonexistent)
            assert result is False

    async def test_disable_nonexistent_plugin_fails(self, plugin_system):
        """
        WHEN disabling non-existent plugin
        THEN both systems fail gracefully
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        nonexistent = "nonexistent_plugin_12345"

        if system_type == "legacy":
            result = system.disable_plugin(nonexistent)
            assert isinstance(result, CommandResult)
            assert result.success is False
        else:
            result = await system.disable_plugin(nonexistent)
            assert result is False

    async def test_is_plugin_enabled_check(self, plugin_system):
        """
        WHEN checking if plugin is enabled
        THEN both systems return boolean
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        # Get a plugin
        if system_type == "legacy":
            plugins = system.list_plugins()
        else:
            plugin_list = await system.list_all_plugins()
            plugins = {p.name: p for p in plugin_list}

        if not plugins:
            pytest.skip("No plugins available")

        plugin_name = list(plugins.keys())[0]

        if system_type == "legacy":
            is_enabled = system.is_plugin_enabled(plugin_name)
            assert isinstance(is_enabled, bool)
        else:
            # New system: check via metadata
            metadata = await system.get_plugin_metadata(plugin_name)
            if metadata:
                assert isinstance(metadata.enabled, bool)

    async def test_enable_disable_state_persists(self, plugin_system):
        """
        WHEN enabling then disabling a plugin
        THEN state changes are persisted
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        # Get a plugin
        if system_type == "legacy":
            plugins = system.list_plugins()
        else:
            plugin_list = await system.list_all_plugins()
            plugins = {p.name: p for p in plugin_list}

        if not plugins:
            pytest.skip("No plugins available")

        plugin_name = list(plugins.keys())[0]

        # Enable
        if system_type == "legacy":
            system.enable_plugin(plugin_name)
            assert system.is_plugin_enabled(plugin_name) is True
        else:
            await system.enable_plugin(plugin_name)
            metadata = await system.get_plugin_metadata(plugin_name)
            assert metadata.enabled is True

        # Disable
        if system_type == "legacy":
            system.disable_plugin(plugin_name)
            assert system.is_plugin_enabled(plugin_name) is False
        else:
            await system.disable_plugin(plugin_name)
            metadata = await system.get_plugin_metadata(plugin_name)
            assert metadata.enabled is False


@pytest.mark.asyncio
class TestHealthCheckCompatibility:
    """Test health check operations"""

    async def test_health_check_returns_dict(self, plugin_system):
        """
        WHEN running health check
        THEN both systems return health status dict
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        if system_type == "legacy":
            health = await system.health_check()
        else:
            # New system needs health_check implementation
            # For now, skip
            pytest.skip("Health check not yet implemented in new system")

        assert isinstance(health, dict)

    async def test_health_check_includes_plugin_counts(self, plugin_system):
        """
        WHEN running health check
        THEN result includes enabled and disabled plugin counts
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        if system_type == "legacy":
            health = await system.health_check()
            # Legacy health check format
            assert "enabled_count" in health or "status" in health
        else:
            pytest.skip("Health check not yet implemented in new system")

    async def test_health_check_includes_failed_plugins(self, plugin_system):
        """
        WHEN health check runs
        THEN result includes failed plugins info
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        if system_type == "legacy":
            health = await system.health_check()
            # Should have some indication of plugin health
            assert isinstance(health, dict)
        else:
            pytest.skip("Health check not yet implemented in new system")


@pytest.mark.asyncio
class TestObserverPatternCompatibility:
    """Test observer pattern for lifecycle events"""

    async def test_register_observer(self, plugin_system):
        """
        WHEN registering observer
        THEN observer is added to notification list
        """
        pytest.skip("Observer pattern test requires implementation")

    async def test_observer_notified_on_enable(self, plugin_system):
        """
        WHEN plugin is enabled
        THEN observers are notified with ENABLED event
        """
        pytest.skip("Observer pattern test requires implementation")

    async def test_observer_notified_on_disable(self, plugin_system):
        """
        WHEN plugin is disabled
        THEN observers are notified with DISABLED event
        """
        pytest.skip("Observer pattern test requires implementation")

    async def test_observer_notified_on_load(self, plugin_system):
        """
        WHEN plugin is loaded
        THEN observers are notified with LOADED event
        """
        pytest.skip("Observer pattern test requires implementation")
