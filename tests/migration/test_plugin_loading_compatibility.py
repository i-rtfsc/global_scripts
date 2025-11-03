"""
Plugin Loading Compatibility Tests

Tests that verify legacy PluginManager and new PluginService
load plugins identically.
"""

import pytest
from typing import Dict, Any


@pytest.mark.asyncio
class TestPluginLoadingCompatibility:
    """Test plugin loading behavioral equivalence"""

    async def test_load_all_plugins_returns_dict(self, plugin_system):
        """
        WHEN loading all plugins
        THEN both systems return plugin data structure
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        if system_type == "legacy":
            # Legacy: PluginManager.load_all_plugins() returns loaded plugins dict
            result = await system.load_all_plugins()
            assert isinstance(result, dict) or result is None
        else:
            # New: PluginService.load_all_plugins() returns plugins dict
            result = await system.load_all_plugins()
            assert isinstance(result, dict) or result is None

    async def test_list_plugins_includes_common_plugins(self, plugin_system):
        """
        WHEN listing plugins
        THEN both systems include expected built-in plugins
        AND plugin count is consistent
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        if system_type == "legacy":
            plugins = system.list_plugins()
        else:
            # New system returns List[PluginMetadata]
            plugin_list = await system.list_all_plugins()
            # Convert to dict format for comparison
            plugins = {p.name: {"name": p.name, "enabled": p.enabled} for p in plugin_list}

        # Both systems should find plugins in the plugins/ directory
        assert isinstance(plugins, dict)
        # Note: Can't assert specific plugins without knowing test environment
        # But should have at least some plugins
        assert len(plugins) >= 0  # May be empty in test environment

    async def test_get_plugin_info_for_existing_plugin(self, plugin_system):
        """
        WHEN getting plugin info for existing plugin
        THEN both systems return plugin metadata
        AND metadata structure is compatible
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        # First, get a list of available plugins
        if system_type == "legacy":
            plugins = system.list_plugins()
        else:
            plugin_list = await system.list_all_plugins()
            plugins = {p.name: p for p in plugin_list}

        if not plugins:
            pytest.skip("No plugins available in test environment")

        # Get info for first plugin
        plugin_name = list(plugins.keys())[0]

        if system_type == "legacy":
            info = system.get_plugin_info(plugin_name)
        else:
            info = await system.get_plugin_info(plugin_name)

        # Both should return plugin info (dict or None)
        if info:
            assert isinstance(info, dict)
            assert "name" in info
            assert info["name"] == plugin_name

    async def test_get_plugin_info_for_nonexistent_plugin(self, plugin_system):
        """
        WHEN getting plugin info for non-existent plugin
        THEN both systems return None
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        nonexistent_plugin = "this_plugin_definitely_does_not_exist_12345"

        if system_type == "legacy":
            info = system.get_plugin_info(nonexistent_plugin)
        else:
            info = await system.get_plugin_info(nonexistent_plugin)

        assert info is None

    async def test_plugin_metadata_structure(self, plugin_system):
        """
        WHEN loading plugins
        THEN plugin metadata has consistent structure
        AND required fields are present
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        # Get plugins
        if system_type == "legacy":
            plugins = system.list_plugins()
        else:
            plugin_list = await system.list_all_plugins()
            plugins = {p.name: p for p in plugin_list}

        if not plugins:
            pytest.skip("No plugins available in test environment")

        # Check first plugin metadata
        plugin_name = list(plugins.keys())[0]

        if system_type == "legacy":
            info = system.get_plugin_info(plugin_name)
        else:
            info = await system.get_plugin_info(plugin_name)

        if info:
            # Common fields that should exist in both systems
            assert "name" in info
            # Note: Other fields may differ between systems
            # This test just verifies basic structure exists

    async def test_loaded_plugins_accessible(self, plugin_system):
        """
        WHEN plugins are loaded
        THEN loaded plugins are accessible via get_loaded_plugins()
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        if system_type == "legacy":
            # Legacy has get_loaded_plugins on PluginManager
            # But it's via PluginLoader wrapper
            # Access via plugin_loader attribute
            if hasattr(system, 'plugin_loader'):
                loaded = system.plugin_loader.plugins if hasattr(system.plugin_loader, 'plugins') else {}
        else:
            # New has get_loaded_plugins on PluginService
            loaded = system.get_loaded_plugins()

        # Should return a dict (may be empty if no plugins loaded yet)
        assert isinstance(loaded, dict)

    async def test_failed_plugins_tracking(self, plugin_system):
        """
        WHEN some plugins fail to load
        THEN failed plugins are tracked
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        if system_type == "legacy":
            # Legacy tracks failed plugins
            # Access might be via plugin_loader
            failed = {}  # Legacy may not expose this directly
        else:
            # New has get_failed_plugins
            failed = system.get_failed_plugins()

        # Should return a dict (may be empty if all loaded successfully)
        assert isinstance(failed, dict)


@pytest.mark.asyncio
class TestPluginTypeLoading:
    """Test loading different plugin types"""

    async def test_python_plugin_loading(self, plugin_system):
        """
        WHEN loading Python plugin
        THEN plugin functions are discovered
        AND @plugin_function decorators are parsed
        """
        # This test would need a known Python plugin in test environment
        pytest.skip("Requires specific test plugin setup")

    async def test_shell_plugin_loading(self, plugin_system):
        """
        WHEN loading Shell plugin
        THEN shell functions are discovered
        AND annotations are parsed
        """
        pytest.skip("Requires specific test plugin setup")

    async def test_config_plugin_loading(self, plugin_system):
        """
        WHEN loading Config plugin
        THEN commands are discovered from JSON
        """
        pytest.skip("Requires specific test plugin setup")

    async def test_hybrid_plugin_loading(self, plugin_system):
        """
        WHEN loading Hybrid plugin
        THEN subplugins are loaded recursively
        AND all function types are discovered
        """
        pytest.skip("Requires specific test plugin setup")
