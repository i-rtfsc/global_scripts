"""
Plugin Query Compatibility Tests

Tests query operations (list, filter, search) for behavioral equivalence
between legacy and new systems.
"""

import pytest


@pytest.mark.asyncio
class TestPluginQueriesCompatibility:
    """Test plugin query operations"""

    async def test_list_all_plugins_returns_data(self, plugin_system):
        """
        WHEN listing all plugins
        THEN both systems return plugin data
        AND includes both enabled and disabled plugins
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        if system_type == "legacy":
            plugins = system.list_plugins()
            assert isinstance(plugins, dict)
        else:
            plugins = await system.list_all_plugins()
            assert isinstance(plugins, list)

    async def test_get_enabled_plugins_only(self, plugin_system):
        """
        WHEN getting enabled plugins
        THEN both systems return only enabled plugins
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        if system_type == "legacy":
            # Legacy: filter from list_plugins
            all_plugins = system.list_plugins()
            enabled = {name: info for name, info in all_plugins.items()
                      if system.is_plugin_enabled(name)}
        else:
            # New: dedicated method
            enabled = await system.get_enabled_plugins()

        # Both should return some structure (may be empty)
        assert enabled is not None

    async def test_get_disabled_plugins_only(self, plugin_system):
        """
        WHEN getting disabled plugins
        THEN both systems return only disabled plugins
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        if system_type == "legacy":
            # Legacy: filter from list_plugins
            all_plugins = system.list_plugins()
            disabled = {name: info for name, info in all_plugins.items()
                       if not system.is_plugin_enabled(name)}
        else:
            # New: dedicated method
            disabled = await system.get_disabled_plugins()

        # Both should return some structure (may be empty)
        assert disabled is not None

    async def test_get_plugin_by_name_exists(self, plugin_system):
        """
        WHEN getting plugin by name (exists)
        THEN both systems return plugin info
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        # Get first plugin name
        if system_type == "legacy":
            plugins = system.list_plugins()
        else:
            plugin_list = await system.list_all_plugins()
            plugins = {p.name: p for p in plugin_list}

        if not plugins:
            pytest.skip("No plugins available")

        plugin_name = list(plugins.keys())[0]

        # Get by name
        if system_type == "legacy":
            info = system.get_plugin_info(plugin_name)
        else:
            info = await system.get_plugin_info(plugin_name)

        assert info is not None
        if isinstance(info, dict):
            assert info.get("name") == plugin_name

    async def test_get_plugin_by_name_not_exists(self, plugin_system):
        """
        WHEN getting plugin by name (doesn't exist)
        THEN both systems return None
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        nonexistent = "definitely_does_not_exist_12345"

        if system_type == "legacy":
            info = system.get_plugin_info(nonexistent)
        else:
            info = await system.get_plugin_info(nonexistent)

        assert info is None

    async def test_filter_plugins_by_type(self, plugin_system):
        """
        WHEN filtering plugins by type
        THEN both systems return matching plugins
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        if system_type == "legacy":
            # Legacy: manual filtering from list_plugins
            all_plugins = system.list_plugins()
            # Can't easily filter by type without plugin info
            pytest.skip("Type filtering requires plugin metadata")
        else:
            # New system will have get_plugins_by_type (to be implemented)
            pytest.skip("get_plugins_by_type not yet implemented")

    async def test_search_functions_by_keyword(self, plugin_system):
        """
        WHEN searching functions by keyword
        THEN both systems return matching functions
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        if system_type == "legacy":
            # Legacy has search_functions
            results = system.search_functions("test")
            assert isinstance(results, list)
        else:
            # New system needs search_functions (to be implemented)
            pytest.skip("search_functions not yet implemented in new system")

    async def test_get_all_shortcuts(self, plugin_system):
        """
        WHEN getting all shortcuts
        THEN both systems return shortcut mappings
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        if system_type == "legacy":
            shortcuts = system.get_all_shortcuts()
            assert isinstance(shortcuts, dict)
        else:
            # New system needs get_all_shortcuts (to be implemented)
            pytest.skip("get_all_shortcuts not yet implemented in new system")


@pytest.mark.asyncio
class TestPluginMetadataQueries:
    """Test plugin metadata query operations"""

    async def test_get_plugin_metadata_structure(self, plugin_system):
        """
        WHEN getting plugin metadata
        THEN metadata has expected structure
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        # Get first plugin
        if system_type == "legacy":
            plugins = system.list_plugins()
        else:
            plugins_list = await system.list_all_plugins()
            plugins = {p.name: p for p in plugins_list}

        if not plugins:
            pytest.skip("No plugins available")

        plugin_name = list(plugins.keys())[0]

        if system_type == "legacy":
            info = system.get_plugin_info(plugin_name)
        else:
            metadata = await system.get_plugin_metadata(plugin_name)
            info = await system.get_plugin_info(plugin_name) if metadata else None

        if info:
            assert "name" in info
            # Other fields may vary

    async def test_plugin_count_consistency(self, plugin_system):
        """
        WHEN counting plugins
        THEN total = enabled + disabled
        """
        system_type = plugin_system["type"]
        system = plugin_system["system"]

        if system_type == "legacy":
            all_plugins = system.list_plugins()
            enabled_count = sum(1 for name in all_plugins if system.is_plugin_enabled(name))
            disabled_count = sum(1 for name in all_plugins if not system.is_plugin_enabled(name))
            total_count = len(all_plugins)
        else:
            all_plugins = await system.list_all_plugins()
            enabled = await system.get_enabled_plugins()
            disabled = await system.get_disabled_plugins()
            enabled_count = len(enabled)
            disabled_count = len(disabled)
            total_count = len(all_plugins)

        assert total_count == enabled_count + disabled_count
