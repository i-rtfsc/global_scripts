"""
Tests for PluginRepository
"""

import pytest
from pathlib import Path

from src.gscripts.infrastructure.persistence import PluginRepository
from src.gscripts.infrastructure.filesystem import InMemoryFileSystem
from src.gscripts.models.plugin import PluginMetadata


@pytest.fixture
def mock_filesystem():
    """Provide mock filesystem"""
    return InMemoryFileSystem()


@pytest.fixture
def plugins_dir():
    """Provide test plugins directory"""
    return Path("/test/plugins")


@pytest.fixture
def plugin_repository(mock_filesystem, plugins_dir):
    """Provide plugin repository"""
    return PluginRepository(mock_filesystem, plugins_dir)


class TestPluginRepository:
    """Tests for PluginRepository"""

    @pytest.mark.asyncio
    async def test_get_all_returns_empty_when_no_plugins(self, plugin_repository):
        """Test get_all returns empty list when no plugins exist"""
        plugins = await plugin_repository.get_all()

        assert plugins == []

    @pytest.mark.asyncio
    async def test_get_all_returns_plugins(
        self, plugin_repository, mock_filesystem, plugins_dir
    ):
        """Test get_all returns all plugins"""
        # Create test plugin
        plugin_json = plugins_dir / "test_plugin" / "plugin.json"
        mock_filesystem.write_json(
            plugin_json,
            {
                "name": "test_plugin",
                "version": "1.0.0",
                "description": "Test plugin",
                "enabled": True,
            },
        )

        plugins = await plugin_repository.get_all()

        assert len(plugins) == 1
        assert plugins[0].name == "test_plugin"
        assert plugins[0].version == "1.0.0"
        assert plugins[0].enabled is True

    @pytest.mark.asyncio
    async def test_get_by_name_returns_none_when_not_found(self, plugin_repository):
        """Test get_by_name returns None when plugin not found"""
        plugin = await plugin_repository.get_by_name("nonexistent")

        assert plugin is None

    @pytest.mark.asyncio
    async def test_get_by_name_returns_plugin(
        self, plugin_repository, mock_filesystem, plugins_dir
    ):
        """Test get_by_name returns plugin"""
        # Create test plugin
        plugin_json = plugins_dir / "my_plugin" / "plugin.json"
        mock_filesystem.write_json(
            plugin_json,
            {"name": "my_plugin", "version": "2.0.0", "description": "My plugin"},
        )

        plugin = await plugin_repository.get_by_name("my_plugin")

        assert plugin is not None
        assert plugin.name == "my_plugin"
        assert plugin.version == "2.0.0"

    @pytest.mark.asyncio
    async def test_save_creates_new_plugin(
        self, plugin_repository, mock_filesystem, plugins_dir
    ):
        """Test save creates new plugin"""
        plugin_meta = PluginMetadata(
            name="new_plugin", version="1.0.0", description="New plugin", enabled=True
        )

        await plugin_repository.save(plugin_meta)

        # Verify file was written
        plugin_json = plugins_dir / "new_plugin" / "plugin.json"
        assert mock_filesystem.exists(plugin_json)

        data = mock_filesystem.read_json(plugin_json)
        assert data["name"] == "new_plugin"
        assert data["version"] == "1.0.0"

    @pytest.mark.asyncio
    async def test_save_updates_existing_plugin(
        self, plugin_repository, mock_filesystem, plugins_dir
    ):
        """Test save updates existing plugin"""
        # Create initial plugin
        plugin_json = plugins_dir / "existing" / "plugin.json"
        mock_filesystem.write_json(
            plugin_json,
            {
                "name": "existing",
                "version": "1.0.0",
                "enabled": True,
                "extra_field": "should_remain",
            },
        )

        # Update plugin
        plugin_meta = PluginMetadata(name="existing", version="2.0.0", enabled=False)

        await plugin_repository.save(plugin_meta)

        # Verify update
        data = mock_filesystem.read_json(plugin_json)
        assert data["version"] == "2.0.0"
        assert data["enabled"] is False
        assert data["extra_field"] == "should_remain"  # Preserved

    @pytest.mark.asyncio
    async def test_delete_disables_plugin(
        self, plugin_repository, mock_filesystem, plugins_dir
    ):
        """Test delete marks plugin as disabled"""
        # Create plugin
        plugin_json = plugins_dir / "to_delete" / "plugin.json"
        mock_filesystem.write_json(
            plugin_json, {"name": "to_delete", "version": "1.0.0", "enabled": True}
        )

        result = await plugin_repository.delete("to_delete")

        assert result is True

        # Verify plugin is disabled
        data = mock_filesystem.read_json(plugin_json)
        assert data["enabled"] is False

    @pytest.mark.asyncio
    async def test_delete_returns_false_when_not_found(self, plugin_repository):
        """Test delete returns False when plugin not found"""
        result = await plugin_repository.delete("nonexistent")

        assert result is False

    @pytest.mark.asyncio
    async def test_cache_is_used_for_repeated_access(
        self, plugin_repository, mock_filesystem, plugins_dir
    ):
        """Test that cache is used for repeated access"""
        # Create plugin
        plugin_json = plugins_dir / "cached" / "plugin.json"
        mock_filesystem.write_json(plugin_json, {"name": "cached", "version": "1.0.0"})

        # First access - loads from filesystem
        plugin1 = await plugin_repository.get_by_name("cached")

        # Second access - should use cache
        plugin2 = await plugin_repository.get_by_name("cached")

        assert plugin1 is plugin2  # Same object reference
