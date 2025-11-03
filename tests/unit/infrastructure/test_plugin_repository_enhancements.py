"""
Unit tests for PluginRepository enhancements

Tests for new methods:
- get_enabled()
- get_by_type()
- update_enabled_status()
"""

import pytest
from pathlib import Path
from unittest.mock import Mock

from gscripts.infrastructure.persistence.plugin_repository import PluginRepository
from gscripts.models.plugin import PluginMetadata, PluginType


@pytest.fixture
def mock_filesystem():
    """Create mock filesystem"""
    fs = Mock()
    fs.exists = Mock(return_value=False)
    fs.list_dir = Mock(return_value=[])
    fs.read_json = Mock(return_value={})
    fs.write_json = Mock()
    return fs


@pytest.fixture
def sample_plugins():
    """Create sample plugin metadata"""
    return [
        PluginMetadata(
            name="plugin1",
            version="1.0.0",
            enabled=True,
            type=PluginType.PYTHON
        ),
        PluginMetadata(
            name="plugin2",
            version="1.0.0",
            enabled=False,
            type=PluginType.SHELL
        ),
        PluginMetadata(
            name="plugin3",
            version="1.0.0",
            enabled=True,
            type=PluginType.PYTHON
        ),
        PluginMetadata(
            name="plugin4",
            version="1.0.0",
            enabled=True,
            type=PluginType.CONFIG
        ),
    ]


@pytest.fixture
def repository(mock_filesystem):
    """Create PluginRepository instance"""
    return PluginRepository(
        filesystem=mock_filesystem,
        plugins_dir=Path("/test/plugins"),
        router_cache_path=None
    )


class TestPluginRepositoryGetEnabled:
    """Tests for get_enabled() method"""

    @pytest.mark.asyncio
    async def test_get_enabled_returns_only_enabled_plugins(self, repository, sample_plugins):
        """Test that get_enabled returns only enabled plugins"""
        # Pre-populate cache
        for plugin in sample_plugins:
            repository._cache[plugin.name] = plugin

        enabled = await repository.get_enabled()

        assert len(enabled) == 3
        assert all(p.enabled for p in enabled)
        assert {p.name for p in enabled} == {"plugin1", "plugin3", "plugin4"}

    @pytest.mark.asyncio
    async def test_get_enabled_returns_empty_when_no_plugins(self, repository):
        """Test that get_enabled returns empty list when no plugins"""
        enabled = await repository.get_enabled()

        assert enabled == []

    @pytest.mark.asyncio
    async def test_get_enabled_returns_empty_when_all_disabled(self, repository):
        """Test that get_enabled returns empty when all plugins disabled"""
        # Add all disabled plugins to cache
        disabled_plugins = [
            PluginMetadata(name=f"plugin{i}", version="1.0.0", enabled=False)
            for i in range(3)
        ]
        for plugin in disabled_plugins:
            repository._cache[plugin.name] = plugin

        enabled = await repository.get_enabled()

        assert enabled == []


class TestPluginRepositoryGetByType:
    """Tests for get_by_type() method"""

    @pytest.mark.asyncio
    async def test_get_by_type_filters_by_python(self, repository, sample_plugins):
        """Test that get_by_type filters Python plugins"""
        for plugin in sample_plugins:
            repository._cache[plugin.name] = plugin

        python_plugins = await repository.get_by_type(PluginType.PYTHON)

        assert len(python_plugins) == 2
        assert all(p.type == PluginType.PYTHON for p in python_plugins)
        assert {p.name for p in python_plugins} == {"plugin1", "plugin3"}

    @pytest.mark.asyncio
    async def test_get_by_type_filters_by_shell(self, repository, sample_plugins):
        """Test that get_by_type filters Shell plugins"""
        for plugin in sample_plugins:
            repository._cache[plugin.name] = plugin

        shell_plugins = await repository.get_by_type(PluginType.SHELL)

        assert len(shell_plugins) == 1
        assert shell_plugins[0].name == "plugin2"
        assert shell_plugins[0].type == PluginType.SHELL

    @pytest.mark.asyncio
    async def test_get_by_type_filters_by_config(self, repository, sample_plugins):
        """Test that get_by_type filters Config plugins"""
        for plugin in sample_plugins:
            repository._cache[plugin.name] = plugin

        config_plugins = await repository.get_by_type(PluginType.CONFIG)

        assert len(config_plugins) == 1
        assert config_plugins[0].name == "plugin4"
        assert config_plugins[0].type == PluginType.CONFIG

    @pytest.mark.asyncio
    async def test_get_by_type_returns_empty_when_no_match(self, repository, sample_plugins):
        """Test that get_by_type returns empty when no plugins match"""
        for plugin in sample_plugins:
            repository._cache[plugin.name] = plugin

        hybrid_plugins = await repository.get_by_type(PluginType.HYBRID)

        assert hybrid_plugins == []

    @pytest.mark.asyncio
    async def test_get_by_type_returns_empty_when_no_plugins(self, repository):
        """Test that get_by_type returns empty when no plugins"""
        python_plugins = await repository.get_by_type(PluginType.PYTHON)

        assert python_plugins == []


class TestPluginRepositoryUpdateEnabledStatus:
    """Tests for update_enabled_status() method"""

    @pytest.mark.asyncio
    async def test_update_enabled_status_enables_plugin(self, repository, mock_filesystem):
        """Test that update_enabled_status can enable a plugin"""
        plugin = PluginMetadata(name="test", version="1.0.0", enabled=False)
        repository._cache["test"] = plugin

        result = await repository.update_enabled_status("test", True)

        assert result is True
        assert plugin.enabled is True
        mock_filesystem.write_json.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_enabled_status_disables_plugin(self, repository, mock_filesystem):
        """Test that update_enabled_status can disable a plugin"""
        plugin = PluginMetadata(name="test", version="1.0.0", enabled=True)
        repository._cache["test"] = plugin

        result = await repository.update_enabled_status("test", False)

        assert result is True
        assert plugin.enabled is False
        mock_filesystem.write_json.assert_called_once()

    @pytest.mark.asyncio
    async def test_update_enabled_status_returns_false_for_nonexistent(self, repository):
        """Test that update_enabled_status returns False for nonexistent plugin"""
        result = await repository.update_enabled_status("nonexistent", True)

        assert result is False

    @pytest.mark.asyncio
    async def test_update_enabled_status_updates_cache(self, repository, mock_filesystem):
        """Test that update_enabled_status updates cache"""
        plugin = PluginMetadata(name="test", version="1.0.0", enabled=False)
        repository._cache["test"] = plugin

        await repository.update_enabled_status("test", True)

        # Cache should be updated
        assert repository._cache["test"].enabled is True

    @pytest.mark.asyncio
    async def test_update_enabled_status_idempotent(self, repository, mock_filesystem):
        """Test that update_enabled_status is idempotent"""
        plugin = PluginMetadata(name="test", version="1.0.0", enabled=True)
        repository._cache["test"] = plugin

        # Enable already enabled plugin
        result = await repository.update_enabled_status("test", True)

        assert result is True
        assert plugin.enabled is True  # Still enabled
        mock_filesystem.write_json.assert_called_once()


class TestPluginRepositoryIntegration:
    """Integration tests for repository methods working together"""

    @pytest.mark.asyncio
    async def test_get_enabled_after_update(self, repository, sample_plugins):
        """Test that get_enabled reflects changes after update_enabled_status"""
        for plugin in sample_plugins:
            repository._cache[plugin.name] = plugin

        # Initially 3 enabled
        enabled_before = await repository.get_enabled()
        assert len(enabled_before) == 3

        # Disable one
        await repository.update_enabled_status("plugin1", False)

        # Now 2 enabled
        enabled_after = await repository.get_enabled()
        assert len(enabled_after) == 2
        assert "plugin1" not in {p.name for p in enabled_after}

    @pytest.mark.asyncio
    async def test_get_by_type_includes_disabled(self, repository, sample_plugins):
        """Test that get_by_type returns plugins regardless of enabled status"""
        for plugin in sample_plugins:
            repository._cache[plugin.name] = plugin

        # Get Python plugins (should include both enabled and disabled)
        python_plugins = await repository.get_by_type(PluginType.PYTHON)

        assert len(python_plugins) == 2
        # Both enabled and disabled Python plugins returned
        assert {p.name for p in python_plugins} == {"plugin1", "plugin3"}
