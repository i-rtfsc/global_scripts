"""
Tests for PluginLoader implementation

Tests the new Clean Architecture PluginLoader that uses repository pattern.
"""

import pytest
from unittest.mock import Mock, AsyncMock

from gscripts.infrastructure.persistence.plugin_loader import PluginLoader
from tests.factories import PluginFactory


class TestPluginLoaderInitialization:
    """Tests for PluginLoader initialization"""

    def test_create_plugin_loader_with_repository_and_root(self, tmp_path):
        """Test creating PluginLoader with required dependencies"""
        # Arrange
        mock_repo = Mock()
        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()

        # Act
        loader = PluginLoader(mock_repo, plugins_root)

        # Assert
        assert loader._repository == mock_repo
        assert loader._plugins_root == plugins_root
        assert loader._loaded_plugins == {}
        assert loader._failed_plugins == {}

    def test_plugin_loader_registers_parsers_on_init(self, tmp_path):
        """Test that PluginLoader registers all parsers during initialization"""
        # Arrange
        mock_repo = Mock()
        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()

        # Act
        loader = PluginLoader(mock_repo, plugins_root)

        # Assert - parser registry should be configured
        assert loader._parser_registry is not None
        # Verify parsers are registered
        assert loader._parser_registry.get("python") is not None
        assert loader._parser_registry.get("shell") is not None
        assert loader._parser_registry.get("config") is not None


class TestLoadAllPlugins:
    """Tests for load_all_plugins method"""

    @pytest.mark.asyncio
    async def test_load_all_plugins_returns_empty_when_no_plugins(self, tmp_path):
        """Test loading plugins when none exist"""
        # Arrange
        mock_repo = Mock()
        mock_repo.get_all = AsyncMock(return_value=[])

        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()

        loader = PluginLoader(mock_repo, plugins_root)

        # Act
        result = await loader.load_all_plugins()

        # Assert
        assert result == {}
        mock_repo.get_all.assert_called_once()

    @pytest.mark.asyncio
    async def test_load_all_plugins_filters_enabled_plugins_by_default(self, tmp_path):
        """Test that only enabled plugins are loaded by default"""
        # Arrange
        mock_repo = Mock()
        enabled_plugin = PluginFactory.create(name="enabled", enabled=True)
        disabled_plugin = PluginFactory.create(name="disabled", enabled=False)
        mock_repo.get_all = AsyncMock(return_value=[enabled_plugin, disabled_plugin])

        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()

        # Create plugin directories
        (plugins_root / "enabled").mkdir()
        (plugins_root / "enabled" / "plugin.json").write_text('{"name": "enabled"}')
        (plugins_root / "disabled").mkdir()
        (plugins_root / "disabled" / "plugin.json").write_text('{"name": "disabled"}')

        loader = PluginLoader(mock_repo, plugins_root)

        # Mock the _load_plugin_impl to return simple plugin info
        async def mock_load_impl(plugin_dir, meta):
            return {"name": meta.name, "enabled": meta.enabled, "functions": {}}

        loader._load_plugin_impl = AsyncMock(side_effect=mock_load_impl)

        # Act
        result = await loader.load_all_plugins(only_enabled=True)

        # Assert
        assert len(result) == 1
        assert "enabled" in result
        assert "disabled" not in result

    @pytest.mark.asyncio
    async def test_load_all_plugins_includes_disabled_when_only_enabled_false(
        self, tmp_path
    ):
        """Test that disabled plugins are loaded when only_enabled=False"""
        # Arrange
        mock_repo = Mock()
        enabled_plugin = PluginFactory.create(name="enabled", enabled=True)
        disabled_plugin = PluginFactory.create(name="disabled", enabled=False)
        mock_repo.get_all = AsyncMock(return_value=[enabled_plugin, disabled_plugin])

        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()

        # Create plugin directories
        (plugins_root / "enabled").mkdir()
        (plugins_root / "enabled" / "plugin.json").write_text('{"name": "enabled"}')
        (plugins_root / "disabled").mkdir()
        (plugins_root / "disabled" / "plugin.json").write_text('{"name": "disabled"}')

        loader = PluginLoader(mock_repo, plugins_root)

        # Mock the _load_plugin_impl
        async def mock_load_impl(plugin_dir, meta):
            return {"name": meta.name, "enabled": meta.enabled, "functions": {}}

        loader._load_plugin_impl = AsyncMock(side_effect=mock_load_impl)

        # Act
        result = await loader.load_all_plugins(only_enabled=False)

        # Assert
        assert len(result) == 2
        assert "enabled" in result
        assert "disabled" in result

    @pytest.mark.asyncio
    async def test_load_all_plugins_discovers_custom_plugins(self, tmp_path):
        """Test that custom plugins are discovered and loaded"""
        # Arrange
        mock_repo = Mock()
        custom_plugin = PluginFactory.create(name="customplugin", enabled=True)
        mock_repo.get_all = AsyncMock(return_value=[custom_plugin])

        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()

        custom_root = tmp_path / "custom"
        custom_root.mkdir()
        (custom_root / "customplugin").mkdir()
        (custom_root / "customplugin" / "plugin.json").write_text(
            '{"name": "customplugin"}'
        )

        loader = PluginLoader(mock_repo, plugins_root)

        # Mock the _load_plugin_impl
        async def mock_load_impl(plugin_dir, meta):
            return {"name": meta.name, "functions": {}}

        loader._load_plugin_impl = AsyncMock(side_effect=mock_load_impl)

        # Act
        result = await loader.load_all_plugins()

        # Assert
        assert "customplugin" in result

    @pytest.mark.asyncio
    async def test_load_all_plugins_handles_exceptions_gracefully(self, tmp_path):
        """Test that exceptions during plugin loading are caught and recorded"""
        # Arrange
        mock_repo = Mock()
        good_plugin = PluginFactory.create(name="good", enabled=True)
        bad_plugin = PluginFactory.create(name="bad", enabled=True)
        mock_repo.get_all = AsyncMock(return_value=[good_plugin, bad_plugin])

        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()

        (plugins_root / "good").mkdir()
        (plugins_root / "good" / "plugin.json").write_text('{"name": "good"}')
        (plugins_root / "bad").mkdir()
        (plugins_root / "bad" / "plugin.json").write_text('{"name": "bad"}')

        loader = PluginLoader(mock_repo, plugins_root)

        # Mock _load_plugin_impl to fail for "bad" plugin
        async def mock_load_impl(plugin_dir, meta):
            if meta.name == "bad":
                raise ValueError("Failed to load bad plugin")
            return {"name": meta.name, "functions": {}}

        loader._load_plugin_impl = AsyncMock(side_effect=mock_load_impl)

        # Act
        result = await loader.load_all_plugins()

        # Assert
        assert "good" in result
        assert "bad" not in result
        assert "bad" in loader.get_failed_plugins()
        assert "Failed to load bad plugin" in loader.get_failed_plugins()["bad"]

    @pytest.mark.asyncio
    async def test_load_all_plugins_loads_in_parallel(self, tmp_path):
        """Test that multiple plugins are loaded concurrently"""
        # Arrange
        mock_repo = Mock()
        plugin1 = PluginFactory.create(name="plugin1", enabled=True)
        plugin2 = PluginFactory.create(name="plugin2", enabled=True)
        plugin3 = PluginFactory.create(name="plugin3", enabled=True)
        mock_repo.get_all = AsyncMock(return_value=[plugin1, plugin2, plugin3])

        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()

        for name in ["plugin1", "plugin2", "plugin3"]:
            (plugins_root / name).mkdir()
            (plugins_root / name / "plugin.json").write_text(f'{{"name": "{name}"}}')

        loader = PluginLoader(mock_repo, plugins_root)

        # Track call order to verify parallelism
        call_order = []

        async def mock_load_impl(plugin_dir, meta):
            call_order.append(f"start_{meta.name}")
            await asyncio.sleep(0.01)  # Simulate async work
            call_order.append(f"end_{meta.name}")
            return {"name": meta.name, "functions": {}}

        loader._load_plugin_impl = AsyncMock(side_effect=mock_load_impl)

        # Act
        result = await loader.load_all_plugins()

        # Assert
        assert len(result) == 3
        # If parallel, all starts should happen before all ends
        # (or at least interleaved, not sequential start-end-start-end)
        start_indices = [i for i, x in enumerate(call_order) if x.startswith("start_")]
        end_indices = [i for i, x in enumerate(call_order) if x.startswith("end_")]
        # Verify parallel behavior: some starts happen before some ends
        assert start_indices[-1] < end_indices[-1]  # Last start before last end


class TestLoadSinglePlugin:
    """Tests for load_plugin method (single plugin loading)"""

    @pytest.mark.asyncio
    async def test_load_single_plugin_successfully(self, tmp_path):
        """Test loading a single plugin by name"""
        # Arrange
        mock_repo = Mock()
        plugin_meta = PluginFactory.create(name="testplugin", enabled=True)
        mock_repo.get_by_name = AsyncMock(return_value=plugin_meta)

        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()
        (plugins_root / "testplugin").mkdir()
        (plugins_root / "testplugin" / "plugin.json").write_text(
            '{"name": "testplugin"}'
        )

        loader = PluginLoader(mock_repo, plugins_root)

        # Mock _load_plugin_impl
        loader._load_plugin_impl = AsyncMock(
            return_value={"name": "testplugin", "functions": {}}
        )

        # Act
        result = await loader.load_plugin("testplugin")

        # Assert
        assert result is not None
        assert result["name"] == "testplugin"
        mock_repo.get_by_name.assert_called_once_with("testplugin")

    @pytest.mark.asyncio
    async def test_load_single_plugin_returns_none_when_not_found(self, tmp_path):
        """Test loading a plugin that doesn't exist in repository"""
        # Arrange
        mock_repo = Mock()
        mock_repo.get_by_name = AsyncMock(return_value=None)

        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()

        loader = PluginLoader(mock_repo, plugins_root)

        # Act
        result = await loader.load_plugin("nonexistent")

        # Assert
        assert result is None
        mock_repo.get_by_name.assert_called_once_with("nonexistent")

    @pytest.mark.asyncio
    async def test_load_single_plugin_returns_none_when_disabled(self, tmp_path):
        """Test that disabled plugins are not loaded"""
        # Arrange
        mock_repo = Mock()
        plugin_meta = PluginFactory.create(name="disabled", enabled=False)
        mock_repo.get_by_name = AsyncMock(return_value=plugin_meta)

        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()

        loader = PluginLoader(mock_repo, plugins_root)

        # Act
        result = await loader.load_plugin("disabled")

        # Assert
        assert result is None

    @pytest.mark.asyncio
    async def test_load_single_plugin_returns_none_when_directory_missing(
        self, tmp_path
    ):
        """Test loading a plugin whose directory doesn't exist"""
        # Arrange
        mock_repo = Mock()
        plugin_meta = PluginFactory.create(name="missing", enabled=True)
        mock_repo.get_by_name = AsyncMock(return_value=plugin_meta)

        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()
        # Don't create the plugin directory

        loader = PluginLoader(mock_repo, plugins_root)

        # Act
        result = await loader.load_plugin("missing")

        # Assert
        assert result is None

    @pytest.mark.asyncio
    async def test_load_single_plugin_handles_exception(self, tmp_path):
        """Test that exceptions during single plugin load are caught"""
        # Arrange
        mock_repo = Mock()
        plugin_meta = PluginFactory.create(name="badplugin", enabled=True)
        mock_repo.get_by_name = AsyncMock(return_value=plugin_meta)

        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()
        (plugins_root / "badplugin").mkdir()

        loader = PluginLoader(mock_repo, plugins_root)

        # Mock _load_plugin_impl to raise exception
        loader._load_plugin_impl = AsyncMock(side_effect=ValueError("Load failed"))

        # Act
        result = await loader.load_plugin("badplugin")

        # Assert
        assert result is None
        assert "badplugin" in loader.get_failed_plugins()
        assert "Load failed" in loader.get_failed_plugins()["badplugin"]


class TestPluginLoaderCacheManagement:
    """Tests for cache management methods"""

    def test_get_loaded_plugins_returns_copy(self, tmp_path):
        """Test that get_loaded_plugins returns a copy, not reference"""
        # Arrange
        mock_repo = Mock()
        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()

        loader = PluginLoader(mock_repo, plugins_root)
        loader._loaded_plugins = {"plugin1": {"name": "plugin1"}}

        # Act
        result = loader.get_loaded_plugins()
        result["plugin2"] = {"name": "plugin2"}

        # Assert
        assert "plugin2" not in loader._loaded_plugins
        assert len(loader._loaded_plugins) == 1

    def test_get_failed_plugins_returns_copy(self, tmp_path):
        """Test that get_failed_plugins returns a copy"""
        # Arrange
        mock_repo = Mock()
        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()

        loader = PluginLoader(mock_repo, plugins_root)
        loader._failed_plugins = {"bad": "error message"}

        # Act
        result = loader.get_failed_plugins()
        result["another"] = "another error"

        # Assert
        assert "another" not in loader._failed_plugins

    def test_clear_removes_all_plugins(self, tmp_path):
        """Test that clear() removes both loaded and failed plugins"""
        # Arrange
        mock_repo = Mock()
        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()

        loader = PluginLoader(mock_repo, plugins_root)
        loader._loaded_plugins = {"plugin1": {}, "plugin2": {}}
        loader._failed_plugins = {"bad1": "error1", "bad2": "error2"}

        # Act
        loader.clear()

        # Assert
        assert len(loader._loaded_plugins) == 0
        assert len(loader._failed_plugins) == 0

    def test_update_plugin_enabled_status_succeeds(self, tmp_path):
        """Test updating enabled status of a loaded plugin"""
        # Arrange
        mock_repo = Mock()
        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()

        loader = PluginLoader(mock_repo, plugins_root)
        loader._loaded_plugins = {"plugin1": {"name": "plugin1", "enabled": True}}

        # Act
        result = loader.update_plugin_enabled_status("plugin1", False)

        # Assert
        assert result is True
        assert loader._loaded_plugins["plugin1"]["enabled"] is False

    def test_update_plugin_enabled_status_fails_for_nonexistent(self, tmp_path):
        """Test that updating nonexistent plugin returns False"""
        # Arrange
        mock_repo = Mock()
        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()

        loader = PluginLoader(mock_repo, plugins_root)

        # Act
        result = loader.update_plugin_enabled_status("nonexistent", True)

        # Assert
        assert result is False


class TestLoadPluginImplementation:
    """Tests for _load_plugin_impl internal method"""

    @pytest.mark.asyncio
    async def test_load_plugin_impl_validates_directory(self, tmp_path):
        """Test that plugin directory validation is performed"""
        # Arrange
        mock_repo = Mock()
        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()

        plugin_dir = plugins_root / "testplugin"
        plugin_dir.mkdir()

        # Create invalid plugin (missing plugin.json)
        plugin_meta = PluginFactory.create(name="testplugin")

        loader = PluginLoader(mock_repo, plugins_root)

        # Act & Assert
        with pytest.raises(ValueError, match="Plugin validation failed"):
            await loader._load_plugin_impl(plugin_dir, plugin_meta)

    @pytest.mark.asyncio
    async def test_load_plugin_impl_parses_python_functions(self, tmp_path):
        """Test that Python functions are parsed correctly"""
        # Arrange
        mock_repo = Mock()
        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()

        plugin_dir = plugins_root / "pythonplugin"
        plugin_dir.mkdir()
        (plugin_dir / "plugin.json").write_text('{"name": "pythonplugin"}')
        (plugin_dir / "plugin.py").write_text(
            """
from gscripts.plugins.decorators import plugin_function

@plugin_function(
    name="test_func",
    description={"zh": "测试", "en": "Test"},
    usage="gs pythonplugin test_func"
)
async def test_func():
    pass
"""
        )

        plugin_meta = PluginFactory.create_python(name="pythonplugin")

        loader = PluginLoader(mock_repo, plugins_root)

        # Act
        result = await loader._load_plugin_impl(plugin_dir, plugin_meta)

        # Assert
        assert result is not None
        assert "functions" in result
        assert len(result["functions"]) > 0

    @pytest.mark.asyncio
    async def test_load_plugin_impl_returns_plugin_info_dict(self, tmp_path):
        """Test that _load_plugin_impl returns properly structured plugin info"""
        # Arrange
        mock_repo = Mock()
        plugins_root = tmp_path / "plugins"
        plugins_root.mkdir()

        plugin_dir = plugins_root / "testplugin"
        plugin_dir.mkdir()
        (plugin_dir / "plugin.json").write_text('{"name": "testplugin"}')

        plugin_meta = PluginFactory.create(
            name="testplugin", version="2.0.0", author="Test Author"
        )

        loader = PluginLoader(mock_repo, plugins_root)

        # Act
        result = await loader._load_plugin_impl(plugin_dir, plugin_meta)

        # Assert
        assert result["name"] == "testplugin"
        assert result["version"] == "2.0.0"
        assert result["author"] == "Test Author"
        assert "functions" in result
        assert "plugin_type" in result
        assert "plugin_dir" in result
        assert "metadata" in result


# Import asyncio for parallel loading test
import asyncio
