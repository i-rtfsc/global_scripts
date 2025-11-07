"""
Tests for PluginMetadata model
"""

from gscripts.models.plugin import PluginMetadata, PluginType
from tests.factories import PluginFactory


class TestPluginMetadata:
    """Tests for PluginMetadata dataclass"""

    def test_create_plugin_metadata_with_required_fields(self):
        """Test creating plugin metadata with required fields"""
        # Arrange & Act
        metadata = PluginMetadata(
            name="testplugin",
            version="1.0.0",
            author="Test Author",
            description={"zh": "测试", "en": "Test"},
            type=PluginType.PYTHON,
            enabled=True,
        )

        # Assert
        assert metadata.name == "testplugin"
        assert metadata.version == "1.0.0"
        assert metadata.author == "Test Author"
        assert metadata.type == PluginType.PYTHON
        assert metadata.enabled is True

    def test_create_plugin_metadata_using_factory(self):
        """Test creating plugin metadata using factory"""
        # Act
        metadata = PluginFactory.create(name="factory_plugin")

        # Assert
        assert metadata.name == "factory_plugin"
        assert isinstance(metadata, PluginMetadata)

    def test_plugin_type_enum_values(self):
        """Test that PluginType enum has expected values"""
        # Assert
        assert PluginType.PYTHON.value == "python"
        assert PluginType.SHELL.value == "shell"
        assert PluginType.CONFIG.value == "config"
        assert PluginType.HYBRID.value == "hybrid"
        assert PluginType.UNKNOWN.value == "unknown"

    def test_create_batch_plugins(self):
        """Test creating multiple plugins using factory"""
        # Act
        plugins = PluginFactory.create_batch(count=5)

        # Assert
        assert len(plugins) == 5
        assert all(isinstance(p, PluginMetadata) for p in plugins)
        # Each plugin should have unique name
        names = [p.name for p in plugins]
        assert len(names) == len(set(names)), "Plugin names should be unique"

    def test_create_python_plugin(self):
        """Test creating Python plugin with factory"""
        # Act
        plugin = PluginFactory.create_python(name="python_test")

        # Assert
        assert plugin.type == PluginType.PYTHON
        assert plugin.name == "python_test"

    def test_create_shell_plugin(self):
        """Test creating Shell plugin with factory"""
        # Act
        plugin = PluginFactory.create_shell(name="shell_test")

        # Assert
        assert plugin.type == PluginType.SHELL
        assert plugin.name == "shell_test"

    def test_create_disabled_plugin(self):
        """Test creating disabled plugin"""
        # Act
        plugin = PluginFactory.create_disabled(name="disabled_test")

        # Assert
        assert plugin.enabled is False
        assert plugin.name == "disabled_test"

    def test_factory_with_custom_attributes(self):
        """Test factory with custom attribute overrides"""
        # Act
        plugin = PluginFactory.create(
            name="custom",
            version="2.0.0",
            author="Custom Author",
            enabled=False,
        )

        # Assert
        assert plugin.name == "custom"
        assert plugin.version == "2.0.0"
        assert plugin.author == "Custom Author"
        assert plugin.enabled is False

    def test_factory_reset_counter(self):
        """Test that factory counter can be reset"""
        # Arrange
        PluginFactory.reset_counter()

        # Act
        plugin1 = PluginFactory.create()
        plugin2 = PluginFactory.create()

        # Assert
        # Names should be sequential after reset
        assert "test_plugin_1" in plugin1.name
        assert "test_plugin_2" in plugin2.name

    def test_get_description_with_dict(self):
        """Test get_description with dict description"""
        # Arrange
        metadata = PluginFactory.create(
            description={"zh": "中文描述", "en": "English description"}
        )

        # Act & Assert
        assert metadata.get_description("zh") == "中文描述"
        assert metadata.get_description("en") == "English description"
        # Falls back to zh if language not found
        assert metadata.get_description("fr") == "中文描述"

    def test_get_description_with_string(self):
        """Test get_description with string description"""
        # Arrange
        metadata = PluginFactory.create(description="Simple description")

        # Act & Assert
        assert metadata.get_description("zh") == "Simple description"
        assert metadata.get_description("en") == "Simple description"

    def test_plugin_with_subplugins(self):
        """Test creating plugin with subplugins list"""
        # Arrange & Act
        metadata = PluginFactory.create(
            name="hybrid_test", subplugins=["sub1", "sub2", "sub3"]
        )

        # Assert
        assert len(metadata.subplugins) == 3
        assert "sub1" in metadata.subplugins
        assert metadata.type == PluginType.PYTHON  # Default type

    def test_plugin_with_tags_and_keywords(self):
        """Test creating plugin with tags and keywords"""
        # Arrange & Act
        metadata = PluginFactory.create(
            tags=["development", "android"], keywords=["adb", "fastboot", "logcat"]
        )

        # Assert
        assert len(metadata.tags) == 2
        assert "development" in metadata.tags
        assert len(metadata.keywords) == 3
        assert "adb" in metadata.keywords

    def test_plugin_priority_default(self):
        """Test plugin has default priority"""
        # Arrange & Act
        metadata = PluginFactory.create()

        # Assert
        assert metadata.priority == 50  # Default priority

    def test_plugin_with_custom_priority(self):
        """Test creating plugin with custom priority"""
        # Arrange & Act
        metadata = PluginFactory.create(priority=100)

        # Assert
        assert metadata.priority == 100
