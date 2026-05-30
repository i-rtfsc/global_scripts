"""
Tests for PluginMetadata model
"""

from typing import Any

from gscripts.models.plugin import PluginMetadata, PluginType, SubPlugin
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
        """Test creating plugin with subplugins list (unified to SubPlugin)"""
        # Arrange & Act
        metadata = PluginFactory.create(
            name="hybrid_test", subplugins=["sub1", "sub2", "sub3"]
        )

        # Assert
        assert len(metadata.subplugins) == 3
        # Even via the factory's setattr path, entries are unified to SubPlugin...
        assert all(isinstance(sp, SubPlugin) for sp in metadata.subplugins)
        assert [sp.name for sp in metadata.subplugins] == ["sub1", "sub2", "sub3"]
        # ...while staying backward-compatible with string membership.
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


class TestSubPlugin:
    """Tests for the unified SubPlugin model."""

    def test_from_raw_string(self):
        """A bare string becomes a SubPlugin named after it."""
        sp = SubPlugin.from_raw("mysub")
        assert isinstance(sp, SubPlugin)
        assert sp.name == "mysub"
        assert sp.type == PluginType.UNKNOWN
        assert sp.entry == ""

    def test_from_raw_dict(self):
        """A plugin.json dict is parsed into typed fields."""
        sp = SubPlugin.from_raw(
            {
                "name": "python_sub",
                "type": "python",
                "entry": "python_sub.py",
                "description": {"zh": "子", "en": "sub"},
            }
        )
        assert sp.name == "python_sub"
        assert sp.type == PluginType.PYTHON
        assert sp.entry == "python_sub.py"
        assert sp.get_description("en") == "sub"

    def test_from_raw_type_aliases(self):
        """plugin.json type aliases map to canonical PluginType."""
        assert (
            SubPlugin.from_raw({"name": "c", "type": "json"}).type == PluginType.CONFIG
        )
        assert SubPlugin.from_raw({"name": "s", "type": "sh"}).type == PluginType.SHELL
        assert (
            SubPlugin.from_raw({"name": "u", "type": "bogus"}).type
            == PluginType.UNKNOWN
        )

    def test_from_raw_is_idempotent(self):
        """from_raw on an existing SubPlugin returns it unchanged."""
        sp = SubPlugin(name="x", type=PluginType.SHELL)
        assert SubPlugin.from_raw(sp) is sp

    def test_to_index_dict_shape(self):
        """to_index_dict matches the router.json / completion contract."""
        sp = SubPlugin.from_raw({"name": "n", "description": {"zh": "中", "en": "en"}})
        assert sp.to_index_dict() == {
            "name": "n",
            "description": {"zh": "中", "en": "en"},
        }
        # String description is normalized to a zh/en dict.
        assert SubPlugin.from_raw("bare").to_index_dict() == {
            "name": "bare",
            "description": {"zh": "", "en": ""},
        }

    def test_to_dict_round_trips_plugin_json(self):
        """A rich plugin.json entry survives from_raw -> to_dict unchanged."""
        raw = {
            "name": "shell_sub",
            "type": "shell",
            "entry": "shell_sub.sh",
            "description": {"zh": "壳", "en": "shell"},
        }
        assert SubPlugin.from_raw(raw).to_dict() == raw

    def test_to_dict_omits_defaults(self):
        """A string-form subplugin serializes to a minimal dict."""
        assert SubPlugin.from_raw("sub1").to_dict() == {"name": "sub1"}

    def test_equality_with_string_and_subplugin(self):
        """Name-based equality preserves the legacy membership idiom."""
        assert SubPlugin(name="a") == "a"
        assert SubPlugin(name="a") == SubPlugin(name="a", type=PluginType.PYTHON)
        assert SubPlugin(name="a") != "b"
        assert (
            SubPlugin(name="a") != 123
        )  # non-str/SubPlugin -> NotImplemented -> False


class TestPluginMetadataSubpluginCoercion:
    """The List[SubPlugin] invariant must hold on every assignment path."""

    def test_constructor_coerces_mixed_raw_entries(self):
        """Strings and dicts passed to the constructor become SubPlugin objects."""
        # Deliberately loose input (Any) — the model normalizes it at runtime.
        raw: Any = [
            "str_sub",
            {"name": "dict_sub", "type": "python", "entry": "d.py"},
        ]
        meta = PluginMetadata(name="hybrid", subplugins=raw)
        assert all(isinstance(sp, SubPlugin) for sp in meta.subplugins)
        assert [sp.name for sp in meta.subplugins] == ["str_sub", "dict_sub"]
        assert meta.subplugins[1].type == PluginType.PYTHON

    def test_reassignment_after_construction_is_coerced(self):
        """Later `meta.subplugins = [...]` (e.g. factory setattr) is coerced too."""
        meta = PluginMetadata(name="hybrid")
        assert meta.subplugins == []
        late: Any = ["late_sub"]
        meta.subplugins = late
        assert isinstance(meta.subplugins[0], SubPlugin)
        assert meta.subplugins[0].name == "late_sub"

    def test_none_subplugins_normalizes_to_empty_list(self):
        """A None value does not break coercion."""
        none_value: Any = None
        meta = PluginMetadata(name="hybrid", subplugins=none_value)
        assert meta.subplugins == []
