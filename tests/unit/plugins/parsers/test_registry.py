"""
Unit tests for FunctionParserRegistry
Tests parser registration, priority, enable/disable, and introspection
"""

import pytest
from pathlib import Path
from typing import List

from gscripts.plugins.parsers import (
    FunctionParser,
    FunctionParserRegistry,
    FunctionInfo,
    parser_metadata,
)


# Mock parsers for testing
@parser_metadata(
    name="test_parser_1",
    version="1.0.0",
    supported_extensions=[".test1"],
    priority=10,
    description="Test parser 1",
)
class TestParser1(FunctionParser):
    def can_parse(self, file: Path) -> bool:
        return file.suffix == ".test1"

    async def parse(
        self, file: Path, plugin_name: str, subplugin_name: str = ""
    ) -> List[FunctionInfo]:
        return [
            FunctionInfo(
                name="test_func",
                description="Test function",
                command="echo test",
                type="shell",
                plugin_name=plugin_name,
                subplugin_name=subplugin_name,
            )
        ]


@parser_metadata(
    name="test_parser_2",
    version="2.0.0",
    supported_extensions=[".test2"],
    priority=20,
    description="Test parser 2",
)
class TestParser2(FunctionParser):
    def can_parse(self, file: Path) -> bool:
        return file.suffix == ".test2"

    async def parse(
        self, file: Path, plugin_name: str, subplugin_name: str = ""
    ) -> List[FunctionInfo]:
        return []


class TestParser3(FunctionParser):
    """Parser without metadata decorator"""

    def can_parse(self, file: Path) -> bool:
        return file.suffix == ".test3"

    async def parse(
        self, file: Path, plugin_name: str, subplugin_name: str = ""
    ) -> List[FunctionInfo]:
        return []


class TestFunctionParserRegistry:
    """Test suite for FunctionParserRegistry"""

    @pytest.fixture
    def registry(self):
        """Create a fresh registry for each test"""
        return FunctionParserRegistry()

    @pytest.fixture
    def parser1(self):
        return TestParser1()

    @pytest.fixture
    def parser2(self):
        return TestParser2()

    @pytest.fixture
    def parser3(self):
        return TestParser3()

    def test_register_parser_with_metadata(self, registry, parser1):
        """Test registering a parser with metadata"""
        registry.register(parser1)

        parsers = registry.list_parsers()
        assert len(parsers) == 1
        assert parsers[0]["name"] == "test_parser_1"
        assert parsers[0]["priority"] == 10
        assert parsers[0]["enabled"] is True

    def test_register_parser_without_metadata(self, registry, parser3):
        """Test registering a parser without metadata"""
        registry.register(parser3)

        parsers = registry.list_parsers()
        assert len(parsers) == 1
        assert parsers[0]["name"] == "TestParser3"
        assert parsers[0]["priority"] == 100  # Default priority

    def test_register_with_custom_name(self, registry, parser1):
        """Test registering with custom name"""
        registry.register(parser1, name="custom_name")

        info = registry.get_parser_info("custom_name")
        assert info is not None
        assert info["name"] == "custom_name"

    def test_register_with_custom_priority(self, registry, parser1):
        """Test registering with custom priority"""
        registry.register(parser1, priority=5)

        info = registry.get_parser_info("test_parser_1")
        assert info["priority"] == 5

    def test_register_by_name(self, registry):
        """Test register_by_name method"""
        registry.register_by_name("my_parser", TestParser1)

        info = registry.get_parser_info("my_parser")
        assert info is not None
        assert info["name"] == "my_parser"

    def test_unregister_parser(self, registry, parser1):
        """Test unregistering a parser"""
        registry.register(parser1)
        assert len(registry.list_parsers()) == 1

        registry.unregister("test_parser_1")
        assert len(registry.list_parsers()) == 0

    def test_enable_disable_parser(self, registry, parser1):
        """Test enabling and disabling parsers"""
        registry.register(parser1)

        # Initially enabled
        info = registry.get_parser_info("test_parser_1")
        assert info["enabled"] is True

        # Disable
        registry.disable("test_parser_1")
        info = registry.get_parser_info("test_parser_1")
        assert info["enabled"] is False

        # Enable
        registry.enable("test_parser_1")
        info = registry.get_parser_info("test_parser_1")
        assert info["enabled"] is True

    def test_register_alias(self, registry, parser1):
        """Test parser aliases"""
        registry.register(parser1)
        registry.register_alias("alias1", "test_parser_1")

        # Should be able to get by alias
        info = registry.get_parser_info("alias1")
        assert info is not None
        assert info["name"] == "test_parser_1"

    def test_get_parser_by_name(self, registry, parser1):
        """Test get method"""
        registry.register(parser1)

        parser = registry.get("test_parser_1")
        assert parser is not None
        assert isinstance(parser, TestParser1)

    def test_get_disabled_parser_returns_none(self, registry, parser1):
        """Test that disabled parsers return None"""
        registry.register(parser1)
        registry.disable("test_parser_1")

        parser = registry.get("test_parser_1")
        assert parser is None

    def test_list_parsers_sorted_by_priority(self, registry, parser1, parser2):
        """Test that list_parsers returns sorted by priority"""
        registry.register(parser2)  # Priority 20
        registry.register(parser1)  # Priority 10

        parsers = registry.list_parsers()
        assert len(parsers) == 2
        assert parsers[0]["name"] == "test_parser_1"  # Priority 10 first
        assert parsers[1]["name"] == "test_parser_2"  # Priority 20 second

    def test_get_parser_info_detailed(self, registry, parser1):
        """Test get_parser_info returns all details"""
        registry.register(parser1)

        info = registry.get_parser_info("test_parser_1")
        assert info["name"] == "test_parser_1"
        assert info["priority"] == 10
        assert info["enabled"] is True
        assert info["class"] == "TestParser1"
        assert info["version"] == "1.0.0"
        assert ".test1" in info["supported_extensions"]
        assert info["description"] == "Test parser 1"

    def test_get_parser_by_file(self, registry, parser1, parser2, tmp_path):
        """Test get_parser method with file matching"""
        registry.register(parser1)
        registry.register(parser2)

        # Create test files
        file1 = tmp_path / "test.test1"
        file1.touch()

        file2 = tmp_path / "test.test2"
        file2.touch()

        # Should match correct parser
        parser = registry.get_parser(file1)
        assert isinstance(parser, TestParser1)

        parser = registry.get_parser(file2)
        assert isinstance(parser, TestParser2)

    def test_get_parser_no_match_raises_error(self, registry, tmp_path):
        """Test get_parser raises ValueError when no match"""
        file = tmp_path / "test.unknown"
        file.touch()

        with pytest.raises(ValueError, match="No parser found"):
            registry.get_parser(file)

    def test_get_parser_respects_priority(self, registry, tmp_path):
        """Test that higher priority parser is selected first"""

        # Both parsers match .test1
        @parser_metadata(
            name="high_priority", priority=5, supported_extensions=[".test1"]
        )
        class HighPriorityParser(FunctionParser):
            def can_parse(self, file: Path) -> bool:
                return file.suffix == ".test1"

            async def parse(self, file, plugin_name, subplugin_name=""):
                return []

        @parser_metadata(
            name="low_priority", priority=100, supported_extensions=[".test1"]
        )
        class LowPriorityParser(FunctionParser):
            def can_parse(self, file: Path) -> bool:
                return file.suffix == ".test1"

            async def parse(self, file, plugin_name, subplugin_name=""):
                return []

        registry.register(LowPriorityParser())
        registry.register(HighPriorityParser())

        file = tmp_path / "test.test1"
        file.touch()

        parser = registry.get_parser(file)
        assert isinstance(parser, HighPriorityParser)

    def test_get_parser_skips_disabled(self, registry, parser1, parser2, tmp_path):
        """Test that disabled parsers are skipped"""
        registry.register(parser1)  # Priority 10
        registry.register(parser2)  # Priority 20
        registry.disable("test_parser_1")

        # Both can parse .test1, but parser1 is disabled
        @parser_metadata(name="fallback", priority=20)
        class FallbackParser(FunctionParser):
            def can_parse(self, file: Path) -> bool:
                return file.suffix == ".test1"

            async def parse(self, file, plugin_name, subplugin_name=""):
                return []

        registry.register(FallbackParser())

        file = tmp_path / "test.test1"
        file.touch()

        parser = registry.get_parser(file)
        assert isinstance(parser, FallbackParser)

    @pytest.mark.asyncio
    async def test_parse_all_integration(self, registry, parser1, tmp_path):
        """Test parse_all method integration"""
        registry.register(parser1)

        # Create test files
        file1 = tmp_path / "test1.test1"
        file1.touch()
        file2 = tmp_path / "test2.test1"
        file2.touch()

        functions = registry.parse_all([file1, file2], plugin_name="test_plugin")

        assert len(functions) == 2
        assert all(f.name == "test_func" for f in functions)

    def test_unregister_removes_aliases(self, registry, parser1):
        """Test that unregistering removes related aliases"""
        registry.register(parser1)
        registry.register_alias("alias1", "test_parser_1")
        registry.register_alias("alias2", "test_parser_1")

        registry.unregister("test_parser_1")

        # Aliases should be gone
        assert registry.get_parser_info("alias1") is None
        assert registry.get_parser_info("alias2") is None

    def test_metadata_property(self, parser1):
        """Test parser metadata property"""
        metadata = parser1.metadata

        assert metadata is not None
        assert metadata.name == "test_parser_1"
        assert metadata.version == "1.0.0"
        assert metadata.priority == 10

    def test_parser_without_metadata_has_none(self, parser3):
        """Test parser without decorator has None metadata"""
        assert parser3.metadata is None
