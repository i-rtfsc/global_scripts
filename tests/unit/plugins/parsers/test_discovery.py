"""
Unit tests for ParserDiscovery
Tests auto-discovery from Entry Points, directories, and config
"""

import pytest
from pathlib import Path
from typing import List

from gscripts.plugins.parsers import (
    FunctionParser,
    FunctionInfo,
    parser_metadata,
)
from gscripts.plugins.parsers.discovery import ParserDiscovery


@parser_metadata(
    name="test_discovery_parser",
    version="1.0.0",
    supported_extensions=[".test"],
    priority=50,
    description="Parser for discovery testing",
)
class TestDiscoveryParser(FunctionParser):
    def can_parse(self, file: Path) -> bool:
        return file.suffix == ".test"

    async def parse(
        self, file: Path, plugin_name: str, subplugin_name: str = ""
    ) -> List[FunctionInfo]:
        return []


class TestParserDiscovery:
    """Test suite for ParserDiscovery"""

    @pytest.fixture
    def discovery(self):
        """Create a ParserDiscovery instance"""
        return ParserDiscovery()

    def test_init(self, discovery):
        """Test ParserDiscovery initialization"""
        assert discovery._cache == {}
        assert discovery._cache_valid is False

    def test_discover_from_entry_points(self, discovery):
        """Test discovering parsers from Entry Points"""
        # This test depends on actual installed parsers
        parsers = discovery.discover_from_entry_points()

        # Should return a list (may be empty if no parsers installed)
        assert isinstance(parsers, list)

        # If parsers found, check structure
        for parser_class, metadata in parsers:
            assert issubclass(parser_class, FunctionParser)
            # Metadata may be None for parsers without decorator

    def test_discover_from_entry_points_caches_results(self, discovery):
        """Test that discovery caches results"""
        # First call
        parsers1 = discovery.discover_from_entry_points()

        # Cache should be valid now
        assert discovery._cache_valid is True

        # Second call should return cached
        parsers2 = discovery.discover_from_entry_points()

        # Should be same results
        assert len(parsers1) == len(parsers2)

    def test_clear_cache(self, discovery):
        """Test cache clearing"""
        discovery.discover_from_entry_points()
        assert discovery._cache_valid is True

        discovery.clear_cache()
        assert discovery._cache_valid is False
        assert len(discovery._cache) == 0

    def test_discover_from_directory_empty(self, discovery, tmp_path):
        """Test discovering from empty directory"""
        parsers = discovery.discover_from_directory(tmp_path)
        assert parsers == []

    def test_discover_from_directory_nonexistent(self, discovery):
        """Test discovering from non-existent directory"""
        parsers = discovery.discover_from_directory(Path("/nonexistent/path"))
        assert parsers == []

    def test_discover_from_directory_with_parsers(self, discovery, tmp_path):
        """Test discovering parsers from directory"""
        # Create a parser file
        parser_file = tmp_path / "custom_parser.py"
        parser_file.write_text(
            """
from pathlib import Path
from typing import List
from gscripts.plugins.parsers import FunctionParser, FunctionInfo, parser_metadata

@parser_metadata(
    name="custom",
    version="1.0.0",
    supported_extensions=[".custom"],
    priority=100,
    description="Custom parser"
)
class CustomParser(FunctionParser):
    def can_parse(self, file: Path) -> bool:
        return file.suffix == ".custom"

    async def parse(self, file: Path, plugin_name: str, subplugin_name: str = "") -> List[FunctionInfo]:
        return []
"""
        )

        parsers = discovery.discover_from_directory(tmp_path)

        # Should find the parser
        assert len(parsers) == 1
        parser_class, metadata = parsers[0]
        assert metadata is not None
        assert metadata.name == "custom"

    def test_discover_from_directory_naming_convention(self, discovery, tmp_path):
        """Test that only *_parser.py files are discovered"""
        # Create files with different names
        (tmp_path / "valid_parser.py").write_text(
            """
from gscripts.plugins.parsers import FunctionParser, FunctionInfo
class ValidParser(FunctionParser):
    def can_parse(self, file): return False
    async def parse(self, file, plugin_name, subplugin_name=""): return []
"""
        )

        (tmp_path / "not_a_parser.py").write_text(
            """
class NotParser:
    pass
"""
        )

        (tmp_path / "another_parser.py").write_text(
            """
from gscripts.plugins.parsers import FunctionParser
class AnotherParser(FunctionParser):
    def can_parse(self, file): return False
    async def parse(self, file, plugin_name, subplugin_name=""): return []
"""
        )

        parsers = discovery.discover_from_directory(tmp_path)

        # Should only find *_parser.py files
        found_names = {p[0].__name__ for p in parsers}
        assert "ValidParser" in found_names
        assert "AnotherParser" in found_names

    def test_discover_from_directory_handles_errors(self, discovery, tmp_path):
        """Test that discovery handles malformed parser files"""
        # Create invalid parser file
        bad_parser = tmp_path / "bad_parser.py"
        bad_parser.write_text(
            """
this is not valid python code!
"""
        )

        # Should not crash
        parsers = discovery.discover_from_directory(tmp_path)
        assert parsers == []

    def test_discover_from_config_enabled_list(self, discovery):
        """Test getting enabled parsers from config"""
        config = {"enabled": ["python", "shell", "yaml"], "disabled": ["experimental"]}

        enabled = discovery.discover_from_config(config)
        assert "python" in enabled
        assert "shell" in enabled
        assert "yaml" in enabled
        assert "experimental" not in enabled

    def test_discover_from_config_removes_disabled(self, discovery):
        """Test that disabled parsers are removed"""
        config = {"enabled": ["python", "shell", "yaml"], "disabled": ["yaml"]}

        enabled = discovery.discover_from_config(config)
        assert "python" in enabled
        assert "shell" in enabled
        assert "yaml" not in enabled

    def test_discover_from_config_empty(self, discovery):
        """Test with empty config"""
        enabled = discovery.discover_from_config({})
        assert enabled == []

    def test_discover_from_config_no_enabled_key(self, discovery):
        """Test with config missing 'enabled' key"""
        config = {"disabled": ["experimental"]}
        enabled = discovery.discover_from_config(config)
        assert enabled == []

    def test_get_custom_paths(self, discovery, tmp_path):
        """Test getting custom parser paths from config"""
        # Create test directories
        path1 = tmp_path / "parsers1"
        path1.mkdir()
        path2 = tmp_path / "parsers2"
        path2.mkdir()

        config = {"custom_paths": [str(path1), str(path2), "/nonexistent/path"]}

        paths = discovery.get_custom_paths(config)

        assert len(paths) == 2
        assert path1 in paths
        assert path2 in paths
        assert Path("/nonexistent/path") not in paths

    def test_get_custom_paths_with_tilde(self, discovery, tmp_path):
        """Test that tilde expansion works"""
        # This tests expanduser functionality
        config = {"custom_paths": ["~/.gscripts/parsers"]}

        paths = discovery.get_custom_paths(config)

        # Should have expanded tilde
        for path in paths:
            assert "~" not in str(path)

    def test_get_custom_paths_empty(self, discovery):
        """Test with no custom_paths in config"""
        paths = discovery.get_custom_paths({})
        assert paths == []

    def test_get_priority_overrides(self, discovery):
        """Test getting priority overrides from config"""
        config = {"priority_overrides": {"yaml": 5, "toml": 10, "custom": 50}}

        overrides = discovery.get_priority_overrides(config)

        assert overrides["yaml"] == 5
        assert overrides["toml"] == 10
        assert overrides["custom"] == 50

    def test_get_priority_overrides_empty(self, discovery):
        """Test with no priority_overrides in config"""
        overrides = discovery.get_priority_overrides({})
        assert overrides == {}

    def test_discover_from_directory_subdirectories(self, discovery, tmp_path):
        """Test that discovery searches subdirectories"""
        # Create nested directory structure
        subdir = tmp_path / "subdir"
        subdir.mkdir()

        parser_file = subdir / "nested_parser.py"
        parser_file.write_text(
            """
from pathlib import Path
from typing import List
from gscripts.plugins.parsers import FunctionParser, FunctionInfo

class NestedParser(FunctionParser):
    def can_parse(self, file: Path) -> bool:
        return False

    async def parse(self, file: Path, plugin_name: str, subplugin_name: str = "") -> List[FunctionInfo]:
        return []
"""
        )

        parsers = discovery.discover_from_directory(tmp_path)

        # Should find parser in subdirectory
        assert len(parsers) == 1
        assert parsers[0][0].__name__ == "NestedParser"

    def test_discover_skips_non_functionparser_classes(self, discovery, tmp_path):
        """Test that discovery only finds FunctionParser subclasses"""
        parser_file = tmp_path / "mixed_parser.py"
        parser_file.write_text(
            """
from pathlib import Path
from typing import List
from gscripts.plugins.parsers import FunctionParser, FunctionInfo

class NotAParser:
    pass

class ValidParser(FunctionParser):
    def can_parse(self, file: Path) -> bool:
        return False

    async def parse(self, file: Path, plugin_name: str, subplugin_name: str = "") -> List[FunctionInfo]:
        return []

class AnotherRegularClass:
    pass
"""
        )

        parsers = discovery.discover_from_directory(tmp_path)

        # Should only find ValidParser
        assert len(parsers) == 1
        assert parsers[0][0].__name__ == "ValidParser"

    def test_integration_full_discovery_flow(self, discovery, tmp_path):
        """Test complete discovery flow with all sources"""
        # Create custom parser directory
        parser_dir = tmp_path / "custom_parsers"
        parser_dir.mkdir()

        # Create custom parser
        (parser_dir / "test_parser.py").write_text(
            """
from pathlib import Path
from typing import List
from gscripts.plugins.parsers import FunctionParser, FunctionInfo, parser_metadata

@parser_metadata(
    name="integration_test",
    version="1.0.0",
    supported_extensions=[".inttest"],
    priority=99,
    description="Integration test parser"
)
class IntegrationTestParser(FunctionParser):
    def can_parse(self, file: Path) -> bool:
        return file.suffix == ".inttest"

    async def parse(self, file: Path, plugin_name: str, subplugin_name: str = "") -> List[FunctionInfo]:
        return []
"""
        )

        config = {
            "enabled": ["python", "shell", "integration_test"],
            "disabled": [],
            "custom_paths": [str(parser_dir)],
            "priority_overrides": {"integration_test": 5},
        }

        # Discover from entry points
        ep_parsers = discovery.discover_from_entry_points()

        # Discover from directory
        custom_parsers = discovery.discover_from_directory(parser_dir)
        assert len(custom_parsers) == 1

        # Get enabled list
        enabled = discovery.discover_from_config(config)
        assert "integration_test" in enabled

        # Get custom paths
        paths = discovery.get_custom_paths(config)
        assert parser_dir in paths

        # Get priority overrides
        overrides = discovery.get_priority_overrides(config)
        assert overrides["integration_test"] == 5
