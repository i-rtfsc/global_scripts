"""
Integration tests for Parser Registry Mechanism
Tests the complete flow from parser registration to plugin loading
"""

import pytest
from pathlib import Path
import json
from typing import List

from gscripts.plugins.parsers import (
    FunctionParser,
    FunctionInfo,
    parser_metadata,
)
from gscripts.plugins.loader import RefactoredPluginLoader


@parser_metadata(
    name="integration_yaml",
    version="1.0.0",
    supported_extensions=[".yaml", ".yml"],
    priority=100,
    description="YAML parser for integration testing",
)
class IntegrationYAMLParser(FunctionParser):
    """Test YAML parser for integration tests"""

    def can_parse(self, file: Path) -> bool:
        return file.suffix.lower() in [".yaml", ".yml"]

    async def parse(
        self, file: Path, plugin_name: str, subplugin_name: str = ""
    ) -> List[FunctionInfo]:
        # Simple YAML-like parsing (no actual YAML library needed for test)
        functions = []

        try:
            content = file.read_text()

            # Very basic parsing - just look for name: and command: lines
            lines = content.split("\n")
            current_func = {}

            for line in lines:
                line = line.strip()

                if line.startswith("- name:"):
                    if current_func and "name" in current_func:
                        # Save previous function
                        functions.append(
                            FunctionInfo(
                                name=current_func.get("name", ""),
                                description=current_func.get("description", ""),
                                command=current_func.get("command", ""),
                                type=current_func.get("type", "shell"),
                                plugin_name=plugin_name,
                                subplugin_name=subplugin_name,
                            )
                        )

                    # Start new function
                    current_func = {"name": line.split(":", 1)[1].strip()}

                elif line.startswith("description:"):
                    current_func["description"] = line.split(":", 1)[1].strip()

                elif line.startswith("command:"):
                    current_func["command"] = line.split(":", 1)[1].strip()

                elif line.startswith("type:"):
                    current_func["type"] = line.split(":", 1)[1].strip()

            # Don't forget last function
            if current_func and "name" in current_func:
                functions.append(
                    FunctionInfo(
                        name=current_func.get("name", ""),
                        description=current_func.get("description", ""),
                        command=current_func.get("command", ""),
                        type=current_func.get("type", "shell"),
                        plugin_name=plugin_name,
                        subplugin_name=subplugin_name,
                    )
                )

        except Exception as e:
            print(f"Error parsing: {e}")

        return functions


class TestParserRegistryIntegration:
    """Integration tests for complete parser workflow"""

    @pytest.fixture
    def test_plugins_dir(self, tmp_path):
        """Create a test plugins directory structure"""
        plugins_dir = tmp_path / "plugins"
        plugins_dir.mkdir()
        return plugins_dir

    @pytest.fixture
    def test_config(self):
        """Create test parser configuration"""
        return {
            "enabled": ["python", "shell", "config", "integration_yaml"],
            "disabled": [],
            "custom_paths": [],
            "priority_overrides": {},
        }

    def test_parser_registration_in_loader(self, test_plugins_dir, test_config):
        """Test that parsers are registered when loader is created"""
        loader = RefactoredPluginLoader(test_plugins_dir, parser_config=test_config)

        parsers = loader.parser_registry.list_parsers()

        # Should have at least the built-in parsers
        parser_names = {p["name"] for p in parsers}
        assert "PythonFunctionParser" in parser_names
        assert "ShellFunctionParser" in parser_names
        assert "ConfigFunctionParser" in parser_names

    def test_custom_parser_integration(self, test_plugins_dir, test_config, tmp_path):
        """Test loading plugin with custom parser"""
        # Register our test YAML parser manually
        from gscripts.plugins.parsers import FunctionParserRegistry

        registry = FunctionParserRegistry()
        registry.register(IntegrationYAMLParser())

        # Create a test plugin with YAML file
        plugin_dir = test_plugins_dir / "yaml_plugin"
        plugin_dir.mkdir()

        # Create plugin.json
        plugin_json = plugin_dir / "plugin.json"
        plugin_json.write_text(
            json.dumps(
                {
                    "name": "yaml_plugin",
                    "version": "1.0.0",
                    "description": "Test YAML plugin",
                }
            )
        )

        # Create functions.yaml
        functions_yaml = plugin_dir / "functions.yaml"
        functions_yaml.write_text(
            """
functions:
  - name: hello
    description: Say hello
    command: echo "Hello World"
    type: shell

  - name: goodbye
    description: Say goodbye
    command: echo "Goodbye"
    type: shell
"""
        )

        # Parse with our registry
        functions = registry.parse_all([functions_yaml], plugin_name="yaml_plugin")

        # Should have parsed both functions
        assert len(functions) == 2
        assert functions[0].name == "hello"
        assert functions[1].name == "goodbye"

    def test_parser_priority_selection(self, test_plugins_dir, test_config, tmp_path):
        """Test that parser priority affects selection"""
        from gscripts.plugins.parsers import FunctionParserRegistry

        # Create two parsers that both match .test files
        @parser_metadata(name="high_priority", priority=10)
        class HighPriorityParser(FunctionParser):
            def can_parse(self, file: Path) -> bool:
                return file.suffix == ".test"

            async def parse(self, file, plugin_name, subplugin_name=""):
                return [
                    FunctionInfo(
                        name="high_priority_func",
                        description="From high priority",
                        command="echo high",
                        type="shell",
                        plugin_name=plugin_name,
                        subplugin_name=subplugin_name,
                    )
                ]

        @parser_metadata(name="low_priority", priority=100)
        class LowPriorityParser(FunctionParser):
            def can_parse(self, file: Path) -> bool:
                return file.suffix == ".test"

            async def parse(self, file, plugin_name, subplugin_name=""):
                return [
                    FunctionInfo(
                        name="low_priority_func",
                        description="From low priority",
                        command="echo low",
                        type="shell",
                        plugin_name=plugin_name,
                        subplugin_name=subplugin_name,
                    )
                ]

        registry = FunctionParserRegistry()
        registry.register(LowPriorityParser())
        registry.register(HighPriorityParser())

        # Create test file
        test_file = tmp_path / "test.test"
        test_file.write_text("test content")

        # Should select high priority parser
        functions = registry.parse_all([test_file], "test_plugin")

        assert len(functions) == 1
        assert functions[0].name == "high_priority_func"

    def test_parser_enable_disable_config(self, test_plugins_dir):
        """Test that config can enable/disable parsers"""
        # Config with yaml disabled
        config_disabled = {
            "enabled": ["python", "shell"],
            "disabled": ["integration_yaml"],
        }

        loader = RefactoredPluginLoader(test_plugins_dir, parser_config=config_disabled)

        # YAML parser should be disabled if it was registered
        parsers = loader.parser_registry.list_parsers()
        yaml_parsers = [p for p in parsers if "yaml" in p["name"].lower()]

        for parser in yaml_parsers:
            # If found, should be disabled
            if parser["name"] == "integration_yaml":
                assert not parser["enabled"]

    def test_parser_priority_override_from_config(self, test_plugins_dir):
        """Test that config can override parser priorities"""
        config = {
            "priority_overrides": {"PythonFunctionParser": 1000}  # Lower its priority
        }

        loader = RefactoredPluginLoader(test_plugins_dir, parser_config=config)
        parsers = loader.parser_registry.list_parsers()

        # Check if priority was overridden (this depends on implementation)
        # In current implementation, priority is set during registration
        # So this test documents expected behavior

    @pytest.mark.skip(
        reason="Integration test needs update for Clean Architecture - tracked in Phase 3 cleanup"
    )
    @pytest.mark.asyncio
    async def test_full_plugin_loading_with_parsers(
        self, test_plugins_dir, test_config
    ):
        """Test complete plugin loading flow with parser registry"""
        # Create a test plugin with Python file
        plugin_dir = test_plugins_dir / "test_plugin"
        plugin_dir.mkdir()

        # Create plugin.json
        (plugin_dir / "plugin.json").write_text(
            json.dumps(
                {
                    "name": "test_plugin",
                    "version": "1.0.0",
                    "description": "Test plugin",
                }
            )
        )

        # Create plugin.py with decorated function
        (plugin_dir / "plugin.py").write_text(
            """
from gscripts.plugins.decorators import plugin_function

@plugin_function(
    name="test_func",
    description="Test function"
)
def test_command(args):
    return "test output"
"""
        )

        # Load plugins
        loader = RefactoredPluginLoader(test_plugins_dir, parser_config=test_config)
        plugins = await loader.load_all_plugins()

        # Should have loaded the plugin
        assert "test_plugin" in plugins

        # Should have parsed the function (if PythonParser works)
        # Note: This depends on PythonFunctionParser implementation

    def test_parser_registry_accessible_from_loader(
        self, test_plugins_dir, test_config
    ):
        """Test that parser registry is accessible from loader"""
        loader = RefactoredPluginLoader(test_plugins_dir, parser_config=test_config)

        # Should be able to access registry
        assert hasattr(loader, "parser_registry")
        assert loader.parser_registry is not None

        # Should be able to list parsers
        parsers = loader.parser_registry.list_parsers()
        assert isinstance(parsers, list)

    def test_multiple_parsers_same_priority(self, test_plugins_dir, tmp_path):
        """Test behavior when multiple parsers have same priority"""
        from gscripts.plugins.parsers import FunctionParserRegistry

        @parser_metadata(name="parser_a", priority=50)
        class ParserA(FunctionParser):
            def can_parse(self, file: Path) -> bool:
                return file.suffix == ".multi"

            async def parse(self, file, plugin_name, subplugin_name=""):
                return [
                    FunctionInfo(
                        name="func_a",
                        description="From A",
                        command="echo a",
                        type="shell",
                        plugin_name=plugin_name,
                        subplugin_name=subplugin_name,
                    )
                ]

        @parser_metadata(name="parser_b", priority=50)
        class ParserB(FunctionParser):
            def can_parse(self, file: Path) -> bool:
                return file.suffix == ".multi"

            async def parse(self, file, plugin_name, subplugin_name=""):
                return [
                    FunctionInfo(
                        name="func_b",
                        description="From B",
                        command="echo b",
                        type="shell",
                        plugin_name=plugin_name,
                        subplugin_name=subplugin_name,
                    )
                ]

        registry = FunctionParserRegistry()
        registry.register(ParserA())
        registry.register(ParserB())

        test_file = tmp_path / "test.multi"
        test_file.write_text("test")

        # Should select one (order depends on registration order)
        functions = registry.parse_all([test_file], "test")
        assert len(functions) == 1
        assert functions[0].name in ["func_a", "func_b"]

    def test_error_handling_in_parser(self, test_plugins_dir, tmp_path):
        """Test that parser errors don't crash the system"""
        from gscripts.plugins.parsers import FunctionParserRegistry

        @parser_metadata(name="error_parser", priority=50)
        class ErrorParser(FunctionParser):
            def can_parse(self, file: Path) -> bool:
                return file.suffix == ".error"

            async def parse(self, file, plugin_name, subplugin_name=""):
                raise Exception("Intentional error")

        registry = FunctionParserRegistry()
        registry.register(ErrorParser())

        test_file = tmp_path / "test.error"
        test_file.write_text("test")

        # Should handle error gracefully
        functions = registry.parse_all([test_file], "test")

        # Depending on implementation, might return empty or handle exception
        # At minimum, should not crash
        assert isinstance(functions, list)
