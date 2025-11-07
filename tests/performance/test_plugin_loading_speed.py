"""
Performance benchmark tests for plugin loading

Tests plugin loading performance with various plugin counts and types
to ensure the system meets performance requirements.
"""

import pytest
import json
import time
from pathlib import Path

from gscripts.infrastructure.filesystem.file_operations import RealFileSystem
from gscripts.infrastructure.persistence.plugin_repository import PluginRepository
from gscripts.infrastructure.persistence.plugin_loader import PluginLoader
from gscripts.core.config_manager import ConfigManager


@pytest.fixture
def perf_environment(tmp_path):
    """Setup environment for performance testing"""
    test_root = tmp_path / "perf_test"
    test_root.mkdir()

    plugins_dir = test_root / "plugins"
    plugins_dir.mkdir()

    filesystem = RealFileSystem()
    config_manager = ConfigManager()

    repository = PluginRepository(
        filesystem=filesystem,
        plugins_dir=plugins_dir,
        router_cache_path=None,
        config_manager=config_manager,
    )

    loader = PluginLoader(plugin_repository=repository, plugins_root=plugins_dir)

    return {"plugins_dir": plugins_dir, "loader": loader, "repository": repository}


def create_python_plugin(plugins_dir: Path, name: str, function_count: int = 5):
    """Helper to create a Python plugin with specified number of functions"""
    plugin_dir = plugins_dir / name
    plugin_dir.mkdir()

    plugin_json = {
        "name": name,
        "version": "1.0.0",
        "type": "python",
        "entry": "plugin.py",
        "enabled": True,
        "description": {"zh": f"{name}", "en": f"{name}"},
    }
    (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json, indent=2))

    # Generate plugin with multiple functions
    functions_code = []
    for i in range(function_count):
        func_code = f"""
    @plugin_function(
        name="func{i}",
        description={{"zh": "功能{i}", "en": "Function {i}"}},
        usage="gs {name} func{i}",
    )
    async def func{i}(self, args=None):
        return CommandResult(success=True, output="func{i}", exit_code=0)
"""
        functions_code.append(func_code)

    plugin_py = f'''"""Performance test plugin {name}"""
from gscripts.plugins.base import BasePlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.models import CommandResult

class {name.capitalize()}Plugin(BasePlugin):
    def __init__(self):
        self.name = "{name}"

{''.join(functions_code)}
'''
    (plugin_dir / "plugin.py").write_text(plugin_py)


def create_shell_plugin(plugins_dir: Path, name: str, function_count: int = 5):
    """Helper to create a Shell plugin with specified number of functions"""
    plugin_dir = plugins_dir / name
    plugin_dir.mkdir()

    plugin_json = {
        "name": name,
        "version": "1.0.0",
        "type": "shell",
        "entry": "plugin.sh",
        "enabled": True,
        "description": {"zh": f"{name}", "en": f"{name}"},
    }
    (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json, indent=2))

    # Generate shell functions
    functions_code = []
    for i in range(function_count):
        func_code = f"""
# @plugin_function
# @name func{i}
# @description {{"zh": "功能{i}", "en": "Function {i}"}}
function func{i}() {{
    echo "func{i}"
}}
"""
        functions_code.append(func_code)

    plugin_sh = f"""#!/bin/bash
{''.join(functions_code)}
"""
    (plugin_dir / "plugin.sh").write_text(plugin_sh)
    (plugin_dir / "plugin.sh").chmod(0o755)


def create_config_plugin(plugins_dir: Path, name: str, function_count: int = 5):
    """Helper to create a Config plugin with specified number of commands"""
    plugin_dir = plugins_dir / name
    plugin_dir.mkdir()

    plugin_json = {
        "name": name,
        "version": "1.0.0",
        "type": "config",
        "entry": "commands.json",
        "enabled": True,
        "description": {"zh": f"{name}", "en": f"{name}"},
    }
    (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json, indent=2))

    commands = {}
    for i in range(function_count):
        commands[f"func{i}"] = {
            "description": {"zh": f"功能{i}", "en": f"Function {i}"},
            "command": f"echo 'func{i}'",
            "usage": f"gs {name} func{i}",
        }

    commands_json = {"commands": commands}
    (plugin_dir / "commands.json").write_text(json.dumps(commands_json, indent=2))


@pytest.mark.performance
@pytest.mark.slow
class TestPluginLoadingPerformance:
    """Performance tests for plugin loading speed"""

    @pytest.mark.asyncio
    async def test_load_10_python_plugins(self, perf_environment):
        """Test loading 10 Python plugins with 5 functions each"""
        plugins_dir = perf_environment["plugins_dir"]
        loader = perf_environment["loader"]

        # Create 10 Python plugins
        for i in range(10):
            create_python_plugin(plugins_dir, f"pyplugin{i}", function_count=5)

        # Measure load time
        start_time = time.time()
        plugins = await loader.load_all_plugins()
        end_time = time.time()

        load_time = end_time - start_time

        # Assert: All plugins loaded
        assert len(plugins) == 10

        # Performance requirement: < 1 second for 10 plugins
        assert load_time < 1.0, f"Loading took {load_time:.3f}s (expected < 1.0s)"

        print(f"\n✓ Loaded 10 Python plugins in {load_time:.3f}s")

    @pytest.mark.asyncio
    async def test_load_50_mixed_plugins(self, perf_environment):
        """Test loading 50 mixed-type plugins"""
        plugins_dir = perf_environment["plugins_dir"]
        loader = perf_environment["loader"]

        # Create 50 plugins: 20 Python, 20 Shell, 10 Config
        for i in range(20):
            create_python_plugin(plugins_dir, f"py{i}", function_count=3)

        for i in range(20):
            create_shell_plugin(plugins_dir, f"sh{i}", function_count=3)

        for i in range(10):
            create_config_plugin(plugins_dir, f"cfg{i}", function_count=3)

        # Measure load time
        start_time = time.time()
        plugins = await loader.load_all_plugins()
        end_time = time.time()

        load_time = end_time - start_time

        # Assert: All plugins loaded
        assert len(plugins) == 50

        # Performance requirement: < 3 seconds for 50 plugins
        assert load_time < 3.0, f"Loading took {load_time:.3f}s (expected < 3.0s)"

        print(
            f"\n✓ Loaded 50 mixed plugins in {load_time:.3f}s ({load_time/50*1000:.1f}ms per plugin)"
        )

    @pytest.mark.asyncio
    async def test_load_plugins_with_many_functions(self, perf_environment):
        """Test loading plugins with many functions"""
        plugins_dir = perf_environment["plugins_dir"]
        loader = perf_environment["loader"]

        # Create 10 plugins with 20 functions each
        for i in range(10):
            create_python_plugin(plugins_dir, f"bigplugin{i}", function_count=20)

        # Measure load time
        start_time = time.time()
        plugins = await loader.load_all_plugins()
        end_time = time.time()

        load_time = end_time - start_time

        # Assert: All plugins loaded
        assert len(plugins) == 10

        # Total functions: 10 plugins * 20 functions = 200 functions
        total_functions = sum(len(p.functions) for p in plugins.values())
        assert total_functions == 200

        # Performance requirement: < 2 seconds for 200 functions
        assert load_time < 2.0, f"Loading took {load_time:.3f}s (expected < 2.0s)"

        print(
            f"\n✓ Loaded {total_functions} functions in {load_time:.3f}s ({load_time/total_functions*1000:.2f}ms per function)"
        )

    @pytest.mark.asyncio
    async def test_incremental_plugin_loading(self, perf_environment):
        """Test incremental plugin loading performance"""
        plugins_dir = perf_environment["plugins_dir"]
        loader = perf_environment["loader"]

        load_times = []

        # Load plugins incrementally and measure each iteration
        for batch in range(5):
            # Add 10 more plugins each batch
            for i in range(10):
                plugin_name = f"batch{batch}_plugin{i}"
                create_python_plugin(plugins_dir, plugin_name, function_count=5)

            start_time = time.time()
            plugins = await loader.load_all_plugins()
            end_time = time.time()

            load_time = end_time - start_time
            load_times.append(load_time)

            assert len(plugins) == (batch + 1) * 10

        # Performance requirement: Load time shouldn't increase dramatically
        # (Should stay roughly O(n), not O(n^2))
        first_batch_time = load_times[0]
        last_batch_time = load_times[-1]

        # Last batch (50 plugins) should not take more than 10x the first batch (10 plugins)
        assert (
            last_batch_time < first_batch_time * 10
        ), f"Performance degradation detected: {first_batch_time:.3f}s → {last_batch_time:.3f}s"

        print(f"\n✓ Incremental loading: {' → '.join(f'{t:.3f}s' for t in load_times)}")

    @pytest.mark.asyncio
    async def test_reload_performance(self, perf_environment):
        """Test plugin reload performance (cache effectiveness)"""
        plugins_dir = perf_environment["plugins_dir"]
        loader = perf_environment["loader"]

        # Create 30 plugins
        for i in range(30):
            create_python_plugin(plugins_dir, f"reloadplugin{i}", function_count=5)

        # First load (cold)
        start_time = time.time()
        plugins_first = await loader.load_all_plugins()
        first_load_time = time.time() - start_time

        # Second load (warm - may have cache)
        start_time = time.time()
        plugins_second = await loader.load_all_plugins()
        second_load_time = time.time() - start_time

        # Assert: Same plugins loaded
        assert len(plugins_first) == len(plugins_second) == 30

        # Second load should be faster or similar (cache effect)
        # Allow for some variance, but second load shouldn't be significantly slower
        assert (
            second_load_time < first_load_time * 1.5
        ), f"Reload slower than expected: {first_load_time:.3f}s → {second_load_time:.3f}s"

        print(
            f"\n✓ Reload: {first_load_time:.3f}s → {second_load_time:.3f}s "
            + f"({(1 - second_load_time/first_load_time)*100:.1f}% improvement)"
        )


@pytest.mark.performance
@pytest.mark.slow
class TestPluginParsingPerformance:
    """Performance tests for plugin parsing"""

    @pytest.mark.asyncio
    async def test_python_parser_performance(self, perf_environment):
        """Test Python plugin parser performance"""
        plugins_dir = perf_environment["plugins_dir"]
        loader = perf_environment["loader"]

        # Create 50 Python plugins
        for i in range(50):
            create_python_plugin(plugins_dir, f"py{i}", function_count=10)

        # Measure parsing time
        start_time = time.time()
        plugins = await loader.load_all_plugins()
        parse_time = time.time() - start_time

        # Assert: All parsed
        assert len(plugins) == 50

        # Performance requirement: < 2 seconds for 50 Python plugins
        assert parse_time < 2.0, f"Parsing took {parse_time:.3f}s (expected < 2.0s)"

        print(f"\n✓ Parsed 50 Python plugins in {parse_time:.3f}s")

    @pytest.mark.asyncio
    async def test_shell_parser_performance(self, perf_environment):
        """Test Shell plugin parser performance"""
        plugins_dir = perf_environment["plugins_dir"]
        loader = perf_environment["loader"]

        # Create 50 Shell plugins
        for i in range(50):
            create_shell_plugin(plugins_dir, f"sh{i}", function_count=10)

        # Measure parsing time
        start_time = time.time()
        plugins = await loader.load_all_plugins()
        parse_time = time.time() - start_time

        # Assert: All parsed
        assert len(plugins) == 50

        # Performance requirement: < 1 second for 50 Shell plugins (simpler parsing)
        assert parse_time < 1.0, f"Parsing took {parse_time:.3f}s (expected < 1.0s)"

        print(f"\n✓ Parsed 50 Shell plugins in {parse_time:.3f}s")

    @pytest.mark.asyncio
    async def test_config_parser_performance(self, perf_environment):
        """Test Config plugin parser performance"""
        plugins_dir = perf_environment["plugins_dir"]
        loader = perf_environment["loader"]

        # Create 50 Config plugins
        for i in range(50):
            create_config_plugin(plugins_dir, f"cfg{i}", function_count=10)

        # Measure parsing time
        start_time = time.time()
        plugins = await loader.load_all_plugins()
        parse_time = time.time() - start_time

        # Assert: All parsed
        assert len(plugins) == 50

        # Performance requirement: < 0.5 seconds for 50 Config plugins (fastest)
        assert parse_time < 0.5, f"Parsing took {parse_time:.3f}s (expected < 0.5s)"

        print(f"\n✓ Parsed 50 Config plugins in {parse_time:.3f}s")
