"""
Performance benchmark tests for router generation

Tests router index and shell completion generation performance
to ensure the system can handle large plugin sets efficiently.
"""

import pytest
import time
import json
from pathlib import Path

from tests.factories.plugin_factory import PluginFactory
from tests.factories.function_factory import FunctionFactory
from gscripts.models.plugin import PluginType


@pytest.fixture
def router_perf_environment(tmp_path):
    """Setup environment for router generation performance testing"""
    test_root = tmp_path / "router_perf_test"
    test_root.mkdir()

    output_dir = test_root / "output"
    output_dir.mkdir()

    return {"root": test_root, "output_dir": output_dir}


def generate_router_json(plugins: dict, output_file: Path):
    """Generate router.json from plugin dict"""
    router_data = {
        "version": "5.0.0",
        "generated_at": "2024-01-01T00:00:00",
        "plugins": {},
    }

    for name, plugin in plugins.items():
        if not plugin.metadata.enabled:
            continue

        plugin_data = {
            "enabled": True,
            "type": plugin.metadata.type.value,
            "commands": {},
        }

        for func_name, func_info in plugin.functions.items():
            plugin_data["commands"][func_name] = {
                "description": func_info.description,
                "usage": func_info.usage,
            }

        router_data["plugins"][name] = plugin_data

    output_file.write_text(json.dumps(router_data, indent=2))


def generate_bash_completion(plugins: dict, output_file: Path):
    """Generate bash completion script from plugins"""
    plugin_names = [name for name, p in plugins.items() if p.metadata.enabled]

    completion_script = f"""# Bash completion for gs command
_gs_completion() {{
    local cur prev
    COMPREPLY=()
    cur="${{COMP_WORDS[COMP_CWORD]}}"
    prev="${{COMP_WORDS[COMP_CWORD-1]}}"

    local plugins="{' '.join(plugin_names)}"

    case "$prev" in
"""

    for name, plugin in plugins.items():
        if not plugin.metadata.enabled:
            continue

        func_names = " ".join(plugin.functions.keys())
        completion_script += f"""        {name})
            COMPREPLY=( $(compgen -W "{func_names}" -- ${{cur}}) )
            return 0
            ;;
"""

    completion_script += """    esac

    COMPREPLY=( $(compgen -W "${plugins}" -- ${cur}) )
}

complete -F _gs_completion gs
"""

    output_file.write_text(completion_script)


@pytest.mark.performance
@pytest.mark.slow
class TestRouterGenerationPerformance:
    """Performance tests for router index generation"""

    def test_generate_router_for_50_plugins(self, router_perf_environment):
        """Test router generation for 50 plugins"""
        output_dir = router_perf_environment["output_dir"]

        # Create 50 plugins with 5 functions each
        plugins = {}
        for i in range(50):
            functions = {}
            for j in range(5):
                functions[f"func{j}"] = FunctionFactory.create_python(name=f"func{j}")

            plugins[f"plugin{i}"] = PluginFactory.create(
                name=f"plugin{i}",
                enabled=True,
                type=PluginType.PYTHON,
                functions=functions,
            )

        output_file = output_dir / "router.json"

        # Measure generation time
        start_time = time.time()
        generate_router_json(plugins, output_file)
        gen_time = time.time() - start_time

        # Assert: Router file created
        assert output_file.exists()

        router_data = json.loads(output_file.read_text())
        assert len(router_data["plugins"]) == 50

        # Performance requirement: < 100ms for 50 plugins
        assert (
            gen_time < 0.1
        ), f"Generation took {gen_time*1000:.1f}ms (expected < 100ms)"

        print(f"\n✓ Generated router for 50 plugins in {gen_time*1000:.1f}ms")

    def test_generate_router_for_large_plugin_set(self, router_perf_environment):
        """Test router generation for large plugin set (200 plugins)"""
        output_dir = router_perf_environment["output_dir"]

        # Create 200 plugins
        plugins = {}
        for i in range(200):
            functions = {}
            for j in range(10):
                functions[f"func{j}"] = FunctionFactory.create_python(name=f"func{j}")

            plugins[f"plugin{i}"] = PluginFactory.create(
                name=f"plugin{i}",
                enabled=True,
                type=PluginType.PYTHON,
                functions=functions,
            )

        output_file = output_dir / "router_large.json"

        # Measure generation time
        start_time = time.time()
        generate_router_json(plugins, output_file)
        gen_time = time.time() - start_time

        # Assert: Router file created
        assert output_file.exists()

        router_data = json.loads(output_file.read_text())
        assert len(router_data["plugins"]) == 200

        # Performance requirement: < 500ms for 200 plugins
        assert (
            gen_time < 0.5
        ), f"Generation took {gen_time*1000:.1f}ms (expected < 500ms)"

        print(
            f"\n✓ Generated router for 200 plugins (2000 functions) in {gen_time*1000:.1f}ms"
        )

    def test_router_generation_with_filtering(self, router_perf_environment):
        """Test router generation excludes disabled plugins efficiently"""
        output_dir = router_perf_environment["output_dir"]

        # Create 100 plugins, half disabled
        plugins = {}
        for i in range(100):
            functions = {
                f"func{j}": FunctionFactory.create_python(name=f"func{j}")
                for j in range(5)
            }

            plugins[f"plugin{i}"] = PluginFactory.create(
                name=f"plugin{i}",
                enabled=(i % 2 == 0),  # Only even plugins enabled
                type=PluginType.PYTHON,
                functions=functions,
            )

        output_file = output_dir / "router_filtered.json"

        # Measure generation time
        start_time = time.time()
        generate_router_json(plugins, output_file)
        gen_time = time.time() - start_time

        # Assert: Only enabled plugins in router
        router_data = json.loads(output_file.read_text())
        assert len(router_data["plugins"]) == 50  # Half enabled

        # Performance requirement: < 200ms for 100 plugins (with filtering)
        assert (
            gen_time < 0.2
        ), f"Generation took {gen_time*1000:.1f}ms (expected < 200ms)"

        print(
            f"\n✓ Generated router with filtering (50/100 enabled) in {gen_time*1000:.1f}ms"
        )


@pytest.mark.performance
@pytest.mark.slow
class TestCompletionGenerationPerformance:
    """Performance tests for shell completion generation"""

    def test_generate_bash_completion_for_50_plugins(self, router_perf_environment):
        """Test bash completion generation for 50 plugins"""
        output_dir = router_perf_environment["output_dir"]

        # Create 50 plugins
        plugins = {}
        for i in range(50):
            functions = {
                f"func{j}": FunctionFactory.create_python(name=f"func{j}")
                for j in range(5)
            }

            plugins[f"plugin{i}"] = PluginFactory.create(
                name=f"plugin{i}",
                enabled=True,
                type=PluginType.PYTHON,
                functions=functions,
            )

        output_file = output_dir / "gs-completion.bash"

        # Measure generation time
        start_time = time.time()
        generate_bash_completion(plugins, output_file)
        gen_time = time.time() - start_time

        # Assert: Completion file created
        assert output_file.exists()

        content = output_file.read_text()
        assert "_gs_completion" in content

        # Performance requirement: < 50ms for 50 plugins
        assert (
            gen_time < 0.05
        ), f"Generation took {gen_time*1000:.1f}ms (expected < 50ms)"

        print(f"\n✓ Generated bash completion for 50 plugins in {gen_time*1000:.1f}ms")

    def test_generate_completion_for_all_shells(self, router_perf_environment):
        """Test completion generation for all supported shells"""
        output_dir = router_perf_environment["output_dir"]

        # Create 30 plugins
        plugins = {}
        for i in range(30):
            functions = {
                f"func{j}": FunctionFactory.create_python(name=f"func{j}")
                for j in range(5)
            }

            plugins[f"plugin{i}"] = PluginFactory.create(
                name=f"plugin{i}",
                enabled=True,
                type=PluginType.PYTHON,
                functions=functions,
            )

        # Generate for all shells
        shells = ["bash", "zsh", "fish"]
        total_time = 0

        for shell in shells:
            output_file = output_dir / f"gs-completion.{shell}"

            start_time = time.time()
            generate_bash_completion(plugins, output_file)
            gen_time = time.time() - start_time

            total_time += gen_time

            assert output_file.exists()

        # Performance requirement: < 100ms for all 3 shells
        assert (
            total_time < 0.1
        ), f"Total generation took {total_time*1000:.1f}ms (expected < 100ms)"

        print(f"\n✓ Generated completions for 3 shells in {total_time*1000:.1f}ms")

    def test_incremental_completion_update(self, router_perf_environment):
        """Test incremental completion update performance"""
        output_dir = router_perf_environment["output_dir"]

        # Start with 20 plugins
        plugins = {}
        for i in range(20):
            functions = {
                f"func{j}": FunctionFactory.create_python(name=f"func{j}")
                for j in range(5)
            }
            plugins[f"plugin{i}"] = PluginFactory.create(
                name=f"plugin{i}",
                enabled=True,
                type=PluginType.PYTHON,
                functions=functions,
            )

        output_file = output_dir / "gs-completion-incremental.bash"

        # Initial generation
        start_time = time.time()
        generate_bash_completion(plugins, output_file)
        initial_time = time.time() - start_time

        # Add 10 more plugins
        for i in range(20, 30):
            functions = {
                f"func{j}": FunctionFactory.create_python(name=f"func{j}")
                for j in range(5)
            }
            plugins[f"plugin{i}"] = PluginFactory.create(
                name=f"plugin{i}",
                enabled=True,
                type=PluginType.PYTHON,
                functions=functions,
            )

        # Regenerate
        start_time = time.time()
        generate_bash_completion(plugins, output_file)
        update_time = time.time() - start_time

        # Performance requirement: Update should be similarly fast
        assert (
            update_time < initial_time * 2
        ), f"Update slower than expected: {initial_time*1000:.1f}ms → {update_time*1000:.1f}ms"

        print(
            f"\n✓ Incremental update: {initial_time*1000:.1f}ms → {update_time*1000:.1f}ms"
        )


@pytest.mark.performance
@pytest.mark.slow
class TestCombinedGenerationPerformance:
    """Performance tests for combined router and completion generation"""

    def test_full_generation_pipeline(self, router_perf_environment):
        """Test full generation pipeline (router + all completions)"""
        output_dir = router_perf_environment["output_dir"]

        # Create 50 plugins
        plugins = {}
        for i in range(50):
            functions = {
                f"func{j}": FunctionFactory.create_python(name=f"func{j}")
                for j in range(8)
            }

            plugins[f"plugin{i}"] = PluginFactory.create(
                name=f"plugin{i}",
                enabled=True,
                type=PluginType.PYTHON,
                functions=functions,
            )

        # Measure full pipeline
        start_time = time.time()

        # Generate router
        router_file = output_dir / "router.json"
        generate_router_json(plugins, router_file)

        # Generate completions for all shells
        for shell in ["bash", "zsh", "fish"]:
            completion_file = output_dir / f"gs-completion.{shell}"
            generate_bash_completion(plugins, completion_file)

        total_time = time.time() - start_time

        # Assert: All files created
        assert router_file.exists()
        assert (output_dir / "gs-completion.bash").exists()
        assert (output_dir / "gs-completion.zsh").exists()
        assert (output_dir / "gs-completion.fish").exists()

        # Performance requirement: < 200ms for full pipeline
        assert (
            total_time < 0.2
        ), f"Full pipeline took {total_time*1000:.1f}ms (expected < 200ms)"

        print(
            f"\n✓ Full generation pipeline (router + 3 completions) in {total_time*1000:.1f}ms"
        )

    def test_generation_scalability(self, router_perf_environment):
        """Test generation scalability with increasing plugin counts"""
        output_dir = router_perf_environment["output_dir"]

        scales = [10, 50, 100]
        times = []

        for scale in scales:
            # Create plugins
            plugins = {}
            for i in range(scale):
                functions = {
                    f"func{j}": FunctionFactory.create_python(name=f"func{j}")
                    for j in range(5)
                }
                plugins[f"plugin{i}"] = PluginFactory.create(
                    name=f"plugin{i}",
                    enabled=True,
                    type=PluginType.PYTHON,
                    functions=functions,
                )

            # Measure generation
            start_time = time.time()
            output_file = output_dir / f"router_{scale}.json"
            generate_router_json(plugins, output_file)
            gen_time = time.time() - start_time

            times.append(gen_time)

        # Performance requirement: Should scale linearly (or better)
        # 100 plugins shouldn't take 10x more than 10 plugins
        ratio = times[-1] / times[0]
        expected_max_ratio = 12  # Allow some overhead, but should be roughly linear

        assert (
            ratio < expected_max_ratio
        ), f"Poor scalability: {times[0]*1000:.1f}ms → {times[-1]*1000:.1f}ms (ratio: {ratio:.1f}x, expected < {expected_max_ratio}x)"

        print(
            f"\n✓ Scalability: {' → '.join(f'{t*1000:.1f}ms' for t in times)} (ratio: {ratio:.1f}x)"
        )


@pytest.mark.performance
class TestRouterFileSize:
    """Tests for router file size (not strictly performance, but related)"""

    def test_router_file_size_efficiency(self, router_perf_environment):
        """Test that router file size is reasonable"""
        output_dir = router_perf_environment["output_dir"]

        # Create 100 plugins
        plugins = {}
        for i in range(100):
            functions = {
                f"func{j}": FunctionFactory.create_python(name=f"func{j}")
                for j in range(10)
            }

            plugins[f"plugin{i}"] = PluginFactory.create(
                name=f"plugin{i}",
                enabled=True,
                type=PluginType.PYTHON,
                functions=functions,
            )

        output_file = output_dir / "router_size_test.json"
        generate_router_json(plugins, output_file)

        # Check file size
        file_size = output_file.stat().st_size
        file_size_kb = file_size / 1024

        # Performance requirement: File should be < 500KB for 100 plugins (1000 functions)
        assert (
            file_size_kb < 500
        ), f"Router file is {file_size_kb:.1f}KB (expected < 500KB)"

        print(
            f"\n✓ Router file size: {file_size_kb:.1f}KB for 100 plugins (1000 functions)"
        )
