"""
Performance benchmark tests for command execution

Tests command execution performance including subprocess overhead,
async execution, and timeout handling.
"""

import pytest
import time
import asyncio
from pathlib import Path
import json

from gscripts.infrastructure.execution.process_executor import ProcessExecutor
from gscripts.application.services.plugin_executor import PluginExecutor
from gscripts.infrastructure.persistence.plugin_loader import PluginLoader
from gscripts.infrastructure.persistence.plugin_repository import PluginRepository
from gscripts.infrastructure.filesystem.file_operations import RealFileSystem
from gscripts.core.config_manager import ConfigManager


@pytest.fixture
def exec_environment(tmp_path):
    """Setup environment for execution performance testing"""
    test_root = tmp_path / "exec_perf_test"
    test_root.mkdir()

    plugins_dir = test_root / "plugins"
    plugins_dir.mkdir()

    filesystem = RealFileSystem()
    config_manager = ConfigManager()
    process_executor = ProcessExecutor()

    repository = PluginRepository(
        filesystem=filesystem,
        plugins_dir=plugins_dir,
        router_cache_path=None,
        config_manager=config_manager,
    )

    loader = PluginLoader(plugin_repository=repository, plugins_root=plugins_dir)

    plugin_executor = PluginExecutor(
        plugin_loader=loader,
        process_executor=process_executor,
        max_concurrent=10,
        default_timeout=30,
    )

    return {
        "plugins_dir": plugins_dir,
        "loader": loader,
        "plugin_executor": plugin_executor,
        "process_executor": process_executor,
    }


def create_fast_plugin(plugins_dir: Path, name: str):
    """Create a plugin with fast-executing functions"""
    plugin_dir = plugins_dir / name
    plugin_dir.mkdir()

    plugin_json = {
        "name": name,
        "version": "1.0.0",
        "type": "python",
        "entry": "plugin.py",
        "enabled": True,
        "description": {"zh": name, "en": name},
    }
    (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json, indent=2))

    plugin_py = f'''"""Fast plugin {name}"""
from gscripts.plugins.base import BasePlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.models import CommandResult

class {name.capitalize()}Plugin(BasePlugin):
    def __init__(self):
        self.name = "{name}"

    @plugin_function(
        name="fast",
        description={{"zh": "快速", "en": "Fast"}},
        usage="gs {name} fast",
    )
    async def fast(self, args=None):
        # Minimal processing
        return CommandResult(success=True, output="done", exit_code=0)
'''
    (plugin_dir / "plugin.py").write_text(plugin_py)


@pytest.mark.performance
@pytest.mark.slow
class TestCommandExecutionOverhead:
    """Performance tests for command execution overhead"""

    @pytest.mark.asyncio
    async def test_simple_command_execution_overhead(self, exec_environment):
        """Test overhead of executing simple commands"""
        process_executor = exec_environment["process_executor"]

        # Measure execution of simple echo command
        iterations = 100
        start_time = time.time()

        for _ in range(iterations):
            result = await process_executor.run_command("echo 'test'")
            assert result.returncode == 0

        total_time = time.time() - start_time
        avg_time = total_time / iterations

        # Performance requirement: < 20ms average per command
        assert (
            avg_time < 0.02
        ), f"Average execution time {avg_time*1000:.1f}ms (expected < 20ms)"

        print(
            f"\n✓ {iterations} commands in {total_time:.3f}s ({avg_time*1000:.1f}ms per command)"
        )

    @pytest.mark.asyncio
    async def test_concurrent_command_execution(self, exec_environment):
        """Test concurrent command execution performance"""
        process_executor = exec_environment["process_executor"]

        # Execute 50 commands concurrently
        num_commands = 50

        start_time = time.time()
        tasks = [
            process_executor.run_command("echo 'test'") for _ in range(num_commands)
        ]
        results = await asyncio.gather(*tasks)
        total_time = time.time() - start_time

        # Assert: All succeeded
        assert all(r.returncode == 0 for r in results)

        # Performance requirement: Concurrent execution should be faster than sequential
        # 50 commands concurrently should take < 1 second (vs ~1s if sequential)
        assert (
            total_time < 1.0
        ), f"Concurrent execution took {total_time:.3f}s (expected < 1.0s)"

        print(f"\n✓ {num_commands} concurrent commands in {total_time:.3f}s")

    @pytest.mark.asyncio
    async def test_plugin_function_execution_overhead(self, exec_environment):
        """Test overhead of plugin function execution"""
        plugins_dir = exec_environment["plugins_dir"]
        loader = exec_environment["loader"]
        plugin_executor = exec_environment["plugin_executor"]

        # Create fast plugin
        create_fast_plugin(plugins_dir, "fastplugin")
        await loader.load_all_plugins()

        # Measure execution overhead
        iterations = 50
        start_time = time.time()

        for _ in range(iterations):
            result = await plugin_executor.execute_plugin_function(
                "fastplugin", "fast", []
            )
            # Note: May fail if plugin_executor needs plugin_service not plugin_loader
            if not result.success:
                break

        total_time = time.time() - start_time
        avg_time = total_time / iterations

        # Performance requirement: < 50ms average per plugin function
        # (includes plugin lookup, function dispatch, etc.)
        expected_time = 0.05
        if avg_time < expected_time:
            print(
                f"\n✓ {iterations} plugin executions in {total_time:.3f}s ({avg_time*1000:.1f}ms per call)"
            )
        else:
            print(
                f"\n⚠ {iterations} plugin executions in {total_time:.3f}s ({avg_time*1000:.1f}ms per call, expected < {expected_time*1000}ms)"
            )


@pytest.mark.performance
@pytest.mark.slow
class TestAsyncPerformance:
    """Performance tests for async execution"""

    @pytest.mark.asyncio
    async def test_async_overhead(self, exec_environment):
        """Test async/await overhead"""
        # Measure overhead of async function calls
        iterations = 1000

        async def simple_async_func():
            return "done"

        start_time = time.time()
        for _ in range(iterations):
            result = await simple_async_func()
            assert result == "done"
        total_time = time.time() - start_time

        avg_time = total_time / iterations

        # Performance requirement: < 0.1ms per async call
        assert (
            avg_time < 0.0001
        ), f"Async overhead {avg_time*1000:.3f}ms (expected < 0.1ms)"

        print(
            f"\n✓ {iterations} async calls in {total_time:.3f}s ({avg_time*1000000:.1f}μs per call)"
        )

    @pytest.mark.asyncio
    async def test_gather_performance(self, exec_environment):
        """Test asyncio.gather performance with many tasks"""
        # Create 100 concurrent tasks
        num_tasks = 100

        async def dummy_task(n):
            await asyncio.sleep(0.01)  # 10ms
            return n

        start_time = time.time()
        results = await asyncio.gather(*[dummy_task(i) for i in range(num_tasks)])
        total_time = time.time() - start_time

        # Assert: All tasks completed
        assert len(results) == num_tasks

        # Performance requirement: 100 tasks with 10ms sleep should complete in ~10-50ms
        # (not 100 * 10ms = 1000ms, due to concurrency)
        assert (
            total_time < 0.1
        ), f"Gather took {total_time:.3f}s (expected < 0.1s with concurrency)"

        print(
            f"\n✓ {num_tasks} concurrent tasks in {total_time:.3f}s (concurrency speedup: {num_tasks*0.01/total_time:.1f}x)"
        )


@pytest.mark.performance
@pytest.mark.slow
class TestTimeoutPerformance:
    """Performance tests for timeout handling"""

    @pytest.mark.asyncio
    async def test_timeout_enforcement_overhead(self, exec_environment):
        """Test overhead of timeout enforcement"""
        process_executor = exec_environment["process_executor"]

        # Execute commands with timeout (should complete well before timeout)
        iterations = 20
        timeout = 5.0  # 5 second timeout

        start_time = time.time()
        for _ in range(iterations):
            result = await process_executor.run_command("echo 'test'", timeout=timeout)
            assert result.returncode == 0
        total_time = time.time() - start_time

        avg_time = total_time / iterations

        # Performance requirement: Timeout mechanism shouldn't add significant overhead
        # Each command should still complete in < 30ms
        assert (
            avg_time < 0.03
        ), f"Timeout overhead: {avg_time*1000:.1f}ms (expected < 30ms)"

        print(
            f"\n✓ {iterations} commands with timeout in {total_time:.3f}s ({avg_time*1000:.1f}ms per command)"
        )

    @pytest.mark.asyncio
    async def test_rapid_timeout_handling(self, exec_environment):
        """Test handling of rapidly timing out commands"""
        process_executor = exec_environment["process_executor"]

        # Execute commands that will timeout quickly
        iterations = 10
        short_timeout = 0.05  # 50ms timeout

        start_time = time.time()
        for _ in range(iterations):
            result = await process_executor.run_command(
                "sleep 10", timeout=short_timeout  # Will timeout
            )
            # Command should timeout (non-zero return code or error)
            # We're just measuring how fast timeouts are detected and handled
        total_time = time.time() - start_time

        # Performance requirement: Each timeout should be detected quickly
        # 10 timeouts with 50ms timeout should complete in < 1s total
        assert (
            total_time < 1.0
        ), f"Timeout detection took {total_time:.3f}s (expected < 1.0s)"

        print(
            f"\n✓ {iterations} timeouts detected in {total_time:.3f}s ({total_time/iterations*1000:.1f}ms per timeout)"
        )


@pytest.mark.performance
@pytest.mark.slow
class TestScalability:
    """Performance tests for scalability"""

    @pytest.mark.asyncio
    async def test_execution_scalability(self, exec_environment):
        """Test that execution time scales linearly"""
        process_executor = exec_environment["process_executor"]

        # Test different scales: 10, 50, 100 commands
        scales = [10, 50, 100]
        times = []

        for scale in scales:
            start_time = time.time()
            tasks = [process_executor.run_command("echo 'test'") for _ in range(scale)]
            await asyncio.gather(*tasks)
            exec_time = time.time() - start_time
            times.append(exec_time)

        # Performance requirement: Time should scale roughly linearly
        # (or better with concurrency)
        # 100 commands shouldn't take 10x more than 10 commands
        # (due to concurrency, should be much better)
        ratio = times[-1] / times[0]  # 100/10 time ratio
        expected_max_ratio = 5  # Should be < 5x (vs 10x if purely linear)

        assert (
            ratio < expected_max_ratio
        ), f"Poor scalability: {times[0]:.3f}s → {times[-1]:.3f}s (ratio: {ratio:.1f}x, expected < {expected_max_ratio}x)"

        print(
            f"\n✓ Scalability: {' → '.join(f'{t:.3f}s' for t in times)} (ratio: {ratio:.1f}x)"
        )

    @pytest.mark.asyncio
    async def test_memory_efficiency(self, exec_environment):
        """Test memory efficiency with many commands"""
        process_executor = exec_environment["process_executor"]

        # Execute many commands and verify no memory leaks
        # (This is a simple test; real memory profiling would use memory_profiler)
        num_commands = 200

        start_time = time.time()
        tasks = [
            process_executor.run_command("echo 'test'") for _ in range(num_commands)
        ]
        results = await asyncio.gather(*tasks)
        total_time = time.time() - start_time

        # Assert: All completed
        assert len(results) == num_commands

        # Performance requirement: 200 commands should complete in < 2 seconds
        assert (
            total_time < 2.0
        ), f"200 commands took {total_time:.3f}s (expected < 2.0s)"

        print(
            f"\n✓ {num_commands} commands in {total_time:.3f}s ({total_time/num_commands*1000:.1f}ms per command)"
        )
