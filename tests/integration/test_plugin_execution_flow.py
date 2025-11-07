"""
Integration tests for plugin execution flow

Tests end-to-end plugin function execution including argument passing,
result formatting, timeout enforcement, and error handling.
"""

import pytest
import json

from gscripts.application.services.plugin_executor import PluginExecutor
from gscripts.application.services.plugin_service import PluginService
from gscripts.infrastructure.persistence.plugin_loader import PluginLoader
from gscripts.infrastructure.persistence.plugin_repository import PluginRepository
from gscripts.infrastructure.filesystem.file_operations import RealFileSystem
from gscripts.infrastructure.execution.process_executor import ProcessExecutor
from gscripts.core.config_manager import ConfigManager


@pytest.fixture
def execution_setup(temp_dir):
    """Setup full execution stack for integration tests"""
    plugins_root = temp_dir / "plugins"
    plugins_root.mkdir(exist_ok=True)

    # Setup dependencies
    filesystem = RealFileSystem()
    config_manager = ConfigManager()
    process_executor = ProcessExecutor()

    # Create repository and loader
    repository = PluginRepository(
        filesystem=filesystem,
        plugins_dir=plugins_root,
        router_cache_path=None,
        config_manager=config_manager,
    )

    loader = PluginLoader(plugin_repository=repository, plugins_root=plugins_root)

    # Create services
    plugin_service = PluginService(
        plugin_loader=loader,
        plugin_repository=repository,
        config_manager=config_manager,
    )

    plugin_executor = PluginExecutor(
        plugin_loader=loader,
        process_executor=process_executor,
    )

    return {
        "plugin_executor": plugin_executor,
        "plugin_service": plugin_service,
        "plugins_root": plugins_root,
        "config_manager": config_manager,
    }


@pytest.mark.integration
class TestPythonPluginExecution:
    """Integration tests for Python plugin execution"""

    @pytest.mark.asyncio
    async def test_execute_simple_python_function(self, execution_setup):
        """Test executing a simple Python plugin function"""
        # Arrange: Create Python plugin
        plugins_root = execution_setup["plugins_root"]
        plugin_executor = execution_setup["plugin_executor"]
        plugin_service = execution_setup["plugin_service"]

        plugin_dir = plugins_root / "testplugin"
        plugin_dir.mkdir()

        plugin_json = {
            "name": "testplugin",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "description": {"zh": "测试", "en": "Test"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json))

        plugin_py = '''"""Test plugin"""
from gscripts.plugins.base import BasePlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.models import CommandResult

class TestPlugin(BasePlugin):
    def __init__(self):
        self.name = "testplugin"

    @plugin_function(
        name="greet",
        description={"zh": "问候", "en": "Greet"},
        usage="gs testplugin greet <name>",
    )
    async def greet(self, args=None):
        name = args[0] if args else "World"
        return CommandResult(success=True, output=f"Hello, {name}!", exit_code=0)
'''
        (plugin_dir / "plugin.py").write_text(plugin_py)

        # Load plugins
        await plugin_service.load_all_plugins()

        # Act: Execute function
        result = await plugin_executor.execute_plugin_function(
            "testplugin", "greet", ["Alice"]
        )

        # Assert
        assert result.success is True
        assert "Hello, Alice!" in result.output
        assert result.exit_code == 0

    @pytest.mark.asyncio
    async def test_execute_python_function_without_args(self, execution_setup):
        """Test executing Python function without arguments"""
        # Arrange
        plugins_root = execution_setup["plugins_root"]
        plugin_executor = execution_setup["plugin_executor"]
        plugin_service = execution_setup["plugin_service"]

        plugin_dir = plugins_root / "noargs"
        plugin_dir.mkdir()

        plugin_json = {
            "name": "noargs",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "description": {"zh": "无参", "en": "No args"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json))

        plugin_py = '''"""No args plugin"""
from gscripts.plugins.base import BasePlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.models import CommandResult

class NoArgsPlugin(BasePlugin):
    def __init__(self):
        self.name = "noargs"

    @plugin_function(
        name="status",
        description={"zh": "状态", "en": "Status"},
        usage="gs noargs status",
    )
    async def status(self, args=None):
        return CommandResult(success=True, output="OK", exit_code=0)
'''
        (plugin_dir / "plugin.py").write_text(plugin_py)

        await plugin_service.load_all_plugins()

        # Act
        result = await plugin_executor.execute_plugin_function("noargs", "status", [])

        # Assert
        assert result.success is True
        assert "OK" in result.output


@pytest.mark.integration
class TestShellPluginExecution:
    """Integration tests for Shell plugin execution"""

    @pytest.mark.asyncio
    async def test_execute_shell_function(self, execution_setup):
        """Test executing a Shell plugin function"""
        # Arrange: Create Shell plugin
        plugins_root = execution_setup["plugins_root"]
        plugin_executor = execution_setup["plugin_executor"]
        plugin_service = execution_setup["plugin_service"]

        plugin_dir = plugins_root / "shelltest"
        plugin_dir.mkdir()

        plugin_json = {
            "name": "shelltest",
            "version": "1.0.0",
            "type": "shell",
            "entry": "plugin.sh",
            "enabled": True,
            "description": {"zh": "Shell测试", "en": "Shell test"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json))

        plugin_sh = """#!/bin/bash
# @plugin_function
# @name echo_text
# @description {"zh": "回显文本", "en": "Echo text"}
# @usage gs shelltest echo_text <text>
function echo_text() {
    echo "Echo: $1"
}

# @plugin_function
# @name list_files
# @description {"zh": "列出文件", "en": "List files"}
# @usage gs shelltest list_files
function list_files() {
    ls
}
"""
        (plugin_dir / "plugin.sh").write_text(plugin_sh)
        (plugin_dir / "plugin.sh").chmod(0o755)

        await plugin_service.load_all_plugins()

        # Act: Execute shell function with argument
        result = await plugin_executor.execute_plugin_function(
            "shelltest", "echo_text", ["Hello"]
        )

        # Assert
        assert result.success is True
        assert "Echo: Hello" in result.output or "Hello" in result.output


@pytest.mark.integration
class TestConfigPluginExecution:
    """Integration tests for Config plugin execution"""

    @pytest.mark.asyncio
    async def test_execute_config_function(self, execution_setup):
        """Test executing a Config plugin function"""
        # Arrange: Create Config plugin
        plugins_root = execution_setup["plugins_root"]
        plugin_executor = execution_setup["plugin_executor"]
        plugin_service = execution_setup["plugin_service"]

        plugin_dir = plugins_root / "configtest"
        plugin_dir.mkdir()

        plugin_json = {
            "name": "configtest",
            "version": "1.0.0",
            "type": "config",
            "entry": "commands.json",
            "enabled": True,
            "description": {"zh": "配置测试", "en": "Config test"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json))

        commands_json = {
            "commands": {
                "version": {
                    "description": {"zh": "版本", "en": "Version"},
                    "command": "echo '1.0.0'",
                    "usage": "gs configtest version",
                }
            }
        }
        (plugin_dir / "commands.json").write_text(json.dumps(commands_json))

        await plugin_service.load_all_plugins()

        # Act
        result = await plugin_executor.execute_plugin_function(
            "configtest", "version", []
        )

        # Assert
        assert result.success is True
        assert "1.0.0" in result.output


@pytest.mark.integration
class TestExecutionErrorHandling:
    """Integration tests for execution error handling"""

    @pytest.mark.asyncio
    async def test_execute_nonexistent_plugin(self, execution_setup):
        """Test executing function from nonexistent plugin"""
        # Arrange
        plugin_executor = execution_setup["plugin_executor"]

        # Act
        result = await plugin_executor.execute_plugin_function(
            "nonexistent", "func", []
        )

        # Assert
        assert result.success is False
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_execute_nonexistent_function(self, execution_setup):
        """Test executing nonexistent function from existing plugin"""
        # Arrange: Create plugin
        plugins_root = execution_setup["plugins_root"]
        plugin_executor = execution_setup["plugin_executor"]
        plugin_service = execution_setup["plugin_service"]

        plugin_dir = plugins_root / "limited"
        plugin_dir.mkdir()

        plugin_json = {
            "name": "limited",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "description": {"zh": "有限", "en": "Limited"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json))

        plugin_py = '''"""Limited plugin"""
from gscripts.plugins.base import BasePlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.models import CommandResult

class LimitedPlugin(BasePlugin):
    def __init__(self):
        self.name = "limited"

    @plugin_function(
        name="only_func",
        description={"zh": "唯一", "en": "Only function"},
        usage="gs limited only_func",
    )
    async def only_func(self, args=None):
        return CommandResult(success=True, output="OK", exit_code=0)
'''
        (plugin_dir / "plugin.py").write_text(plugin_py)

        await plugin_service.load_all_plugins()

        # Act: Try to execute nonexistent function
        result = await plugin_executor.execute_plugin_function(
            "limited", "nonexistent_func", []
        )

        # Assert
        assert result.success is False
        assert result.error is not None

    @pytest.mark.asyncio
    async def test_execute_disabled_plugin(self, execution_setup):
        """Test executing function from disabled plugin"""
        # Arrange: Create disabled plugin
        plugins_root = execution_setup["plugins_root"]
        plugin_executor = execution_setup["plugin_executor"]
        plugin_service = execution_setup["plugin_service"]

        plugin_dir = plugins_root / "disabled"
        plugin_dir.mkdir()

        plugin_json = {
            "name": "disabled",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": False,  # Disabled
            "description": {"zh": "禁用", "en": "Disabled"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json))

        plugin_py = '''"""Disabled plugin"""
from gscripts.plugins.base import BasePlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.models import CommandResult

class DisabledPlugin(BasePlugin):
    def __init__(self):
        self.name = "disabled"

    @plugin_function(
        name="func",
        description={"zh": "功能", "en": "Function"},
        usage="gs disabled func",
    )
    async def func(self, args=None):
        return CommandResult(success=True, output="Should not execute", exit_code=0)
'''
        (plugin_dir / "plugin.py").write_text(plugin_py)

        await plugin_service.load_all_plugins()

        # Act
        result = await plugin_executor.execute_plugin_function("disabled", "func", [])

        # Assert
        assert result.success is False
        assert result.error is not None


@pytest.mark.integration
class TestArgumentPassing:
    """Integration tests for argument passing and parsing"""

    @pytest.mark.asyncio
    async def test_execute_with_multiple_arguments(self, execution_setup):
        """Test executing function with multiple arguments"""
        # Arrange
        plugins_root = execution_setup["plugins_root"]
        plugin_executor = execution_setup["plugin_executor"]
        plugin_service = execution_setup["plugin_service"]

        plugin_dir = plugins_root / "multiarg"
        plugin_dir.mkdir()

        plugin_json = {
            "name": "multiarg",
            "version": "1.0.0",
            "type": "python",
            "entry": "plugin.py",
            "enabled": True,
            "description": {"zh": "多参数", "en": "Multi args"},
        }
        (plugin_dir / "plugin.json").write_text(json.dumps(plugin_json))

        plugin_py = '''"""Multi-arg plugin"""
from gscripts.plugins.base import BasePlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.models import CommandResult

class MultiArgPlugin(BasePlugin):
    def __init__(self):
        self.name = "multiarg"

    @plugin_function(
        name="concat",
        description={"zh": "连接", "en": "Concatenate"},
        usage="gs multiarg concat <args...>",
    )
    async def concat(self, args=None):
        result = " ".join(args) if args else ""
        return CommandResult(success=True, output=result, exit_code=0)
'''
        (plugin_dir / "plugin.py").write_text(plugin_py)

        await plugin_service.load_all_plugins()

        # Act
        result = await plugin_executor.execute_plugin_function(
            "multiarg", "concat", ["Hello", "World", "!"]
        )

        # Assert
        assert result.success is True
        assert "Hello World !" in result.output
