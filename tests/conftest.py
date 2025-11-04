"""
Test configuration and fixtures
Provides test fixtures and utility functions
"""

import pytest
from pathlib import Path
from typing import Generator

from src.gscripts.infrastructure import (
    DIContainer,
    get_container,
    reset_container,
    configure_services,
)
from src.gscripts.infrastructure.filesystem import (
    InMemoryFileSystem,
    MockEnvironment,
)


@pytest.fixture
def test_container() -> Generator[DIContainer, None, None]:
    """Provide test DI container"""
    reset_container()
    container = get_container()
    configure_services(container, use_mocks=True)
    yield container
    reset_container()


@pytest.fixture
def mock_filesystem(test_container: DIContainer) -> InMemoryFileSystem:
    """Provide mock filesystem"""
    from src.gscripts.domain.interfaces import IFileSystem

    return test_container.resolve(IFileSystem)


@pytest.fixture
def mock_environment(test_container: DIContainer) -> MockEnvironment:
    """Provide mock environment"""
    from src.gscripts.domain.interfaces import IEnvironment

    return test_container.resolve(IEnvironment)


@pytest.fixture
def temp_plugin_dir(tmp_path: Path) -> Path:
    """Provide temporary plugin directory"""
    plugin_dir = tmp_path / "plugins"
    plugin_dir.mkdir()
    return plugin_dir


@pytest.fixture
def sample_plugin_config() -> dict:
    """Provide sample plugin config"""
    return {
        "name": "test_plugin",
        "version": "1.0.0",
        "description": "Test plugin",
        "type": "python",
        "enabled": True,
    }


# Parser-related fixtures
@pytest.fixture
def sample_yaml_content():
    """Sample YAML plugin content for testing"""
    return """
functions:
  - name: hello
    description: Say hello to someone
    command: echo "Hello, {{args[0]}}!"
    type: shell
    args:
      - name
    examples:
      - hello world

  - name: goodbye
    description: Say goodbye
    command: echo "Goodbye!"
    type: shell
"""


@pytest.fixture
def sample_toml_content():
    """Sample TOML plugin content for testing"""
    return """
[functions.hello]
description = "Say hello"
command = "echo 'Hello'"
type = "shell"

[functions.goodbye]
description = "Say goodbye"
command = "echo 'Goodbye'"
type = "shell"
"""


@pytest.fixture
def sample_python_plugin():
    """Sample Python plugin content for testing"""
    return """
from gscripts.plugins.decorators import plugin_function

@plugin_function(
    name="hello",
    description="Say hello"
)
def hello_command(args):
    return "Hello, " + args[0] if args else "Hello, World!"

@plugin_function(
    name="goodbye",
    description="Say goodbye"
)
def goodbye_command(args):
    return "Goodbye!"
"""


@pytest.fixture
def sample_shell_plugin():
    """Sample Shell plugin content for testing"""
    return """#!/bin/bash

# @function: hello
# @description: Say hello to someone
# @args: name
hello() {
    echo "Hello, $1!"
}

# @function: goodbye
# @description: Say goodbye
goodbye() {
    echo "Goodbye!"
}
"""


@pytest.fixture
def mock_parser_config():
    """Mock parser configuration for testing"""
    return {
        "enabled": ["python", "shell", "config"],
        "disabled": [],
        "custom_paths": [],
        "priority_overrides": {},
    }


@pytest.fixture
def extended_parser_config(tmp_path):
    """Extended parser config with custom paths"""
    custom_dir = tmp_path / "custom_parsers"
    custom_dir.mkdir()

    return {
        "enabled": ["python", "shell", "config", "yaml", "toml"],
        "disabled": ["experimental"],
        "custom_paths": [str(custom_dir)],
        "priority_overrides": {"yaml": 15, "toml": 25},
    }


__all__ = [
    "test_container",
    "mock_filesystem",
    "mock_environment",
    "temp_plugin_dir",
    "sample_plugin_config",
    "sample_yaml_content",
    "sample_toml_content",
    "sample_python_plugin",
    "sample_shell_plugin",
    "mock_parser_config",
    "extended_parser_config",
]
