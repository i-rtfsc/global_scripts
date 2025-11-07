"""
Filesystem fixtures for testing.

Provides mock and real filesystem abstractions for testing.
"""

import pytest
from pathlib import Path

from gscripts.infrastructure.filesystem.file_operations import InMemoryFileSystem


@pytest.fixture
def mock_filesystem() -> InMemoryFileSystem:
    """
    Provide in-memory filesystem for fast, isolated testing.

    This filesystem is completely isolated - no real I/O occurs.
    Automatically cleaned up after each test.
    """
    return InMemoryFileSystem()


@pytest.fixture
def mock_filesystem_with_plugins(
    mock_filesystem: InMemoryFileSystem, temp_dir: Path
) -> InMemoryFileSystem:
    """
    Provide in-memory filesystem pre-populated with sample plugins.

    Includes:
    - Python plugin
    - Shell plugin
    - Config plugin
    - Hybrid plugin with subplugins
    """
    import json

    plugins_dir = temp_dir / "plugins"

    # Python plugin
    python_plugin = plugins_dir / "python_test"
    mock_filesystem.write_text(
        python_plugin / "plugin.json",
        json.dumps(
            {
                "name": "python_test",
                "version": "1.0.0",
                "type": "python",
                "entry": "plugin.py",
                "enabled": True,
                "description": {"zh": "Python测试", "en": "Python test"},
            }
        ),
    )
    mock_filesystem.write_text(
        python_plugin / "plugin.py",
        "# Python plugin code\npass",
    )

    # Shell plugin
    shell_plugin = plugins_dir / "shell_test"
    mock_filesystem.write_text(
        shell_plugin / "plugin.json",
        json.dumps(
            {
                "name": "shell_test",
                "version": "1.0.0",
                "type": "shell",
                "entry": "plugin.sh",
                "enabled": True,
                "description": {"zh": "Shell测试", "en": "Shell test"},
            }
        ),
    )
    mock_filesystem.write_text(
        shell_plugin / "plugin.sh",
        "#!/bin/bash\n# Shell plugin",
    )

    # Config plugin
    config_plugin = plugins_dir / "config_test"
    mock_filesystem.write_text(
        config_plugin / "plugin.json",
        json.dumps(
            {
                "name": "config_test",
                "version": "1.0.0",
                "type": "json",
                "entry": "commands.json",
                "enabled": True,
                "description": {"zh": "配置测试", "en": "Config test"},
            }
        ),
    )
    mock_filesystem.write_text(
        config_plugin / "commands.json",
        json.dumps(
            {
                "functions": [
                    {
                        "name": "test",
                        "description": {"zh": "测试", "en": "Test"},
                        "command": "echo test",
                    }
                ]
            }
        ),
    )

    return mock_filesystem


@pytest.fixture
def temp_filesystem(temp_dir: Path) -> Path:
    """
    Provide real temporary filesystem for integration tests.

    Uses pytest's tmp_path fixture. Automatically cleaned up after test.
    Use this when you need real file I/O for integration testing.
    """
    return temp_dir


@pytest.fixture
def plugin_directory(temp_dir: Path) -> Path:
    """
    Create and provide a temporary plugin directory.

    Returns path to plugins/ directory ready for use.
    """
    plugins_dir = temp_dir / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    return plugins_dir


@pytest.fixture
def config_directory(temp_dir: Path) -> Path:
    """
    Create and provide a temporary config directory.

    Returns path to config/ directory ready for use.
    """
    config_dir = temp_dir / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


@pytest.fixture
def home_directory(temp_dir: Path) -> Path:
    """
    Create and provide a temporary home directory structure.

    Creates:
    - ~/.config/global-scripts/config/
    - ~/.config/global-scripts/logs/
    - ~/.config/global-scripts/plugins/

    Returns path to home directory.
    """
    home = temp_dir / "home"
    gs_config = home / ".config" / "global-scripts"

    (gs_config / "config").mkdir(parents=True, exist_ok=True)
    (gs_config / "logs").mkdir(parents=True, exist_ok=True)
    (gs_config / "plugins").mkdir(parents=True, exist_ok=True)

    return home
