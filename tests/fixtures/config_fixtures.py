"""
Configuration fixtures for testing.

Provides various configuration scenarios for testing config loading and validation.
"""

import pytest
from typing import Dict, Any
from pathlib import Path


@pytest.fixture
def minimal_config() -> Dict[str, Any]:
    """Provide minimal valid configuration."""
    return {
        "language": "en",
        "logging_level": "INFO",
    }


@pytest.fixture
def full_config() -> Dict[str, Any]:
    """Provide complete configuration with all options."""
    return {
        "system_plugins": {
            "android": True,
            "gerrit": False,
            "grep": True,
            "navigator": True,
            "repo": True,
            "spider": False,
            "system": True,
        },
        "custom_plugins": {},
        "logging_level": "INFO",
        "language": "zh",
        "show_examples": True,
        "prompt_theme": "bitstream",
        "completion_enabled": True,
        "router_cache_enabled": True,
        "async_execution": True,
        "max_concurrent_executions": 10,
        "default_timeout": 30,
        "parser_config": {
            "enabled": ["python", "shell", "config"],
            "priorities": {
                "python": 100,
                "shell": 50,
                "config": 10,
            },
        },
    }


@pytest.fixture
def invalid_config() -> Dict[str, Any]:
    """Provide invalid configuration for error testing."""
    return {
        "language": "invalid_language",  # Invalid value
        "logging_level": "INVALID",  # Invalid level
        "system_plugins": "not_a_dict",  # Wrong type
    }


@pytest.fixture
def user_config_path(temp_dir: Path) -> Path:
    """Provide path to user config file (doesn't exist by default)."""
    return temp_dir / ".config" / "global-scripts" / "config" / "gs.json"


@pytest.fixture
def project_config_path(temp_dir: Path) -> Path:
    """Provide path to project config file (doesn't exist by default)."""
    return temp_dir / "config" / "gs.json"


@pytest.fixture
def config_with_disabled_plugins() -> Dict[str, Any]:
    """Provide configuration with some plugins disabled."""
    return {
        "system_plugins": {
            "android": False,
            "system": True,
        },
        "language": "en",
    }


@pytest.fixture
def config_with_parser_settings() -> Dict[str, Any]:
    """Provide configuration with parser-specific settings."""
    return {
        "parser_config": {
            "enabled": ["python", "shell"],  # Config parser disabled
            "priorities": {
                "python": 100,
                "shell": 50,
            },
            "custom_paths": [
                "~/custom/parsers",
            ],
        },
        "language": "en",
    }


@pytest.fixture
def config_hierarchy(temp_dir: Path, full_config: Dict[str, Any]) -> Dict[str, Path]:
    """
    Create configuration file hierarchy for testing priority.

    Creates:
    - user config (highest priority)
    - project config (medium priority)
    - default config (lowest priority, built-in)

    Returns dict with paths to each config file.
    """
    import json

    # Create directories
    user_config_dir = temp_dir / ".config" / "global-scripts" / "config"
    user_config_dir.mkdir(parents=True)

    project_config_dir = temp_dir / "config"
    project_config_dir.mkdir(parents=True)

    # User config (overrides everything)
    user_config = {
        "language": "zh",  # Override
        "logging_level": "DEBUG",  # Override
    }
    user_config_path = user_config_dir / "gs.json"
    with open(user_config_path, "w") as f:
        json.dump(user_config, f, indent=2)

    # Project config (overrides defaults)
    project_config = {
        "language": "en",  # Will be overridden by user
        "show_examples": True,
        "system_plugins": {
            "android": True,
        },
    }
    project_config_path = project_config_dir / "gs.json"
    with open(project_config_path, "w") as f:
        json.dump(project_config, f, indent=2)

    return {
        "user": user_config_path,
        "project": project_config_path,
        "temp_dir": temp_dir,
    }
