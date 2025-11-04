<!-- OPENSPEC:START -->
# OpenSpec Instructions

These instructions are for AI assistants working in this project.

Always open `@/openspec/AGENTS.md` when the request:
- Mentions planning or proposals (words like proposal, spec, change, plan)
- Introduces new capabilities, breaking changes, architecture shifts, or big performance/security work
- Sounds ambiguous and you need the authoritative spec before coding

Use `@/openspec/AGENTS.md` to learn:
- How to create and apply change proposals
- Spec format and conventions
- Project structure and guidelines

Keep this managed block so 'openspec update' can refresh the instructions.

<!-- OPENSPEC:END -->

# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Global Scripts is a modern, high-performance shell command management system with a plugin-based architecture. It supports Python, Shell, Config (JSON), and Hybrid plugin types with async execution and type safety.

**Version**: 5.0.0
**Tech Stack**: Python 3.8+, asyncio, UV dependency management
**Architecture**: Clean architecture with Domain-Driven Design principles

## Essential Commands

### Development Setup

```bash
# Install UV and sync dependencies
curl -LsSf https://astral.sh/uv/install.sh | sh
uv sync

# Run setup/installation
uv run python scripts/setup.py

# Reload environment
source ~/.bashrc  # or ~/.zshrc or ~/.config/fish/config.fish
```

### Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test types
pytest tests/unit/ -v
pytest tests/integration/ -v

# Run with coverage
pytest tests/ -v --cov=src/gscripts --cov-report=term-missing

# Run specific test file
pytest tests/unit/infrastructure/test_plugin_repository.py -v
```

### Code Quality

```bash
# Format code (Black)
black src/ tests/

# Lint (Ruff)
ruff check src/ tests/
ruff check --fix src/ tests/

# Type checking (MyPy)
mypy src/

# Run pre-commit hooks
pre-commit install
pre-commit run --all-files
```

### Running Commands

```bash
# Main CLI entry point
gs help
gs version
gs status
gs doctor

# Plugin management
gs plugin list
gs plugin info <plugin_name>
gs plugin enable <plugin_name>
gs plugin disable <plugin_name>

# Execute plugin commands
gs <plugin> <subplugin> <function> [args]
```

## Architecture Overview

**Note**: Clean Architecture migration completed as of Phase 3 (Nov 2024). The legacy `core/plugin_manager.py` and `core/plugin_loader.py` have been removed.

### Core Execution Flow

```
User Command → CLI Layer → Command Handler → Adapter → Application Services → Domain/Infrastructure
              (main.py)   (commands.py)      (adapter)   (PluginService)      (repositories)
```

### Clean Architecture Layers

1. **CLI Layer** (`src/gscripts/cli/`)
   - `main.py`: Entry point, argument parsing, async event loop initialization
   - `commands.py`: Command routing and delegation
   - `formatters.py`: Output formatting with i18n support
   - `command_classes/`: Individual command implementations

2. **Application Layer** (`src/gscripts/application/`)
   - `services/plugin_service.py`: Plugin lifecycle management (load, enable, disable, health checks)
   - `services/plugin_executor.py`: Safe plugin execution with validation and timeout control
   - `services/config_service.py`: Configuration management
   - Orchestrates domain logic and coordinates infrastructure

3. **Domain Layer** (`src/gscripts/domain/`)
   - `interfaces/`: Contracts (IPluginLoader, IPluginRepository, IFileSystem)
   - Pure business logic, no dependencies on outer layers
   - Defines plugin models and rules

4. **Infrastructure Layer** (`src/gscripts/infrastructure/`)
   - `adapters/plugin_manager_adapter.py`: Legacy API compatibility adapter
   - `persistence/plugin_loader.py`: Plugin discovery and loading implementation
   - `persistence/plugin_repository.py`: Plugin data access
   - `execution/process_executor.py`: Subprocess execution
   - `filesystem/`: File system operations
   - Implements domain interfaces

5. **Core Layer** (`src/gscripts/core/`) - **Transitional, being phased out**
   - `config_manager.py`: Configuration loading (user > project > defaults)
   - `command_executor.py`: Safe command execution with whitelist/blacklist
   - `constants.py`: Global constants and configuration
   - `logger.py`: Logging setup and utilities
   - `router/indexer.py`: Builds command routing index for shell integration

6. **Models Layer** (`src/gscripts/models/`)
   - `result.py`: `CommandResult` dataclass for unified return values
   - `plugin.py`: `PluginMetadata` and `PluginType` enum
   - `function.py`: `FunctionInfo` for plugin function metadata

7. **Plugin System** (`src/gscripts/plugins/`)
   - `base.py`: `BasePlugin` and `BaseSubPlugin` base classes
   - `decorators.py`: `@plugin_function` and `@subplugin` decorators
   - `parsers/`: Python, Shell, and Config parsers for plugin discovery
   - `discovery.py`: Plugin file scanning and validation
   - `loader.py`: RefactoredPluginLoader for coordinated plugin loading

### Plugin Types

1. **Python Plugins** (recommended for complex logic)
   - Use `@plugin_function` decorator
   - Async execution support
   - Full access to Python ecosystem
   - Example: `plugins/android/plugin.py`

2. **Shell Plugins** (for shell script integration)
   - Direct execution without Python overhead
   - Use shell annotations: `# @plugin_function`
   - Example: `plugins/grep/plugin.sh`

3. **Config Plugins** (simplest, for command wrappers)
   - Pure JSON configuration
   - No code required
   - Example: `plugins/navigator/commands.json`

4. **Hybrid Plugins** (mix all types)
   - Combines Python, Shell, and Config
   - Use `subplugins` for organization
   - Example: `plugins/system/`

### Configuration System

**Priority**: User config (`~/.config/global-scripts/config/gs.json`) > Project config (`./config/gs.json`) > Defaults

**Key Config Structure**:
```json
{
  "system_plugins": {
    "android": true,
    "gerrit": false
  },
  "custom_plugins": {
    "myplugin": true
  },
  "logging_level": "INFO",
  "language": "zh",
  "show_examples": false,
  "prompt_theme": "bitstream"
}
```

### Router Index & Shell Integration

The system generates a `router.json` index that enables:
- Direct shell execution for Shell and Config plugins (bypassing Python)
- Command routing based on plugin type
- Dynamic shell completion

**Router Flow**:
```
gs command → Check router.json → Route by type:
  - "json": Execute in current shell (eval)
  - "shell": Call gs-router script
  - "python": Use Python CLI
```

## Critical Implementation Details

### Plugin Discovery

1. Scans `plugins/` and `custom/` directories recursively
2. Identifies plugins by presence of `plugin.json` or `plugin.py`
3. Parses metadata, functions, and subplugin structure
4. Builds unified plugin registry

### Async Execution

- All plugin execution is async (uses `asyncio`)
- Command executor uses subprocess with timeout control
- Semaphore limits concurrent execution
- Process groups for proper cleanup

### Security Model

- **Whitelist**: `GlobalConstants.SAFE_COMMANDS` defines allowed commands
- **Blacklist**: `GlobalConstants.DANGEROUS_COMMANDS` blocks dangerous operations
- **Timeout**: Default 30s, configurable
- **Argument escaping**: Uses `shlex.quote` to prevent injection

### Logging System

- Centralized logging in `~/.config/global-scripts/logs/gs.log`
- Structured logging with correlation IDs
- Utilities in `utils/logging_utils.py`: `redact()`, `correlation_id()`, `duration()`, `sanitize_path()`
- Tag-based logger creation: `get_logger(tag="CORE.PLUGIN_MANAGER")`

## Common Development Patterns

### Creating a Python Plugin

```python
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).resolve().parents[2]
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from gscripts.plugins.base import BasePlugin
from gscripts.plugins.decorators import plugin_function
from gscripts.models import CommandResult

class MyPlugin(BasePlugin):
    def __init__(self):
        self.name = "myplugin"

    @plugin_function(
        name="myfunction",
        description={"zh": "中文描述", "en": "English description"},
        usage="gs myplugin myfunction <arg>",
        examples=["gs myplugin myfunction example"]
    )
    async def my_function(self, args: List[str] = None) -> CommandResult:
        # Implementation
        return CommandResult(
            success=True,
            output="Result",
            exit_code=0
        )
```

### Plugin JSON Structure

```json
{
  "name": "myplugin",
  "version": "1.0.0",
  "author": "Author Name",
  "description": {
    "zh": "中文描述",
    "en": "English description"
  },
  "type": "python",
  "entry": "plugin.py",
  "enabled": true,
  "subplugins": [
    {
      "name": "subplugin",
      "type": "python",
      "entry": "subplugin.py",
      "description": {"zh": "子插件", "en": "Subplugin"}
    }
  ]
}
```

### Testing a Plugin

```python
import pytest
from gscripts.core.plugin_loader import PluginLoader
from gscripts.core.plugin_manager import PluginManager

@pytest.mark.asyncio
async def test_my_plugin():
    loader = PluginLoader("plugins")
    plugins = await loader.load_all_plugins()

    assert "myplugin" in plugins
    plugin = plugins["myplugin"]
    assert "myfunction" in plugin.functions
```

## Important Conventions

1. **Type Annotations**: All public functions must have type annotations
2. **Async First**: Prefer async functions for I/O operations
3. **CommandResult**: Always return `CommandResult` from plugin functions
4. **Error Handling**: Use try/except and return `CommandResult(success=False, error=...)`
5. **Logging**: Use correlation IDs and structured logging
6. **I18n**: Support both Chinese and English in descriptions

## File Structure

```
global_scripts-v5/
├── src/gscripts/          # Core source code
│   ├── cli/               # CLI interface
│   ├── core/              # Core modules (managers, loaders, executors)
│   ├── models/            # Data models (CommandResult, PluginMetadata, etc.)
│   ├── plugins/           # Plugin system (base, decorators, parsers)
│   ├── router/            # Command routing and indexing
│   ├── shell_completion/  # Dynamic completion generation
│   └── utils/             # Utilities (logging, i18n, process execution)
├── plugins/               # Built-in plugins
│   ├── android/           # Android development tools
│   ├── system/            # System management
│   ├── grep/              # Search utilities
│   └── spider/            # Web scraping
├── custom/                # User custom plugins (not tracked by git)
├── tests/                 # Test suite
│   ├── unit/              # Unit tests
│   └── integration/       # Integration tests
├── scripts/               # Installation and setup scripts
│   └── setup.py           # Main installation script
├── config/                # Project-level configuration
│   └── gs.json            # Default config
├── themes/                # Shell prompt themes
└── docs/                  # Documentation (Chinese and English)
```

## Key Files to Understand

- `src/gscripts/cli/main.py`: CLI entry point and async orchestration
- `src/gscripts/core/plugin_manager.py`: Plugin lifecycle management
- `src/gscripts/core/plugin_loader.py`: Plugin discovery and parsing logic
- `src/gscripts/plugins/parsers/`: How different plugin types are parsed
- `src/gscripts/router/indexer.py`: Command routing index generation
- `scripts/setup.py`: Installation logic, env generation, completion generation

## Troubleshooting

- **Plugin not loading**: Check `plugin.json` format, ensure `name` field matches directory
- **Function not found**: Verify `@plugin_function` decorator and router index regeneration (`gs refresh`)
- **Import errors**: Ensure project root is in `sys.path` (see plugin template above)
- **Completion not working**: Run `uv run python scripts/setup.py` to regenerate
- **Permission errors**: Check file permissions on `env.sh` and plugin directories

## Additional Resources

- [Plugin Development Guide](docs/plugin-development.md): Comprehensive plugin creation tutorial
- [Architecture Document](docs/architecture.md): Deep dive into system design
- [Contributing Guide](docs/contributing.md): Code standards and PR process
- [CLI Reference](docs/cli-reference.md): Complete command documentation
