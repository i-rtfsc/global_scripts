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
User Command → CLI Layer → Command Handler → Application Services → Domain/Infrastructure
              (main.py)   (commands.py)      (PluginService)      (repositories)
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

## Testing

### Test Suite Overview

The project has a comprehensive test suite with **691 tests** achieving **55% code coverage** (baseline was 19%).

**Test Statistics**:
- Unit tests: ~870 tests covering individual components
- Integration tests: 57 tests for component interactions
- E2E tests: 46 tests with 100% pass rate
- Performance tests: 27 benchmarks
- Script tests: 31 tests for setup.py

**Coverage by Layer**:
- Infrastructure: 79-97% ✅ (Excellent)
- Models: 84-100% ✅ (Excellent)
- Security: 87-96% ✅ (Excellent)
- Utilities: 72-98% ✅ (Good)
- Domain: 72-74% ✅ (Good)
- Application: 10-27% ⚠️ (Needs work)
- CLI: 0% ⚠️ (Needs work)

### Running Tests

```bash
# Run all tests (excludes slow tests by default)
pytest tests/ -v

# Run specific test types
pytest tests/unit/ -v              # Unit tests only
pytest tests/integration/ -v       # Integration tests
pytest tests/e2e/ -v              # E2E tests
pytest tests/performance/ -v      # Performance benchmarks

# Run with coverage
pytest tests/ -v --cov=src/gscripts --cov-report=html
# View coverage: open htmlcov/index.html

# Run all tests including slow ones
pytest tests/ -v --run-slow

# Run specific test file
pytest tests/unit/security/test_sanitizers.py -v

# Run specific test
pytest tests/unit/security/test_sanitizers.py::test_sanitize_command_safe -v
```

### Test Markers

Tests are organized with pytest markers:

- `@pytest.mark.unit` - Fast unit tests with mocked dependencies
- `@pytest.mark.integration` - Integration tests with real dependencies
- `@pytest.mark.e2e` - End-to-end workflow tests
- `@pytest.mark.performance` - Performance benchmarks
- `@pytest.mark.slow` - Slow running tests (auto-excluded by default)
- `@pytest.mark.asyncio` - Async tests (handled by pytest-asyncio)

### Test Infrastructure

**Fixtures** (tests/fixtures/):
- `sample_plugins.py` - Sample plugin metadata and content
- `config_fixtures.py` - Configuration fixtures (minimal, full, invalid)
- `filesystem_fixtures.py` - Filesystem fixtures (InMemoryFileSystem, temp dirs)
- `process_fixtures.py` - Process execution mocks

**Factories** (tests/factories/):
- `PluginFactory` - Create plugin test data with defaults and overrides
- `FunctionFactory` - Create function metadata
- `ResultFactory` - Create CommandResult objects

**Helpers** (tests/helpers/):
- `assertions.py` - Custom assertions (assert_command_result_success, etc.)
- `async_helpers.py` - Async test utilities
- `mock_builders.py` - Mock object builders

### Writing Tests

**Example Unit Test**:
```python
import pytest
from gscripts.security.sanitizers import sanitize_command

@pytest.mark.unit
def test_sanitize_command_removes_dangerous_chars():
    """Test command sanitization removes dangerous characters"""
    # Arrange
    dangerous_cmd = "rm -rf /; echo 'hacked'"

    # Act
    result = sanitize_command(dangerous_cmd)

    # Assert
    assert ";" not in result
    assert "hacked" not in result
```

**Example Integration Test**:
```python
import pytest
from tests.factories.plugin_factory import PluginFactory

@pytest.mark.integration
@pytest.mark.asyncio
async def test_plugin_loading_flow(temp_dir):
    """Test complete plugin loading pipeline"""
    # Arrange
    plugin = PluginFactory.create(name="test_plugin", enabled=True)

    # Act
    loader = PluginLoader(plugins_root=temp_dir)
    loaded_plugins = await loader.load_all_plugins()

    # Assert
    assert "test_plugin" in loaded_plugins
```

**Example E2E Test**:
```python
@pytest.mark.e2e
def test_plugin_enable_disable_workflow(e2e_environment):
    """Test complete plugin enable/disable workflow"""
    # Uses real filesystem, no mocks
    plugin_service = PluginService(...)

    # Enable plugin
    result = plugin_service.enable_plugin("android")
    assert result.success

    # Verify enabled in config
    config = load_config()
    assert config["system_plugins"]["android"] is True
```

### Test Best Practices

1. **Use Descriptive Names**: `test_<method>_<scenario>_<expected_result>`
2. **Follow AAA Pattern**: Arrange, Act, Assert
3. **One Assertion Per Test** (when possible)
4. **Use Factories for Test Data**: Don't hardcode test objects
5. **Mock External Dependencies**: File I/O, network, subprocess
6. **Test Both Success and Failure Paths**
7. **Use Appropriate Markers**: @pytest.mark.unit, @pytest.mark.integration
8. **Document Complex Tests**: Add comments explaining non-obvious logic

### Continuous Integration

Tests run automatically on:
- Every push to main/develop/feature branches
- Every pull request
- Multiple OS: Ubuntu, macOS
- Multiple Python versions: 3.8, 3.9, 3.10, 3.11

Coverage reports are uploaded to Codecov and available as artifacts.

### Test Documentation

- **tests/README.md** - Comprehensive testing guide
- **COVERAGE_ANALYSIS.md** - Module-by-module coverage breakdown
- **TEST_SUITE_COMPLETION_REPORT.md** - Complete rebuild documentation

## Additional Resources

- [Plugin Development Guide](docs/plugin-development.md): Comprehensive plugin creation tutorial
- [Architecture Document](docs/architecture.md): Deep dive into system design
- [Contributing Guide](docs/contributing.md): Code standards and PR process
- [CLI Reference](docs/cli-reference.md): Complete command documentation
- [Test Suite Guide](tests/README.md): Detailed testing documentation
- [Menu Bar Guide](docs/menubar-guide.md): macOS menu bar status monitor documentation

## macOS Menu Bar Status Monitor

### Overview

Global Scripts includes a macOS-only menu bar status indicator that provides real-time visibility into command execution and system metrics.

**Platform**: macOS 10.10+ only
**Dependencies**: `rumps>=0.4.0`, `psutil>=5.9.0`

### Features

- **Auto-start**: Automatically launches when GS commands run (if enabled)
- **Command Progress**: Shows command name, progress %, elapsed time
- **Completion Status**: Displays success (✓) or failure (✗) with duration
- **System Metrics**: CPU temperature and memory usage in dropdown
- **IPC Communication**: Unix sockets for CLI → menu bar messaging

### Quick Start

1. **Enable in config** (`~/.config/global-scripts/config/gs.json`):
   ```json
   {
     "menubar": {
       "enabled": true,
       "refresh_interval": 5,
       "show_cpu_temp": true,
       "show_memory": true
     }
   }
   ```

2. **Run any command** - menu bar auto-starts:
   ```bash
   gs android build aosp
   ```

3. **Menu bar shows**: `GS: android.build 45% 2m15s`

### Development Guidelines

#### Adding Progress Reporting to Plugins

Plugin functions can report progress by yielding progress dicts:

```python
@plugin_function(name="download", description={"en": "Download with progress"})
async def download_file(args):
    """Download file and report progress"""
    for i in range(0, 101, 10):
        await asyncio.sleep(0.5)
        yield {"progress": i}  # Sends to menu bar

    return CommandResult(success=True, output="Download complete")
```

**Important**:
- Yield `{"progress": 0-100}` for progress updates
- Final return must be `CommandResult`
- Works with both sync and async generators
- Progress updates sent automatically via IPC

#### Module Structure

```
src/gscripts/menubar/
├── __init__.py          # Platform detection, exports
├── __main__.py          # Entry point (python -m gscripts.menubar)
├── app.py               # MenuBarApp (rumps.App subclass)
├── ipc.py               # IPCServer & IPCClient (Unix sockets)
├── status_manager.py    # CommandStatus dataclass
├── monitors.py          # CPUTemperatureMonitor, MemoryMonitor
└── utils.py             # Process management (start/stop/is_running)
```

#### IPC Protocol

**Socket**: `~/.config/global-scripts/menubar.sock`

**Messages** (JSON over socket):
```json
{"type": "command_start", "command": "plugin.function", "timestamp": 123456.0}
{"type": "progress_update", "percentage": 45, "elapsed": 15.3}
{"type": "command_complete", "success": true, "duration": 1.23, "error": null}
```

#### Integration Points

**1. Auto-start** (`cli/main.py`):
```python
def _ensure_menubar_started(self):
    """Ensure menu bar is running if enabled"""
    from gscripts.menubar.utils import ensure_menubar_running
    config = self.config_manager.config
    ensure_menubar_running(config)
```

**2. Progress Reporting** (`application/services/plugin_executor.py`):
```python
async def _process_generator_result(self, result, start_time):
    """Process generator/async generator with progress reporting"""
    if inspect.isasyncgen(result):
        async for item in result:
            if isinstance(item, dict) and "progress" in item:
                elapsed = time.time() - start_time
                self._send_ipc_progress_update(item["progress"], elapsed)
```

**3. Nested Call Guard**:
- Uses `ContextVar` to track execution depth
- Only top-level commands send IPC (depth == 1)
- Prevents duplicate status for nested calls

#### Testing

**Unit Tests**:
```bash
pytest tests/unit/menubar/ -v
```

**Integration Tests**:
```bash
pytest tests/integration/menubar/ -v
```

**Platform Skip**:
- Tests auto-skip on non-macOS unless `FORCE_MENUBAR_TESTS=1`
- Use `@pytest.mark.skipif(os.sys.platform != "darwin")` decorator

#### Common Patterns

**Check if supported**:
```python
from gscripts.menubar import is_supported

if is_supported():
    # Menu bar available
    pass
```

**Send custom message**:
```python
from gscripts.menubar.ipc import IPCClient

client = IPCClient()
client.send_message({"type": "custom_message", "text": "Status"})
```

**Process management**:
```python
from gscripts.menubar.utils import is_menubar_running, start_menubar, stop_menubar

if not is_menubar_running():
    start_menubar()
```

#### Troubleshooting

- **Menu bar not appearing**: Check platform (macOS only), rumps installed, enabled in config
- **CPU temp shows "N/A"**: Normal on M1/M2 Macs (sensors not exposed)
- **Progress not showing**: Ensure plugin yields `{"progress": int}` dicts
- **IPC errors**: Check socket at `~/.config/global-scripts/menubar.sock`, check logs at `~/.config/global-scripts/logs/menubar.log`

See [Menu Bar Guide](docs/menubar-guide.md) for complete documentation.
