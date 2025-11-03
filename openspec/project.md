# Project Context

## Purpose

Global Scripts V5 is a **modern, high-performance shell command management system** with a plugin-based architecture. It provides a unified CLI interface for managing development tools, automation scripts, and system utilities across multiple environments.

**Core Goals:**
- Zero-dependency shell integration with optional Python enhancement
- Plugin-based extensibility (Python, Shell, JSON Config, Hybrid)
- Async-first execution with type safety
- Multi-language support (Chinese/English i18n)
- Clean architecture with DDD principles

**Target Users:** DevOps engineers, Android developers, system administrators, power users

## Tech Stack

### Core Technologies
- **Python 3.8+**: Core runtime with backward compatibility
- **asyncio**: Asynchronous execution engine
- **UV**: Modern Python dependency manager (replaces pip/poetry)
- **Rich**: Terminal UI and formatted output
- **Jinja2**: Template engine for shell integration (env.sh, completions)
- **PyYAML**: Configuration file parsing
- **aiofiles**: Async file I/O operations

### Development Tools
- **pytest** + **pytest-asyncio**: Testing framework
- **pytest-cov**: Code coverage reporting
- **Black**: Code formatting (line length: 88)
- **Ruff**: Fast Python linter (replaces flake8, isort)
- **MyPy**: Static type checking

### Architecture Pattern
**Clean Architecture** with **Domain-Driven Design** (in migration):
- `cli/`: Presentation layer (CLI interface)
- `application/`: Application services (orchestration)
- `domain/`: Domain entities, value objects, interfaces (⚠️ incomplete)
- `infrastructure/`: External concerns (persistence, execution, filesystem)
- `models/`: Data transfer objects
- `plugins/`: Plugin system (base classes, decorators, parsers)

## Project Conventions

### Code Style

#### Naming Conventions
- **Files**: `snake_case.py` (e.g., `plugin_manager.py`)
- **Classes**: `PascalCase` (e.g., `PluginManager`, `CommandResult`)
- **Interfaces**: `I` prefix (e.g., `IPluginRepository`, `IFileSystem`)
- **Functions/Methods**: `snake_case` (e.g., `load_plugin()`, `execute_command()`)
- **Constants**: `UPPER_SNAKE_CASE` (e.g., `DEFAULT_TIMEOUT`, `SAFE_COMMANDS`)
- **Private members**: `_leading_underscore` (e.g., `_internal_method()`)
- **Async functions**: Always prefix async def, never sync equivalent names

#### Type Annotations (MANDATORY)
```python
# ✅ Required for all public functions/methods
async def execute_plugin(
    self,
    plugin_name: str,
    function_name: str,
    args: List[str] = None
) -> CommandResult:
    ...

# ✅ Return types required
def get_config(self) -> Dict[str, Any]:
    ...

# ❌ Avoid generic dict/list without types
def process_data(data): ...  # WRONG
def process_data(data: Dict[str, Any]) -> List[PluginMetadata]: ...  # CORRECT
```

#### String Formatting
- Use **f-strings** for formatting: `f"Plugin {name} loaded"`
- Use `"""docstrings"""` for multi-line documentation
- Use `'single quotes'` for dict keys, `"double quotes"` for user-facing strings

#### Import Organization
```python
# 1. Standard library
import asyncio
import sys
from pathlib import Path
from typing import List, Dict, Optional

# 2. Third-party
import yaml
from rich.console import Console

# 3. Local application
from gscripts.models import CommandResult
from gscripts.core import PluginManager
from gscripts.plugins.decorators import plugin_function
```

### Architecture Patterns

#### Current State (CRITICAL ISSUES)

**⚠️ Problem: Dual Implementation**
The codebase has TWO parallel plugin systems:
1. **Legacy** (`core/plugin_manager.py`, `core/plugin_loader.py`) - 1600+ lines
2. **New** (`application/services/`, `infrastructure/`) - Clean Architecture

**Status**: Migration 60% complete. New code MUST use Clean Architecture layers.

#### Target Architecture: Clean Architecture + DDD

```
┌─────────────────────────────────────────────────────────┐
│                    CLI Layer (Presentation)              │
│  - cli/main.py: Entry point, async orchestration        │
│  - cli/commands.py: Command routing                     │
│  - cli/formatters.py: Output formatting                 │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────────┐
│              Application Layer (Use Cases)               │
│  - PluginService: Plugin lifecycle management           │
│  - PluginExecutor: Command execution orchestration      │
│  - ConfigService: Configuration management              │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────────┐
│              Domain Layer (Business Logic)               │
│  - entities/: Plugin, Command (rich domain objects)     │
│  - value_objects/: PluginMetadata, FunctionInfo         │
│  - interfaces/: IPluginRepository, IExecutor            │
│  - services/: Domain services (pure business logic)     │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ↓
┌─────────────────────────────────────────────────────────┐
│           Infrastructure Layer (External Concerns)       │
│  - persistence/: PluginRepository, ConfigRepository     │
│  - execution/: ProcessExecutor, ShellExecutor           │
│  - filesystem/: FileSystem abstraction                  │
│  - di/: Dependency injection container                  │
└─────────────────────────────────────────────────────────┘
```

#### Dependency Rules (ENFORCE STRICTLY)
1. **Dependencies point inward**: CLI → Application → Domain ← Infrastructure
2. **Domain layer is independent**: No imports from outer layers
3. **Interfaces in domain**: Infrastructure implements domain interfaces
4. **No circular dependencies**: Use dependency injection to break cycles

#### Current Violations to Fix
```python
# ❌ WRONG: Core importing from infrastructure
# core/plugin_manager.py:191
from ..infrastructure.execution import ProcessExecutor

# ✅ CORRECT: Use dependency injection
# application/services/plugin_service.py
def __init__(self, executor: IProcessExecutor):  # Interface from domain
    self._executor = executor
```

### Async/Sync Policy

#### **Rule: All I/O operations MUST be async**

```python
# ✅ CORRECT: File I/O
import aiofiles

async def load_config(self, path: Path) -> Dict[str, Any]:
    async with aiofiles.open(path, 'r') as f:
        content = await f.read()
        return json.loads(content)

# ❌ WRONG: Sync file I/O in async context
def load_config(self, path: Path) -> Dict[str, Any]:
    with open(path, 'r') as f:  # Blocks event loop!
        return json.load(f)

# ✅ CORRECT: Subprocess execution
async def execute_command(self, cmd: str) -> CommandResult:
    process = await asyncio.create_subprocess_shell(...)
    stdout, stderr = await process.communicate()

# ✅ CORRECT: Concurrent execution
async def load_all_plugins(self) -> List[Plugin]:
    tasks = [self.load_plugin(name) for name in plugin_names]
    return await asyncio.gather(*tasks)
```

**Exceptions where sync is acceptable:**
- Pure computation (no I/O)
- Data structure manipulation
- Logging calls (logger methods are sync)
- Property getters

### Error Handling

#### **Standard Pattern: CommandResult**

```python
from gscripts.models import CommandResult

# ✅ Use for expected operation outcomes
async def enable_plugin(self, name: str) -> CommandResult:
    if name not in self.plugins:
        return CommandResult(
            success=False,
            error=self.i18n.get_message('errors.plugin_not_found', name=name),
            exit_code=1
        )

    try:
        await self._enable_plugin_internal(name)
        return CommandResult(
            success=True,
            output=self.i18n.get_message('plugin.enabled', name=name),
            exit_code=0
        )
    except Exception as e:
        logger.error(f"Failed to enable plugin {name}", exc_info=True)
        return CommandResult(
            success=False,
            error=str(e),
            exit_code=1
        )
```

#### **When to raise exceptions:**
- Programming errors (assertions, type errors)
- Unrecoverable system failures
- Framework/library integration points

#### **When to return CommandResult:**
- User-initiated operations
- Plugin execution
- Configuration changes
- Any CLI command handler

### Testing Strategy

#### Test Structure
```
tests/
├── unit/                    # Fast, isolated tests
│   ├── infrastructure/      # Repository, filesystem tests
│   ├── plugins/parsers/     # Parser unit tests
│   └── ...
├── integration/             # Multi-component tests
│   ├── test_plugin_executor.py
│   └── plugins/
└── manual/                  # Manual verification tests
```

#### Testing Requirements

1. **Unit Tests** (required for new code)
   - Test single units in isolation
   - Use mocks for dependencies
   - Fast execution (< 1s per test)
   - Minimum 80% line coverage

2. **Integration Tests** (required for APIs/workflows)
   - Test component interaction
   - Use real implementations with test fixtures
   - Allowed to be slower (< 5s per test)

3. **Test Naming Convention**
```python
class TestPluginRepository:
    """Tests for PluginRepository"""

    @pytest.mark.asyncio
    async def test_get_all_returns_empty_when_no_plugins(self):
        """Test get_all returns empty list when no plugins exist"""
        ...

    @pytest.mark.asyncio
    async def test_save_creates_plugin_directory(self):
        """Test save creates plugin directory if not exists"""
        ...
```

#### Fixtures and Mocks

**Use DI container for test isolation:**
```python
@pytest.fixture
def test_container() -> Generator[DIContainer, None, None]:
    """Provide test DI container"""
    reset_container()
    container = get_container()
    configure_services(container, use_mocks=True)  # ← Mock implementations
    yield container
    reset_container()

@pytest.fixture
def mock_filesystem(test_container: DIContainer) -> InMemoryFileSystem:
    """Provide mock filesystem"""
    from src.gscripts.domain.interfaces import IFileSystem
    return test_container.resolve(IFileSystem)
```

#### Running Tests
```bash
# All tests
pytest tests/ -v

# Unit tests only (fast)
pytest tests/unit/ -v

# Integration tests
pytest tests/integration/ -v

# With coverage
pytest tests/ -v --cov=src/gscripts --cov-report=term-missing

# Specific test file
pytest tests/unit/infrastructure/test_plugin_repository.py -v

# Watch mode (requires pytest-watch)
ptw tests/unit/
```

### Git Workflow

#### Branching Strategy
- **main**: Production-ready code, protected branch
- **develop**: Integration branch for features
- **feature/\***: Feature branches (e.g., `feature/add-two-factor-auth`)
- **fix/\***: Bug fix branches (e.g., `fix/plugin-loading-race-condition`)
- **refactor/\***: Refactoring branches (e.g., `refactor/consolidate-repositories`)

#### Commit Message Convention

**Format**: `<type>(<scope>): <subject>`

```
feat(multirepo): 重构 sync 命令支持 repo/git 双模式
refactor(cli): 完全迁移至 Rich Table 并优化显示效果
fix(completion): 修正 Fish 补全在 plugin/parser 子命令后的错误提示
docs: 更新文档以反映近期重构成果
chore(config): 优化 Shell 环境检测与配置文件
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `refactor`: Code restructuring (no functional change)
- `docs`: Documentation changes
- `test`: Adding/updating tests
- `chore`: Build process, tooling, dependencies
- `perf`: Performance improvements
- `style`: Code style changes (formatting, whitespace)

**Scopes** (examples):
- `cli`: CLI interface
- `plugins`: Plugin system
- `core`: Core managers/loaders
- `config`: Configuration system
- `multirepo`: Multirepo plugin
- `dotfiles`: Dotfiles plugin

**Subject:**
- Use Chinese or English (project supports both)
- Present tense, imperative mood (English: "add feature" not "added feature")
- No period at the end
- Max 72 characters

#### Pull Request Process
1. Create feature branch from `develop`
2. Implement changes with tests
3. Run full test suite: `pytest tests/ -v --cov`
4. Run linters: `ruff check src/ tests/` and `black src/ tests/`
5. Update documentation if needed
6. Create PR to `develop` (not `main`)
7. Ensure CI passes
8. Code review required
9. Squash merge to `develop`

## Domain Context

### Plugin System Fundamentals

**Plugin Types:**
1. **Python Plugin**: Full Python code with decorators
   - Entry: `plugin.py` with `@plugin_function` decorated methods
   - Use for: Complex logic, API integration, data processing

2. **Shell Plugin**: Bash/Zsh/Fish scripts
   - Entry: `plugin.sh` with `# @plugin_function` annotations
   - Use for: Simple shell commands, wrapper scripts

3. **Config Plugin**: Pure JSON command definitions
   - Entry: `commands.json` with command metadata
   - Use for: Simple command aliases, no logic

4. **Hybrid Plugin**: Combination of above
   - Has `subplugins/` directory with mixed types
   - Use for: Large feature sets (e.g., Android toolkit)

### Plugin Discovery Flow
```
1. Scan plugin directories (plugins/ and custom/)
2. Find plugin.json metadata files
3. Determine plugin type from "type" field
4. Load appropriate parser (Python/Shell/Config)
5. Discover functions via decorators/annotations
6. Build function registry
7. Generate router index for shell integration
```

### Command Execution Flow
```
User: gs android adb devices
  ↓
1. CLI parses: plugin=android, subplugin=adb, function=devices
  ↓
2. Router checks: Is this Shell/Config plugin?
   → Yes: Execute via gs-router (direct shell, fast)
   → No: Use Python PluginExecutor
  ↓
3. PluginExecutor loads plugin module dynamically
  ↓
4. Calls decorated function with args
  ↓
5. Function returns CommandResult
  ↓
6. CLI formats output (Rich tables/text)
```

### i18n System
- All user-facing strings must support Chinese and English
- Message files: `config/messages/zh.json`, `config/messages/en.json`
- Usage: `self.i18n.get_message('key.path', **params)`
- Plugin metadata: `{"description": {"zh": "中文", "en": "English"}}`

## Important Constraints

### Technical Constraints

1. **Python Version**: Must support Python 3.8+ (Ubuntu 20.04 default)
   - Avoid walrus operator `:=` in critical paths
   - Avoid 3.9+ typing features (use `typing.List` not `list[...]`)

2. **Zero System Dependencies**:
   - No required system packages (except Python)
   - Optional features can require tools (git, adb, etc.)
   - Graceful degradation when tools missing

3. **Async Execution**:
   - All I/O must be async to avoid blocking
   - Use `asyncio.gather()` for parallelism
   - Timeout enforcement (default 30s, configurable)

4. **Shell Integration**:
   - Must work in Bash, Zsh, Fish
   - Environment setup via generated `env.sh`/`env.fish`
   - Completions must be shell-specific

5. **Performance**:
   - Plugin discovery: < 500ms for 50 plugins
   - Command execution: < 100ms overhead
   - Shell command routing: < 10ms (direct execution)

### Business Constraints

1. **Backward Compatibility**:
   - Existing user configs must work
   - Plugin API stable (decorators, base classes)
   - Breaking changes require major version bump

2. **Multi-Language Support**:
   - Primary: Chinese (zh)
   - Secondary: English (en)
   - All errors, help text, examples must have both

3. **Plugin Ecosystem**:
   - Built-in plugins under `plugins/`
   - User plugins under `custom/` (not tracked by git)
   - Plugin metadata format is contract

### Security Constraints

1. **Command Whitelist/Blacklist**:
   - `GlobalConstants.SAFE_COMMANDS`: Allowed commands
   - `GlobalConstants.DANGEROUS_COMMANDS`: Blocked (rm -rf, dd, etc.)
   - Validation before execution

2. **Argument Sanitization**:
   - Use `shlex.quote()` for shell arguments
   - No eval() or exec() on user input
   - Path traversal prevention

3. **Timeout Enforcement**:
   - All subprocess calls must have timeout
   - Default 30s, configurable per command
   - Proper process cleanup on timeout

## External Dependencies

### Required Dependencies (in pyproject.toml)
- **PyYAML**: System config loading (`system_config.yaml`)
- **Jinja2**: Template engine for env.sh/env.fish generation
- **aiofiles**: Async file I/O (with sync fallback)
- **Rich**: Terminal UI and formatted output

### Optional System Tools (graceful degradation)
- **git**: For git/gerrit plugins
- **repo**: For multirepo plugin
- **adb**: For android plugin
- **docker**: For container plugins

### Development Dependencies
- pytest, pytest-asyncio, pytest-cov
- black, ruff, mypy
- UV for dependency management

### Environment Variables
- `GS_HOME`: Global Scripts installation directory (default: `~/.config/global-scripts`)
- `GS_CONFIG`: Config file path override
- `GS_LOG_LEVEL`: Logging level (DEBUG, INFO, WARNING, ERROR)
- `GS_LANGUAGE`: Language override (zh, en)

## Migration Roadmap (CRITICAL)

### Current Architecture Issues

**Priority 1: Resolve Dual Implementation**
- **Problem**: Both `core/` and `application/infrastructure/` exist
- **Decision needed**: Complete Clean Architecture migration or rollback
- **Recommendation**: Complete migration (better long-term)
- **Effort**: 2-3 weeks

**Priority 2: Fix Layer Violations**
- Move logger to `infrastructure/logging/`
- Move plugin interfaces to `domain/interfaces/`
- Remove `core/` imports from infrastructure
- Effort: 1 week

**Priority 3: Consolidate Duplicates**
- Merge `utils/process_executor.py` → `infrastructure/execution/`
- Remove `core/config_repository.py`, use infrastructure version
- Eliminate `SimplePlugin`, use `PluginMetadata` everywhere
- Effort: 1 week

**Priority 4: Complete Domain Layer**
- Implement rich domain entities (not anemic models)
- Add domain services for business logic
- Add value objects with validation
- Effort: 1-2 weeks

### New Code Guidelines

**Until migration completes:**
1. ✅ **DO**: Use Clean Architecture layers for new features
2. ✅ **DO**: Add tests with DI container and mocks
3. ✅ **DO**: Follow async-first pattern
4. ❌ **DON'T**: Extend `core/plugin_manager.py` or `core/plugin_loader.py`
5. ❌ **DON'T**: Create new utils that import from core
6. ❌ **DON'T**: Add dependencies from domain → infrastructure

**Refactoring policy:**
- Bug fixes: Fix in place (legacy or new architecture)
- New features: MUST use Clean Architecture
- Performance issues: Refactor affected area to new architecture first
