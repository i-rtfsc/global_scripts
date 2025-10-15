# Architecture Design

Detailed system architecture of Global Scripts.

## System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI Layer                             │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐ │
│  │  main.py     │  │ commands.py   │  │ formatters.py    │ │
│  └──────────────┘  └───────────────┘  └──────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                        Core Layer                            │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐ │
│  │ Plugin       │  │ Config        │  │ Command          │ │
│  │ Manager      │  │ Manager       │  │ Executor         │ │
│  └──────────────┘  └───────────────┘  └──────────────────┘ │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐ │
│  │ Plugin       │  │ Router        │  │ Logger           │ │
│  │ Loader       │  │ Indexer       │  │                  │ │
│  └──────────────┘  └───────────────┘  └──────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                       Models Layer (NEW)                     │
│  ┌──────────────┐  ┌───────────────┐  ┌──────────────────┐ │
│  │ CommandResult│  │ PluginMetadata│  │ FunctionInfo     │ │
│  └──────────────┘  └───────────────┘  └──────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                            │
┌─────────────────────────────────────────────────────────────┐
│                      Plugin Layer                            │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌──────────────┐  │
│  │ Python  │  │  Shell  │  │ Config  │  │   Hybrid     │  │
│  │ Plugins │  │ Plugins │  │ Plugins │  │   Plugins    │  │
│  └─────────┘  └─────────┘  └─────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. CLI Layer (`src/gscripts/cli/`)

#### main.py
- **Responsibility**: CLI entry point, argument parsing
- **Key Class**: `GlobalScriptsCLI`
- **Workflow**:
  1. Initialize configuration and plugin manager
  2. Parse command-line arguments
  3. Route to corresponding handler
  4. Format and output results

#### commands.py
- **Responsibility**: Command processing logic
- **Key Class**: `CommandHandler`
- **Supported Command Types**:
  - System commands (`help`, `version`, `status`)
  - Plugin management commands (`plugin list/info/enable/disable`)
  - Plugin function commands (`<plugin> <subplugin> <function>`)

#### formatters.py
- **Responsibility**: Output formatting
- **Key Class**: `OutputFormatter`
- **Features**:
  - Table formatting (supports Chinese character width calculation)
  - Multi-language output
  - Color highlighting

### 2. Core Layer (`src/gscripts/core/`)

#### plugin_manager.py
- **Responsibility**: Plugin lifecycle management
- **Key Features**:
  - Plugin loading and unloading
  - Plugin enable/disable
  - Function execution dispatching
  - Health checks

**Main Methods**:
```python
async def initialize()  # Initialize plugin system
async def load_all_plugins()  # Load all plugins
async def execute_plugin_function()  # Execute plugin function
def enable_plugin()  # Enable plugin
def disable_plugin()  # Disable plugin
```

#### plugin_loader.py
- **Responsibility**: Plugin discovery and parsing
- **Key Features**:
  - Scan plugin directories
  - Parse plugin.json
  - Parse Python decorators
  - Parse Shell annotations
  - Build function index

**Plugin Type Identification**:
1. Python plugins: Contains `plugin.py`, uses `@plugin_function` decorator
2. Shell plugins: Contains `.sh` files, uses Shell annotations
3. Config plugins: Only `plugin.json`, contains `commands` field
4. Hybrid plugins: Mixed use of above types

#### config_manager.py
- **Responsibility**: Configuration management
- **Configuration Priority**:
  1. User configuration (`~/.config/global-scripts/config/gs.json`)
  2. Project configuration (`./config/gs.json`)
  3. Default configuration

**Configuration Structure** (new version):
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
  "show_examples": false
}
```

#### command_executor.py
- **Responsibility**: Safe command execution
- **Security Mechanisms**:
  - Command whitelist checking
  - Dangerous command blacklist
  - Timeout control
  - Process group management
- **Concurrency Control**: Semaphore limits concurrent execution

#### router/indexer.py
- **Responsibility**: Build command routing index
- **Index Structure**:
```json
{
  "version": "2.0",
  "plugins": {
    "plugin_name": {
      "commands": {
        "command_key": {
          "kind": "shell|json|python",
          "entry": "/path/to/file",
          "command": "template"
        }
      }
    }
  }
}
```

### 3. Models Layer (`src/gscripts/models/`) ✨ NEW

Unified data structure definitions to improve type safety.

#### result.py
```python
@dataclass
class CommandResult:
    success: bool
    output: str
    error: str
    exit_code: int
    execution_time: float
    metadata: Dict[str, Any]
```

#### plugin.py
```python
@dataclass
class PluginMetadata:
    name: str
    version: str
    author: str
    description: Union[str, Dict[str, str]]
    enabled: bool
    ...

class PluginType(Enum):
    PYTHON = "python"
    SHELL = "shell"
    CONFIG = "config"
    HYBRID = "hybrid"
```

#### function.py
```python
@dataclass
class FunctionInfo:
    name: str
    description: Union[str, Dict[str, str]]
    type: FunctionType
    command: Optional[str]
    python_file: Optional[Path]
    ...
```

### 4. Plugin Layer (`src/gscripts/plugins/`)

#### base.py
- Plugin base class `BasePlugin`
- Subplugin base class `BaseSubPlugin`

#### decorators.py
- `@plugin_function`: Mark Python function as plugin command
- `@subplugin`: Mark class as subplugin

## Data Flow

### Command Execution Flow

```
User Input: gs android logcat clear
    │
    ├─> CLI parses arguments: ['android', 'logcat', 'clear']
    │
    ├─> CommandHandler dispatches
    │   ├─ Identifies as plugin command
    │   └─ Calls plugin_manager.execute_plugin_function()
    │
    ├─> PluginManager executes
    │   ├─ Find plugin: 'android'
    │   ├─ Find function: 'logcat-clear'
    │   ├─ Determine type: shell|python|config
    │   └─ Call corresponding executor
    │
    ├─> Executor runs
    │   ├─ Security check (CommandExecutor)
    │   ├─ Execute command/function
    │   └─ Return CommandResult
    │
    └─> Output formatting
        ├─ OutputFormatter formats
        ├─ Apply multi-language
        └─ Terminal display
```

### Plugin Loading Flow

```
System Startup
    │
    ├─> PluginManager.initialize()
    │
    ├─> PluginLoader.load_all_plugins()
    │   ├─ Scan plugins/ directory
    │   ├─ Scan custom/ directory
    │   ├─ (Optional) Scan examples/ directory
    │   │
    │   └─ For each plugin directory:
    │       ├─ Read plugin.json
    │       ├─ Create PluginMetadata
    │       ├─ Scan functions:
    │       │   ├─ Python functions (decorators)
    │       │   ├─ Shell functions (annotations)
    │       │   └─ Config functions (JSON)
    │       └─ Create SimplePlugin object
    │
    ├─> Load plugin enable status (from config)
    │
    └─> Generate Router Index (for shell dispatching)
```

## Configuration System

### Configuration Loading Priority

```
1. User Configuration (~/.config/global-scripts/config/gs.json)
   │
   ├─ Exists → Use as override layer
   │
2. Project Configuration (./config/gs.json)
   │
   ├─ Exists → Use as base layer
   │
3. Default Configuration (code-generated)
   │
   └─ Use as fallback
```

### Configuration Merge Rules

- `system_plugins` / `custom_plugins`: Key-level merge
- Other fields: User configuration overrides project configuration
- Automatically clean up non-existent plugin entries

## Security Model

### Command Execution Security

1. **Whitelist Mechanism**
   - `GlobalConstants.SAFE_COMMANDS` defines allowed commands
   - Only commands in whitelist can be executed

2. **Blacklist Mechanism**
   - `GlobalConstants.DANGEROUS_COMMANDS` dangerous command list
   - `GlobalConstants.FORBIDDEN_PATTERNS` dangerous patterns
   - Regex matching intercepts dangerous operations

3. **Timeout Control**
   - Default 30-second timeout
   - Configurable via settings
   - Automatically terminates process group on timeout

4. **Parameter Escaping**
   - Use `shlex.quote` to escape all parameters
   - Prevent command injection attacks

### Process Management

- Use `os.setsid` to create new process group
- Terminate entire process group on timeout
- Two-level termination: SIGTERM + SIGKILL

## Extension Points

### How to Add a New Plugin Type

1. Add new `PluginType` in `models/plugin.py`
2. Add scanning logic in `plugin_loader.py`
3. Add execution logic in `plugin_manager.py`
4. Update `router/indexer.py` to support routing

### How to Add a New System Command

1. Add handler method in `CommandHandler` in `cli/commands.py`
2. Add multi-language descriptions in `config/i18n.json`
3. Update completion script generation logic

## Performance Optimization

### Current Optimizations
- Asynchronous I/O (asyncio)
- Concurrent execution (Semaphore)
- Lazy loading (plugins loaded on demand)

### Planned Optimizations
- ✅ Unified data structures (reduce Dict[str, Any])
- ⏳ Plugin configuration caching (`@lru_cache`)
- ⏳ Concurrent plugin loading
- ⏳ ProcessExecutor reuse

## Design Principles

1. **Single Responsibility**: Each module has clear responsibility
2. **Dependency Injection**: Inject dependencies through constructors
3. **Interface Segregation**: Use abstract base classes to define interfaces
4. **Open/Closed Principle**: Open for extension, closed for modification
5. **Type Safety**: Use dataclasses and type annotations

## Tech Stack

- **Language**: Python 3.7+
- **Async**: asyncio
- **Types**: typing, dataclasses
- **Configuration**: JSON
- **Logging**: logging (custom format)
- **Shell**: Bash/Zsh completion

## Next Steps

- [Plugin Development Guide](./plugin-development.md) - How to develop plugins
- [API Documentation](./api-reference.md) - Detailed API documentation
- [Data Structures](./data-structures.md) - Data structure details
