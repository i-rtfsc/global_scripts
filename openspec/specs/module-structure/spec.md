# Module Structure Specification

## Purpose

This specification defines the directory structure, module organization, and file placement rules for Global Scripts V5.

## Requirements

### Requirement: Root Directory Structure

The system SHALL organize source code and configuration files in a standard project layout.

#### Scenario: Source code is under src/
- **WHEN** examining the project root
- **THEN** all Python source code MUST be under `src/gscripts/`
- **AND** plugins MUST be under `plugins/` at project root
- **AND** user custom plugins MUST be under `custom/` (git-ignored)
- **AND** tests MUST be under `tests/` at project root

#### Scenario: Configuration is separated
- **WHEN** organizing configuration files
- **THEN** project config MUST be in `config/` directory
- **AND** message files MUST be in `config/messages/` (zh.json, en.json)
- **AND** themes MUST be in `themes/` directory
- **AND** user config MUST be in `~/.config/global-scripts/`

#### Scenario: Documentation is organized
- **WHEN** adding documentation
- **THEN** documentation MUST be in `docs/` directory
- **AND** README.md MUST be at project root
- **AND** CLAUDE.md MUST be at project root for AI guidance
- **AND** OpenSpec files MUST be in `openspec/` directory

### Requirement: Core Module Structure

The src/gscripts/ directory SHALL be organized into Clean Architecture layers.

#### Scenario: Layer directories exist
- **WHEN** examining src/gscripts/
- **THEN** cli/ directory MUST exist for presentation layer
- **AND** application/ directory MUST exist for application services
- **AND** domain/ directory MUST exist for domain logic
- **AND** infrastructure/ directory MUST exist for external concerns
- **AND** models/ directory MUST exist for data transfer objects
- **AND** plugins/ directory MUST exist for plugin system

#### Scenario: CLI layer structure
- **WHEN** organizing CLI code
- **THEN** cli/main.py MUST be the entry point
- **AND** cli/commands.py MUST handle command routing
- **AND** cli/formatters.py MUST handle output formatting
- **AND** cli/command_classes/ MUST contain command implementations

#### Scenario: Application layer structure
- **WHEN** organizing application services
- **THEN** application/services/ MUST contain service classes
- **AND** each service MUST be in its own file (e.g., `plugin_service.py`)
- **AND** services MUST orchestrate use cases
- **AND** services MUST NOT contain business logic

#### Scenario: Domain layer structure
- **WHEN** organizing domain code
- **THEN** domain/entities/ MUST contain rich domain entities
- **AND** domain/value_objects/ MUST contain value objects with validation
- **AND** domain/services/ MUST contain domain services
- **AND** domain/interfaces/ MUST contain interface definitions (repositories, services)

#### Scenario: Infrastructure layer structure
- **WHEN** organizing infrastructure code
- **THEN** infrastructure/persistence/ MUST contain repository implementations
- **AND** infrastructure/execution/ MUST contain process/command executors
- **AND** infrastructure/filesystem/ MUST contain filesystem abstractions
- **AND** infrastructure/logging/ MUST contain logging implementations
- **AND** infrastructure/di/ MUST contain dependency injection container

### Requirement: Plugin Directory Structure

Plugin directories SHALL follow a consistent structure for all plugin types.

#### Scenario: Plugin has metadata file
- **WHEN** creating a plugin
- **THEN** plugin directory MUST contain plugin.json with metadata
- **AND** plugin.json MUST define name, version, author, description, type
- **AND** plugin.json MUST specify enabled status
- **AND** plugin.json MAY specify subplugins array

#### Scenario: Python plugin structure
- **WHEN** creating a Python plugin
- **THEN** plugin directory MUST contain plugin.py as entry point
- **AND** plugin.py MUST define a class inheriting from BasePlugin
- **AND** plugin.py MUST use @plugin_function decorator for functions
- **AND** plugin MAY have additional modules in the directory

#### Scenario: Shell plugin structure
- **WHEN** creating a Shell plugin
- **THEN** plugin directory MUST contain plugin.sh as entry point
- **AND** plugin.sh MUST use `# @plugin_function` annotations
- **AND** plugin.sh MUST define shell functions
- **AND** plugin.sh MUST be executable (chmod +x)

#### Scenario: Config plugin structure
- **WHEN** creating a Config plugin
- **THEN** plugin directory MUST contain commands.json
- **AND** commands.json MUST define command metadata
- **AND** each command MUST specify name, description, command template
- **AND** commands MUST NOT contain complex logic

#### Scenario: Hybrid plugin structure
- **WHEN** creating a Hybrid plugin
- **THEN** plugin directory MUST contain subplugins/ directory
- **AND** each subplugin MUST be in its own subdirectory
- **AND** each subplugin MUST have its own plugin.json
- **AND** parent plugin.json MUST list subplugins

### Requirement: Test Directory Structure

The tests/ directory SHALL be organized to mirror source code structure.

#### Scenario: Test organization mirrors source
- **WHEN** organizing tests
- **THEN** tests/unit/ MUST contain unit tests
- **AND** tests/integration/ MUST contain integration tests
- **AND** tests/manual/ MAY contain manual verification tests
- **AND** test directory structure SHOULD mirror src/gscripts/ structure

#### Scenario: Test files are discoverable
- **WHEN** naming test files
- **THEN** test files MUST start with `test_` prefix
- **AND** test files MUST have .py extension
- **AND** test classes MUST start with `Test` prefix
- **AND** test methods MUST start with `test_` prefix

#### Scenario: Test fixtures are centralized
- **WHEN** defining test fixtures
- **THEN** shared fixtures MUST be in tests/conftest.py
- **AND** module-specific fixtures MAY be in module conftest.py
- **AND** fixtures MUST be properly scoped (function, module, session)

#### Scenario: Test data is organized
- **WHEN** using test data files
- **THEN** test data MUST be in tests/fixtures/ or tests/data/
- **AND** test data MUST be committed to git (unless large)
- **AND** temporary test files MUST use pytest tmp_path fixtures

### Requirement: Configuration File Placement

Configuration files SHALL be placed in appropriate locations based on scope.

#### Scenario: Project configuration location
- **WHEN** defining project-level configuration
- **THEN** config/gs.json MUST contain default configuration
- **AND** config/messages/ MUST contain i18n message files
- **AND** config MUST NOT contain user-specific settings

#### Scenario: User configuration location
- **WHEN** storing user-specific configuration
- **THEN** user config MUST be in `~/.config/global-scripts/config/gs.json`
- **AND** user logs MUST be in `~/.config/global-scripts/logs/`
- **AND** user plugins MUST be in `custom/` directory
- **AND** user configuration MUST override project defaults

#### Scenario: Environment-specific configuration
- **WHEN** handling environment variables
- **THEN** environment setup MUST generate env.sh and env.fish
- **AND** generated files MUST be in `~/.config/global-scripts/`
- **AND** shell completion files MUST be installed to shell-specific locations

### Requirement: Import Path Organization

Module imports SHALL follow consistent patterns across the codebase.

#### Scenario: Absolute imports from project root
- **WHEN** importing modules
- **THEN** imports MUST use absolute paths from gscripts package
- **AND** imports MUST use full qualified names (e.g., `from gscripts.core import PluginManager`)
- **AND** relative imports SHOULD be avoided except within same package

#### Scenario: Layer boundaries respected in imports
- **WHEN** importing across layers
- **THEN** CLI MAY import from application, domain, infrastructure
- **AND** application MAY import from domain, infrastructure
- **AND** domain MUST NOT import from any other layer
- **AND** infrastructure MAY only import from domain (for interfaces)

#### Scenario: Circular imports prevented
- **WHEN** structuring imports
- **THEN** import graph MUST be acyclic (no circular dependencies)
- **AND** TYPE_CHECKING block MUST be used for type-only imports when needed
- **AND** dependency injection MUST be used to break potential cycles

### Requirement: Utils and Shared Code Organization

Utility code SHALL be organized to avoid tight coupling and maintain reusability.

#### Scenario: Utils are layer-independent
- **WHEN** creating utility modules
- **THEN** utils/ MUST NOT import from core/, application/, or infrastructure/
- **AND** utils/ MUST only use standard library and typing
- **AND** utils/ SHOULD be pure functions when possible

#### Scenario: Shared utilities categorized
- **WHEN** organizing utils/
- **THEN** file utilities MUST be in utils/file_utils.py
- **AND** i18n utilities MUST be in utils/i18n.py
- **AND** logging utilities MUST be in utils/logging_utils.py
- **AND** each utility module MUST have single, clear purpose

#### Scenario: Constants are centralized
- **WHEN** defining constants
- **THEN** global constants MUST be in core/constants.py or utils/constants.py
- **AND** layer-specific constants MAY be in layer's constants.py
- **AND** constants MUST be UPPER_SNAKE_CASE
- **AND** magic numbers MUST be replaced with named constants

### Requirement: Generated Files Organization

Generated files SHALL be organized separately from source code and excluded from version control.

#### Scenario: Generated files location
- **WHEN** generating files programmatically
- **THEN** router.json MUST be in `~/.config/global-scripts/`
- **AND** env.sh and env.fish MUST be in `~/.config/global-scripts/`
- **AND** completion scripts MUST be installed to shell-specific locations
- **AND** generated files MUST be excluded from git

#### Scenario: Build artifacts location
- **WHEN** building the project
- **THEN** Python bytecode (.pyc) MUST be in `__pycache__/` directories
- **AND** distribution files MUST be in `dist/` directory
- **AND** build metadata MUST be in `.egg-info/` directory
- **AND** all build artifacts MUST be git-ignored

#### Scenario: Cache files location
- **WHEN** caching data
- **THEN** cache files MUST be in `~/.config/global-scripts/cache/`
- **AND** cache MUST be invalidated appropriately
- **AND** cache MUST NOT be committed to git

### Requirement: Documentation Structure

Documentation SHALL be organized by audience and purpose.

#### Scenario: User documentation structure
- **WHEN** writing user documentation
- **THEN** README.md MUST provide quick start guide
- **AND** docs/user-guide/ MUST contain detailed user documentation
- **AND** docs/plugin-development.md MUST guide plugin authors
- **AND** documentation MUST support both Chinese and English

#### Scenario: Developer documentation structure
- **WHEN** writing developer documentation
- **THEN** docs/architecture.md MUST describe system architecture
- **AND** docs/contributing.md MUST explain contribution process
- **AND** CLAUDE.md MUST provide AI assistant guidance
- **AND** openspec/ MUST contain formal specifications

#### Scenario: API documentation structure
- **WHEN** documenting APIs
- **THEN** docs/cli-reference.md MUST document CLI commands
- **AND** docs/api-reference.md MUST document Python API
- **AND** code docstrings MUST be comprehensive
- **AND** examples MUST be provided for complex APIs

### Requirement: Version Control Organization

Git repository SHALL organize files with appropriate ignore patterns.

#### Scenario: Gitignore patterns configured
- **WHEN** configuring version control
- **THEN** .gitignore MUST exclude `__pycache__/` directories
- **AND** .gitignore MUST exclude `*.pyc` bytecode files
- **AND** .gitignore MUST exclude `custom/` user plugins
- **AND** .gitignore MUST exclude `.env` and secret files

#### Scenario: Custom plugins excluded
- **WHEN** users create custom plugins
- **THEN** custom/ directory MUST be git-ignored
- **AND** users MUST manage their own custom plugin versioning
- **AND** system plugins in plugins/ MUST be version controlled

#### Scenario: Configuration files handled appropriately
- **WHEN** managing configuration
- **THEN** default config (config/gs.json) MUST be versioned
- **AND** user config (~/.config/global-scripts/) MUST NOT be versioned
- **AND** example configs MAY be provided in docs/examples/

### Requirement: Dependency Management Structure

Dependencies SHALL be managed using modern Python tools with clear organization.

#### Scenario: Dependencies declared in pyproject.toml
- **WHEN** managing dependencies
- **THEN** runtime dependencies MUST be in [project.dependencies]
- **AND** dev dependencies MUST be in [dependency-groups.dev]
- **AND** version constraints MUST be specified appropriately
- **AND** dependencies MUST be minimal and justified

#### Scenario: Lock file is maintained
- **WHEN** using UV dependency manager
- **THEN** uv.lock file MUST be committed to git
- **AND** lock file MUST be updated when dependencies change
- **AND** lock file MUST ensure reproducible builds

#### Scenario: Optional dependencies are grouped
- **WHEN** defining optional features
- **THEN** optional dependencies MUST be in separate groups
- **AND** groups MUST be installable independently
- **AND** core functionality MUST work without optional deps

### Requirement: Shell Integration Files

Shell integration files SHALL be organized for multi-shell support.

#### Scenario: Completion files per shell
- **WHEN** generating shell completions
- **THEN** Bash completion MUST be generated for ~/.bashrc integration
- **AND** Zsh completion MUST be generated for ~/.zshrc integration
- **AND** Fish completion MUST be generated for ~/.config/fish/ integration
- **AND** each completion MUST be shell-specific

#### Scenario: Environment setup per shell
- **WHEN** generating environment files
- **THEN** env.sh MUST be generated for Bash/Zsh
- **AND** env.fish MUST be generated for Fish
- **AND** environment files MUST set GS_HOME and PATH
- **AND** environment files MUST be sourced in shell rc files

#### Scenario: Router scripts located appropriately
- **WHEN** installing router scripts
- **THEN** gs-router script MUST be in `~/.config/global-scripts/bin/`
- **AND** router scripts MUST be executable
- **AND** router scripts MUST be in PATH

### Requirement: Logging Files Organization

Log files SHALL be organized with rotation and cleanup policies.

#### Scenario: Logs in user config directory
- **WHEN** writing log files
- **THEN** logs MUST be in `~/.config/global-scripts/logs/`
- **AND** main log MUST be gs.log
- **AND** logs MUST use structured format
- **AND** logs MUST include timestamps and log levels

#### Scenario: Log rotation is implemented
- **WHEN** logs grow large
- **THEN** logs SHOULD rotate when exceeding size limit
- **AND** old logs SHOULD be compressed
- **AND** very old logs SHOULD be deleted automatically
- **AND** rotation policy MUST be configurable

#### Scenario: Debug logs are separate
- **WHEN** debug logging is enabled
- **THEN** debug logs MAY use separate file
- **AND** debug logs MUST NOT affect performance in production
- **AND** debug logs MUST be opt-in via configuration
