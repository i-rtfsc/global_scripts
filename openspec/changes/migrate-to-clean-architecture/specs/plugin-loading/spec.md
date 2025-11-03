# Plugin Loading Specification Delta

## ADDED Requirements

### Requirement: Asynchronous Plugin Discovery

The system SHALL discover plugins asynchronously from configured directories.

#### Scenario: Scan system plugin directory
- **WHEN** discovering plugins
- **THEN** loader MUST scan plugins/ directory for system plugins
- **AND** loader MUST check for plugin.json in each subdirectory
- **AND** scan MUST be non-recursive for system plugins
- **AND** scan MUST complete within 500ms for 50 plugins

#### Scenario: Scan custom plugin directory recursively
- **WHEN** discovering custom plugins
- **THEN** loader MUST scan custom/ directory recursively
- **AND** loader MUST find plugins at any depth
- **AND** loader MUST skip directories without plugin.json
- **AND** custom plugins MUST override system plugins with same name

#### Scenario: Concurrent plugin discovery
- **WHEN** scanning multiple directories
- **THEN** loader MUST scan directories concurrently using asyncio.gather()
- **AND** concurrent scanning MUST improve discovery performance
- **AND** errors in one directory MUST NOT prevent discovery in others
- **AND** all discovered plugins MUST be collected and returned

### Requirement: Plugin Metadata Parsing

The system SHALL parse and validate plugin metadata from plugin.json files.

#### Scenario: Parse valid plugin.json
- **WHEN** loading plugin metadata
- **THEN** loader MUST parse plugin.json as JSON
- **AND** loader MUST validate required fields (name, version, type)
- **AND** loader MUST support optional fields (author, description, enabled)
- **AND** loader MUST create PluginMetadata instance

#### Scenario: Handle invalid plugin.json
- **WHEN** plugin.json is malformed or missing required fields
- **THEN** loader MUST log error with plugin path
- **AND** loader MUST skip invalid plugin
- **AND** loader MUST continue discovering other plugins
- **AND** loader MUST NOT raise exception

#### Scenario: Support internationalized metadata
- **WHEN** parsing description fields
- **THEN** loader MUST support description as dict with zh/en keys
- **AND** loader MUST support description as plain string (fallback)
- **AND** loader MUST validate both language keys exist if dict
- **AND** loader MUST use same language for all metadata

### Requirement: Multi-Type Plugin Parsing

The system SHALL support parsing multiple plugin types with specialized parsers.

#### Scenario: Determine plugin type from metadata
- **WHEN** loading plugin
- **THEN** loader MUST read type field from plugin.json
- **AND** loader MUST validate type is one of: python, shell, config, hybrid
- **AND** loader MUST select appropriate parser for type
- **AND** loader MUST raise error for unknown types

#### Scenario: Parse Python plugin functions
- **WHEN** loading Python plugin
- **THEN** loader MUST import plugin.py module
- **AND** loader MUST scan for @plugin_function decorated methods
- **AND** loader MUST extract function metadata from decorator
- **AND** loader MUST support both sync and async functions
- **AND** loader MUST handle import errors gracefully

#### Scenario: Parse Shell plugin functions
- **WHEN** loading Shell plugin
- **THEN** loader MUST read plugin.sh file
- **AND** loader MUST scan for # @plugin_function annotations
- **AND** loader MUST parse function metadata from comments
- **AND** loader MUST extract function names from shell function definitions
- **AND** loader MUST validate shell script syntax

#### Scenario: Parse Config plugin commands
- **WHEN** loading Config plugin
- **THEN** loader MUST read commands.json file
- **AND** loader MUST parse command definitions
- **AND** loader MUST validate command structure (name, description, command)
- **AND** loader MUST create function metadata from command definitions

#### Scenario: Parse Hybrid plugin with subplugins
- **WHEN** loading Hybrid plugin
- **THEN** loader MUST read subplugins array from plugin.json
- **AND** loader MUST load each subplugin recursively
- **AND** loader MUST support mixed types in subplugins
- **AND** loader MUST namespace subplugin functions (parent.child.function)

### Requirement: Function Discovery and Registration

The system SHALL discover and register all plugin functions.

#### Scenario: Discover functions from decorators
- **WHEN** parsing Python plugin
- **THEN** loader MUST use AST or regex to find @plugin_function decorators
- **AND** loader MUST extract decorator arguments (name, description, usage, examples)
- **AND** loader MUST match decorator to function definition
- **AND** loader MUST store function metadata in registry

#### Scenario: Discover functions from annotations
- **WHEN** parsing Shell plugin
- **THEN** loader MUST use regex to find # @plugin_function annotations
- **AND** loader MUST parse annotation parameters
- **AND** loader MUST match annotation to shell function definition
- **AND** loader MUST store function metadata in registry

#### Scenario: Register function with full path
- **WHEN** registering discovered function
- **THEN** function MUST be registered with full path (plugin.subplugin.function)
- **AND** function MUST include metadata (description, usage, examples)
- **AND** function MUST include execution information (type, entry point)
- **AND** duplicate function names MUST log warning and use last definition

### Requirement: Plugin State Management

The system SHALL manage plugin state across system restarts.

#### Scenario: Load plugin enabled state from config
- **WHEN** loading plugins
- **THEN** loader MUST read enabled status from configuration
- **AND** user config MUST override plugin.json default
- **AND** plugins without config entry MUST use plugin.json enabled value
- **AND** enabled state MUST be accessible via PluginMetadata

#### Scenario: Persist plugin state changes
- **WHEN** plugin enabled state changes
- **THEN** new state MUST be written to user configuration
- **AND** user config MUST be updated immediately
- **AND** state change MUST be reflected in plugin metadata
- **AND** state MUST persist across system restarts

### Requirement: Parser Extensibility

The system SHALL support custom plugin parsers via plugin system.

#### Scenario: Register custom parser
- **WHEN** registering custom parser
- **THEN** parser MUST implement IPluginParser interface
- **AND** parser MUST be registered for specific plugin type
- **AND** parser MUST be used for matching plugin types
- **AND** custom parsers MUST override built-in parsers

#### Scenario: Parser entry points
- **WHEN** system loads parsers
- **THEN** system MUST discover parsers via entry points
- **AND** entry points MUST be defined in pyproject.toml
- **AND** parsers MUST be loaded at initialization
- **AND** parser loading errors MUST be logged but not fatal

### Requirement: Error Handling and Recovery

The system SHALL handle plugin loading errors gracefully without crashing.

#### Scenario: Handle corrupted plugin.json
- **WHEN** plugin.json cannot be parsed
- **THEN** loader MUST log error with file path and error details
- **AND** loader MUST skip corrupted plugin
- **AND** loader MUST continue loading other plugins
- **AND** loader MUST return partial results

#### Scenario: Handle missing entry files
- **WHEN** plugin.py or plugin.sh is missing
- **THEN** loader MUST log error indicating missing entry file
- **AND** loader MUST skip plugin with missing entry
- **AND** loader MUST NOT raise exception
- **AND** missing plugin MUST NOT appear in plugin list

#### Scenario: Handle circular subplugin dependencies
- **WHEN** hybrid plugin has circular subplugin references
- **THEN** loader MUST detect circular dependencies
- **AND** loader MUST log error with dependency chain
- **AND** loader MUST skip plugin with circular dependencies
- **AND** loader MUST prevent infinite recursion

### Requirement: Performance Optimization

The system SHALL optimize plugin loading performance for large plugin sets.

#### Scenario: Cache plugin metadata
- **WHEN** plugins have not changed
- **THEN** loader MAY cache parsed plugin metadata
- **AND** cache MUST be invalidated when plugin.json changes
- **AND** cache MUST be invalidated on refresh command
- **AND** cache MUST improve subsequent load times by 50%+

#### Scenario: Lazy load plugin functions
- **WHEN** listing plugins
- **THEN** loader MAY defer function discovery until needed
- **AND** plugin metadata MUST be loaded eagerly
- **AND** function discovery MUST be triggered on first access
- **AND** lazy loading MUST reduce initial startup time

#### Scenario: Parallel parsing for large plugin sets
- **WHEN** loading many plugins concurrently
- **THEN** loader MUST use asyncio.gather() for parallel parsing
- **AND** parser MUST not block other parsers
- **AND** parsing MUST scale linearly with plugin count
- **AND** semaphore MUST limit concurrent file I/O to prevent resource exhaustion

### Requirement: Backward Compatibility with Legacy Loader

The system SHALL maintain identical loading behavior to legacy PluginLoader.

#### Scenario: Test legacy parser logic preservation
- **WHEN** parsing plugins with new loader
- **THEN** new loader MUST produce identical function metadata to legacy
- **AND** decorator parsing MUST match legacy regex patterns
- **AND** annotation parsing MUST match legacy parsing rules
- **AND** behavioral tests MUST validate equivalence

#### Scenario: Support existing plugin structures
- **WHEN** loading existing plugins
- **THEN** all existing plugins MUST load successfully
- **AND** function metadata MUST be identical to legacy loader
- **AND** execution paths MUST remain compatible
- **AND** no plugin MUST require changes to migrate
