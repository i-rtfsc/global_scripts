# API Design Specification

## Purpose

This specification defines API design principles, patterns, and interfaces for Global Scripts V5.

## Requirements

### Requirement: CommandResult Interface

The system SHALL use CommandResult as the standard return type for all operations.

#### Scenario: CommandResult contains operation outcome
- **WHEN** an operation completes
- **THEN** result MUST be a CommandResult instance
- **AND** result.success MUST be True for successful operations, False otherwise
- **AND** result.output MUST contain success message or data
- **AND** result.error MUST contain error message if success is False
- **AND** result.exit_code MUST be 0 for success, non-zero for failure

#### Scenario: CommandResult is consistent
- **WHEN** returning CommandResult
- **THEN** success=True MUST have exit_code=0
- **AND** success=False MUST have non-zero exit_code
- **AND** error MUST be None when success=True
- **AND** output SHOULD be None when success=False (unless partial results)

#### Scenario: CommandResult errors are internationalized
- **WHEN** creating error CommandResult
- **THEN** error message MUST be internationalized (zh/en)
- **AND** error message MUST be user-friendly
- **AND** error message SHOULD suggest remediation
- **AND** error message MUST NOT contain stack traces

### Requirement: Repository Interface Pattern

Repository interfaces SHALL define data access contracts in the domain layer.

#### Scenario: Repository interface in domain
- **WHEN** defining a repository interface
- **THEN** interface MUST be in domain/interfaces/repositories.py
- **AND** interface MUST extend Protocol or ABC
- **AND** interface MUST use domain objects (entities, value objects)
- **AND** interface MUST NOT expose infrastructure details

#### Scenario: Repository methods are async
- **WHEN** defining repository methods
- **THEN** all I/O methods MUST be async
- **AND** method signatures MUST use type hints
- **AND** method names MUST clearly indicate the operation (get, save, delete, list)

#### Scenario: Repository CRUD operations
- **WHEN** implementing repository interface
- **THEN** interface MUST define get_all() -> List[Entity]
- **AND** interface MUST define get_by_id(id) -> Optional[Entity]
- **AND** interface MUST define save(entity: Entity) -> None
- **AND** interface MUST define delete(id) -> None
- **AND** interface MAY define query methods for specific use cases

### Requirement: Service Interface Pattern

Service interfaces SHALL define business capabilities in the domain layer.

#### Scenario: Service interface in domain
- **WHEN** defining a service interface
- **THEN** interface MUST be in domain/interfaces/services.py
- **AND** interface MUST define business operations
- **AND** interface MUST use domain language (ubiquitous language)
- **AND** interface MUST NOT depend on infrastructure

#### Scenario: Service methods are cohesive
- **WHEN** defining service methods
- **THEN** methods MUST be related to service's core responsibility
- **AND** methods MUST have clear, descriptive names
- **AND** methods MUST return CommandResult or domain objects
- **AND** methods MUST use type annotations

#### Scenario: Service dependencies injected
- **WHEN** service depends on other services or repositories
- **THEN** dependencies MUST be declared in constructor
- **AND** dependencies MUST be interfaces, not concrete implementations
- **AND** dependencies MUST be injected via DI container

### Requirement: Plugin Function Decorator API

Plugin functions SHALL use decorator-based API for metadata and registration.

#### Scenario: Decorator provides metadata
- **WHEN** defining a plugin function
- **THEN** function MUST be decorated with @plugin_function
- **AND** decorator MUST specify name parameter
- **AND** decorator MUST specify description parameter (zh/en dict)
- **AND** decorator MAY specify usage and examples parameters

#### Scenario: Plugin function signature is standard
- **WHEN** implementing plugin function
- **THEN** function MUST accept self parameter (instance method)
- **AND** function MUST accept args: List[str] = None parameter
- **AND** function MUST return CommandResult
- **AND** function MAY be async or sync

#### Scenario: Plugin function registration
- **WHEN** plugin is loaded
- **THEN** decorated functions MUST be automatically discovered
- **AND** function metadata MUST be extracted from decorator
- **AND** functions MUST be registered in plugin registry
- **AND** functions MUST be callable via CLI

### Requirement: Dependency Injection Container API

The DI container SHALL provide type-safe dependency resolution.

#### Scenario: Container registration
- **WHEN** registering services
- **THEN** container.register(interface, implementation) MUST register binding
- **AND** container.register_singleton(interface, implementation) MUST register singleton
- **AND** registrations MUST be type-safe
- **AND** duplicate registrations MUST raise error or warn

#### Scenario: Container resolution
- **WHEN** resolving dependencies
- **THEN** container.resolve(Interface) MUST return implementation instance
- **AND** resolution MUST handle transitive dependencies
- **AND** circular dependencies MUST be detected and raise error
- **AND** missing registrations MUST raise clear error

#### Scenario: Container lifecycle management
- **WHEN** managing container lifecycle
- **THEN** container MUST support reset for testing
- **AND** singleton instances MUST be reused across resolutions
- **AND** transient instances MUST be created per resolution
- **AND** container MUST be thread-safe

### Requirement: Async Execution API

Async operations SHALL follow consistent patterns for execution and error handling.

#### Scenario: Async function declarations
- **WHEN** defining async functions
- **THEN** function MUST use `async def` keyword
- **AND** function MUST await all async operations
- **AND** function MUST not mix sync and async I/O
- **AND** function return type MUST reflect async nature

#### Scenario: Async context managers
- **WHEN** managing resources asynchronously
- **THEN** code MUST use `async with` statement
- **AND** __aenter__ and __aexit__ MUST be implemented
- **AND** resources MUST be cleaned up in __aexit__
- **AND** exceptions MUST propagate correctly

#### Scenario: Concurrent execution
- **WHEN** running operations concurrently
- **THEN** asyncio.gather() MUST be used for multiple operations
- **AND** error handling MUST use return_exceptions parameter appropriately
- **AND** results MUST be collected in order
- **AND** partial failures MUST be handled gracefully

### Requirement: Error Handling API

Error handling SHALL distinguish between expected failures and unexpected errors.

#### Scenario: Expected failures return CommandResult
- **WHEN** operation fails expectedly (validation, not found, etc.)
- **THEN** function MUST return CommandResult with success=False
- **AND** error message MUST be user-friendly and actionable
- **AND** exception MUST NOT be raised
- **AND** error MUST be logged at INFO or WARNING level

#### Scenario: Unexpected errors raise exceptions
- **WHEN** unexpected error occurs (programming error, system failure)
- **THEN** function MUST raise appropriate exception
- **AND** exception MUST be logged at ERROR level
- **AND** exception MUST be caught at appropriate boundary (CLI layer)
- **AND** user MUST see friendly error message, not stack trace

#### Scenario: Custom exceptions are specific
- **WHEN** defining custom exceptions
- **THEN** exceptions MUST inherit from appropriate base (ValueError, RuntimeError, etc.)
- **AND** exception names MUST be descriptive (PluginNotFoundError)
- **AND** exceptions MUST include helpful error messages
- **AND** exceptions MAY include context attributes

### Requirement: Configuration API

Configuration SHALL be accessed through typed interfaces with validation.

#### Scenario: Configuration loading
- **WHEN** loading configuration
- **THEN** system MUST load from user config if exists
- **AND** system MUST fall back to project defaults
- **AND** environment variables MUST override file config
- **AND** configuration MUST be validated on load

#### Scenario: Configuration access
- **WHEN** accessing configuration values
- **THEN** config API MUST provide get(key, default) method
- **AND** config MUST support nested keys with dot notation
- **AND** config MUST return typed values
- **AND** missing required keys MUST raise error

#### Scenario: Configuration modification
- **WHEN** modifying configuration
- **THEN** changes MUST be saved to user config file
- **AND** project default config MUST remain unchanged
- **AND** invalid values MUST be rejected
- **AND** configuration MUST be reloaded after save

### Requirement: Event System API

The system SHALL support observer pattern for plugin lifecycle events.

#### Scenario: Event definition
- **WHEN** defining events
- **THEN** event types MUST be defined in enum (PluginEvent)
- **AND** event data MUST be defined in dataclass (PluginEventData)
- **AND** events MUST be immutable
- **AND** events MUST contain timestamp and correlation ID

#### Scenario: Observer registration
- **WHEN** registering event observers
- **THEN** observer MUST implement IPluginObserver interface
- **AND** observer MUST define on_event(event, data) method
- **AND** multiple observers MUST be supported
- **AND** observers MUST be notified in registration order

#### Scenario: Event notification
- **WHEN** emitting events
- **THEN** all registered observers MUST be notified
- **AND** notification MUST be asynchronous if observers are async
- **AND** observer exceptions MUST NOT affect event emitter
- **AND** observer exceptions MUST be logged

### Requirement: Plugin Loader API

Plugin loader SHALL provide async discovery and loading of plugins.

#### Scenario: Plugin discovery
- **WHEN** discovering plugins
- **THEN** loader MUST scan configured plugin directories
- **AND** loader MUST detect plugins by plugin.json presence
- **AND** loader MUST support recursive scanning for custom plugins
- **AND** loader MUST return list of discovered plugin paths

#### Scenario: Plugin loading
- **WHEN** loading plugins
- **THEN** loader MUST parse plugin metadata from plugin.json
- **AND** loader MUST determine plugin type (python, shell, config, hybrid)
- **AND** loader MUST discover plugin functions
- **AND** loader MUST return Plugin or SimplePlugin object

#### Scenario: Plugin function discovery
- **WHEN** discovering plugin functions
- **THEN** Python plugins MUST scan for @plugin_function decorators
- **AND** Shell plugins MUST parse # @plugin_function annotations
- **AND** Config plugins MUST parse commands.json
- **AND** Hybrid plugins MUST discover functions from all subplugins

### Requirement: Plugin Executor API

Plugin executor SHALL provide unified execution interface for all plugin types.

#### Scenario: Execute method signature
- **WHEN** executing plugin function
- **THEN** executor MUST accept plugin_name, function_name, args parameters
- **AND** executor MUST return CommandResult
- **AND** execution MUST be asynchronous
- **AND** execution MUST enforce timeout

#### Scenario: Execution routing
- **WHEN** routing execution
- **THEN** Shell/Config plugins MUST use gs-router (shell execution)
- **AND** Python plugins MUST use dynamic import and function call
- **AND** executor MUST handle both sync and async plugin functions
- **AND** executor MUST capture stdout/stderr for shell plugins

#### Scenario: Execution error handling
- **WHEN** execution fails
- **THEN** executor MUST catch exceptions and return CommandResult with success=False
- **AND** timeout MUST terminate process and return appropriate error
- **AND** missing plugins/functions MUST return clear error message
- **AND** execution errors MUST be logged with context

### Requirement: Internationalization API

i18n system SHALL provide multi-language support for all user-facing text.

#### Scenario: Message file structure
- **WHEN** organizing i18n messages
- **THEN** messages MUST be in config/messages/zh.json and en.json
- **AND** message keys MUST use dot notation (errors.plugin_not_found)
- **AND** messages MUST support placeholders
- **AND** both languages MUST have same keys

#### Scenario: Message retrieval
- **WHEN** getting internationalized messages
- **THEN** i18n.get_message(key, **params) MUST return formatted message
- **AND** current language MUST be determined from config
- **AND** missing keys MUST return key name with warning
- **AND** parameter substitution MUST use {param} syntax

#### Scenario: Plugin metadata i18n
- **WHEN** defining plugin metadata
- **THEN** description MUST be dict with zh and en keys
- **AND** function descriptions MUST be dict with zh and en keys
- **AND** usage examples MUST be dict with zh and en keys
- **AND** current language determines which text is displayed

### Requirement: FileSystem Abstraction API

Filesystem operations SHALL use abstraction layer to enable testing.

#### Scenario: FileSystem interface
- **WHEN** defining filesystem interface
- **THEN** interface MUST provide read_text(path) -> str method
- **AND** interface MUST provide write_text(path, content) method
- **AND** interface MUST provide exists(path) -> bool method
- **AND** interface MUST provide list_dir(path) -> List[Path] method
- **AND** all methods MUST be async

#### Scenario: Real filesystem implementation
- **WHEN** implementing real filesystem
- **THEN** implementation MUST use aiofiles for async I/O
- **AND** implementation MUST handle errors appropriately
- **AND** implementation MUST validate paths for security
- **AND** implementation MUST be registered in DI container

#### Scenario: Mock filesystem for testing
- **WHEN** testing with mock filesystem
- **THEN** InMemoryFileSystem MUST implement IFileSystem interface
- **AND** mock MUST store files in memory dictionary
- **AND** mock MUST simulate file operations
- **AND** mock MUST be provided by test fixtures

### Requirement: Process Executor API

Process execution SHALL provide secure, async subprocess management.

#### Scenario: Executor interface
- **WHEN** defining executor interface
- **THEN** interface MUST provide execute(cmd, timeout) -> CommandResult method
- **AND** method MUST be async
- **AND** method MUST support timeout parameter
- **AND** method MUST return stdout, stderr, exit code

#### Scenario: Command validation
- **WHEN** executing commands
- **THEN** executor MUST validate against whitelist if configured
- **AND** executor MUST block dangerous commands (rm -rf, dd, etc.)
- **AND** executor MUST sanitize arguments with shlex.quote()
- **AND** validation failure MUST return CommandResult with error

#### Scenario: Process management
- **WHEN** running subprocess
- **THEN** executor MUST create subprocess with asyncio
- **AND** executor MUST enforce timeout and terminate on expiry
- **AND** executor MUST capture stdout and stderr
- **AND** executor MUST clean up process resources properly

### Requirement: CLI Command Handler API

CLI command handlers SHALL follow consistent patterns for argument parsing and execution.

#### Scenario: Command handler signature
- **WHEN** implementing command handler
- **THEN** handler MUST accept parsed args parameter
- **AND** handler MUST return CommandResult
- **AND** handler MUST be async
- **AND** handler MUST handle errors gracefully

#### Scenario: Argument parsing
- **WHEN** parsing command arguments
- **THEN** parser MUST use argparse or similar
- **AND** parser MUST define clear help messages
- **AND** parser MUST validate required arguments
- **AND** parser MUST provide usage examples

#### Scenario: Output formatting
- **WHEN** displaying command results
- **THEN** success output MUST use formatters for consistent display
- **AND** errors MUST be displayed with appropriate color (red)
- **AND** tables MUST use Rich Table for structured data
- **AND** output MUST respect user language preference

### Requirement: Router Index API

Router index SHALL provide fast command routing for shell integration.

#### Scenario: Router index generation
- **WHEN** generating router index
- **THEN** indexer MUST scan all plugins and functions
- **AND** index MUST map command paths to plugin type and location
- **AND** index MUST be written to router.json
- **AND** index MUST be regenerated when plugins change

#### Scenario: Router index structure
- **WHEN** structuring router index
- **THEN** index MUST use command path as key (plugin.subplugin.function)
- **AND** value MUST include type (python, shell, json)
- **AND** value MUST include execution path or script
- **AND** index MUST be JSON serializable

#### Scenario: Router index usage
- **WHEN** using router index
- **THEN** shell wrapper MUST read router.json
- **AND** Shell/Config commands MUST execute directly
- **AND** Python commands MUST invoke gs CLI
- **AND** missing commands MUST show helpful error
