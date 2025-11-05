# plugin-execution Specification

## Purpose
TBD - created by archiving change migrate-to-clean-architecture. Update Purpose after archive.
## Requirements
### Requirement: Unified Execution Interface

The system SHALL provide unified execution interface for all plugin types.

#### Scenario: Execute method signature
- **WHEN** executing plugin function
- **THEN** executor MUST accept plugin_name parameter
- **AND** executor MUST accept function_name parameter
- **AND** executor MUST accept optional args parameter (List[str])
- **AND** executor MUST return CommandResult with success, output, error, exit_code

#### Scenario: Async execution by default
- **WHEN** executing any plugin function
- **THEN** execution MUST be asynchronous (async def)
- **AND** executor MUST await all async operations
- **AND** executor MUST handle both sync and async plugin functions
- **AND** sync functions MUST be wrapped to run in executor if needed

### Requirement: Execution Routing by Plugin Type

The system SHALL route execution based on plugin type for optimal performance.

#### Scenario: Route Shell plugin to gs-router
- **WHEN** executing Shell plugin function
- **THEN** executor MUST route to gs-router script for direct shell execution
- **AND** executor MUST avoid Python overhead
- **AND** execution MUST complete in < 10ms overhead
- **AND** stdout/stderr MUST be captured and returned

#### Scenario: Route Config plugin to gs-router
- **WHEN** executing Config plugin command
- **THEN** executor MUST route to gs-router script
- **AND** executor MUST substitute command template with args
- **AND** executor MUST execute in user's current shell
- **AND** execution MUST preserve shell environment

#### Scenario: Execute Python plugin via import
- **WHEN** executing Python plugin function
- **THEN** executor MUST dynamically import plugin module
- **AND** executor MUST locate decorated function by name
- **AND** executor MUST call function with args parameter
- **AND** executor MUST await if function is async

#### Scenario: Execute Hybrid plugin subplugin
- **WHEN** executing function in hybrid plugin subplugin
- **THEN** executor MUST parse full path (plugin.subplugin.function)
- **AND** executor MUST determine subplugin type
- **AND** executor MUST route to appropriate execution method
- **AND** executor MUST handle multi-level nesting

### Requirement: Command Validation and Security

The system SHALL validate and secure all command execution.

#### Scenario: Validate against whitelist
- **WHEN** whitelist is configured
- **THEN** executor MUST check command against GlobalConstants.SAFE_COMMANDS
- **AND** executor MUST reject commands not in whitelist
- **AND** rejection MUST return CommandResult with error
- **AND** rejection MUST log security warning

#### Scenario: Block dangerous commands
- **WHEN** executing shell commands
- **THEN** executor MUST check against GlobalConstants.DANGEROUS_COMMANDS
- **AND** executor MUST block rm -rf, dd, mkfs, and similar destructive commands
- **AND** blocked command MUST return CommandResult with security error
- **AND** blocked attempt MUST be logged with WARNING level

#### Scenario: Sanitize command arguments
- **WHEN** building shell command with user arguments
- **THEN** executor MUST quote arguments using shlex.quote()
- **AND** executor MUST prevent command injection
- **AND** executor MUST escape special shell characters
- **AND** executor MUST validate argument count matches function definition

### Requirement: Timeout Enforcement

The system SHALL enforce timeout limits on all plugin execution.

#### Scenario: Default timeout applied
- **WHEN** executing plugin function without explicit timeout
- **THEN** executor MUST apply default 30 second timeout
- **AND** timeout MUST be configurable via configuration
- **AND** timeout MUST apply to all plugin types
- **AND** timeout MUST include both execution and I/O time

#### Scenario: Process termination on timeout
- **WHEN** plugin execution exceeds timeout
- **THEN** executor MUST terminate subprocess immediately
- **AND** executor MUST return CommandResult with timeout error
- **AND** error message MUST indicate timeout duration
- **AND** partial output MUST be included in result if available

#### Scenario: Cleanup on timeout
- **WHEN** timeout occurs
- **THEN** executor MUST send SIGTERM to process
- **AND** executor MUST wait up to 5 seconds for graceful shutdown
- **AND** executor MUST send SIGKILL if process doesn't terminate
- **AND** executor MUST clean up all subprocess resources

### Requirement: Error Handling and Reporting

The system SHALL handle execution errors and provide actionable error messages.

#### Scenario: Handle plugin not found
- **WHEN** executing non-existent plugin
- **THEN** executor MUST return CommandResult with success=False
- **AND** error MUST be internationalized (zh/en)
- **AND** error MUST suggest using 'gs plugin list' to see available plugins
- **AND** exit_code MUST be 1

#### Scenario: Handle function not found
- **WHEN** executing non-existent function
- **THEN** executor MUST return CommandResult with success=False
- **AND** error MUST list available functions for that plugin
- **AND** error MUST be internationalized
- **AND** exit_code MUST be 1

#### Scenario: Handle execution exception
- **WHEN** plugin function raises exception
- **THEN** executor MUST catch exception
- **AND** executor MUST log exception with stack trace
- **AND** executor MUST return CommandResult with success=False and error message
- **AND** error message MUST be user-friendly, not raw stack trace

#### Scenario: Handle disabled plugin execution attempt
- **WHEN** user attempts to execute disabled plugin
- **THEN** executor MUST check plugin enabled status
- **AND** executor MUST reject execution with appropriate error
- **AND** error MUST suggest enabling plugin first
- **AND** exit_code MUST be 1

### Requirement: Result Capture and Formatting

The system SHALL capture and format execution results consistently.

#### Scenario: Capture subprocess stdout and stderr
- **WHEN** executing shell or config plugin
- **THEN** executor MUST capture stdout stream
- **AND** executor MUST capture stderr stream separately
- **AND** executor MUST include both in CommandResult output
- **AND** executor MUST preserve output encoding (UTF-8)

#### Scenario: Handle Python function return values
- **WHEN** Python function returns value
- **THEN** executor MUST convert return value to CommandResult if not already
- **AND** executor MUST handle string return as output
- **AND** executor MUST handle dict/list return as JSON output
- **AND** executor MUST handle None return as empty success

#### Scenario: Preserve exit codes
- **WHEN** subprocess completes
- **THEN** executor MUST capture subprocess exit code
- **AND** exit code MUST be set in CommandResult
- **AND** non-zero exit code MUST set success=False
- **AND** exit code 0 MUST set success=True

### Requirement: Concurrent Execution Support

The system SHALL support concurrent execution of multiple plugin functions.

#### Scenario: Multiple plugins execute concurrently
- **WHEN** multiple plugin functions are executed simultaneously
- **THEN** executor MUST use asyncio for concurrent execution
- **AND** executions MUST NOT block each other
- **AND** each execution MUST have independent timeout
- **AND** failure in one execution MUST NOT affect others

#### Scenario: Limit concurrent executions
- **WHEN** many plugins execute at once
- **THEN** executor MAY use semaphore to limit concurrency
- **AND** limit SHOULD be configurable (default 10)
- **AND** excess executions MUST queue, not fail
- **AND** limit MUST prevent resource exhaustion

### Requirement: Dynamic Module Import for Python Plugins

The system SHALL dynamically import and execute Python plugin modules.

#### Scenario: Import plugin module by path
- **WHEN** executing Python plugin
- **THEN** executor MUST construct module import path
- **AND** executor MUST use importlib to import module
- **AND** executor MUST handle import errors gracefully
- **AND** imported module MUST be cached for subsequent calls

#### Scenario: Locate decorated function in module
- **WHEN** finding function to execute
- **THEN** executor MUST scan module for @plugin_function decorators
- **AND** executor MUST match function_name to decorated function
- **AND** executor MUST validate function signature
- **AND** executor MUST raise error if function not found

#### Scenario: Call function with arguments
- **WHEN** invoking plugin function
- **THEN** executor MUST pass self if function is instance method
- **AND** executor MUST pass args parameter
- **AND** executor MUST await if function is async
- **AND** executor MUST catch and handle function exceptions

#### Scenario: Handle module reload for development
- **WHEN** plugin code changes during development
- **THEN** executor MAY support module reload
- **AND** reload MUST clear module cache
- **AND** reload MUST re-import updated code
- **AND** reload MUST be triggered by refresh command

### Requirement: Shell Integration and Environment

The system SHALL preserve shell environment during execution.

#### Scenario: Preserve working directory
- **WHEN** executing shell commands
- **THEN** executor MUST preserve user's current working directory
- **AND** executor MUST NOT change to plugin directory
- **AND** executor MUST pass cwd to subprocess
- **AND** working directory MUST be available to plugin functions

#### Scenario: Preserve environment variables
- **WHEN** executing shell commands
- **THEN** executor MUST inherit user's environment variables
- **AND** executor MAY add GS_* environment variables
- **AND** executor MUST NOT modify user's environment
- **AND** plugin-specific env vars MUST be isolated

#### Scenario: Support shell-specific features
- **WHEN** executing in specific shell
- **THEN** executor MUST detect user's shell (bash/zsh/fish)
- **AND** executor MUST use appropriate shell for execution
- **AND** shell-specific syntax MUST be supported
- **AND** executor MUST handle shell startup files

### Requirement: Performance Monitoring

The system SHALL monitor and report execution performance metrics.

#### Scenario: Measure execution duration
- **WHEN** executing plugin function
- **THEN** executor MUST record start time
- **AND** executor MUST record end time
- **AND** executor MUST calculate duration in milliseconds
- **AND** duration MUST be logged for performance monitoring

#### Scenario: Log slow executions
- **WHEN** execution exceeds performance threshold
- **THEN** executor MUST log WARNING for executions > 5 seconds
- **AND** log MUST include plugin name, function name, duration
- **AND** log MUST include correlation ID for tracing
- **AND** slow executions MUST be available in health metrics

#### Scenario: Track execution statistics
- **WHEN** collecting health metrics
- **THEN** executor MUST track total execution count
- **AND** executor MUST track success/failure ratio
- **AND** executor MUST track average execution time
- **AND** statistics MUST be available via health check API

### Requirement: Migration Compatibility

The system SHALL maintain execution behavior identical to legacy system.

#### Scenario: Test execution equivalence
- **WHEN** running execution compatibility tests
- **THEN** new PluginExecutor MUST produce identical results to legacy
- **AND** all plugin types MUST execute identically
- **AND** error handling MUST be identical
- **AND** timeout behavior MUST be identical

#### Scenario: Support legacy execution patterns
- **WHEN** migrating from legacy system
- **THEN** executor MUST support all legacy execution modes
- **AND** executor MUST handle legacy plugin structures
- **AND** executor MUST be drop-in replacement for legacy executor
- **AND** migration MUST not require plugin changes

