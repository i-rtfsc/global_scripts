# Architecture Specification

## Purpose

This specification defines the target architecture for Global Scripts V5 using Clean Architecture principles with Domain-Driven Design (DDD) patterns.

## Requirements

### Requirement: Clean Architecture Layer Structure

The system SHALL organize code into four distinct layers following Clean Architecture principles with strict dependency rules.

#### Scenario: Layer organization is enforced
- **WHEN** examining the codebase directory structure
- **THEN** the following layers MUST exist:
  - `cli/` - Presentation layer (user interface)
  - `application/` - Application services layer (use cases)
  - `domain/` - Domain layer (business logic, entities, interfaces)
  - `infrastructure/` - Infrastructure layer (external concerns)

#### Scenario: Dependency direction is inward-only
- **WHEN** analyzing imports between layers
- **THEN** dependencies MUST point inward: CLI → Application → Domain ← Infrastructure
- **AND** domain layer MUST NOT import from any outer layer
- **AND** infrastructure layer MUST only import from domain (for interfaces)

#### Scenario: Layer responsibilities are clear
- **WHEN** implementing a new feature
- **THEN** CLI layer MUST only handle user input/output and command routing
- **AND** application layer MUST only orchestrate use cases
- **AND** domain layer MUST only contain business logic and rules
- **AND** infrastructure layer MUST only handle external concerns (I/O, persistence, execution)

### Requirement: Domain Layer Independence

The domain layer SHALL be completely independent of frameworks, infrastructure, and external dependencies.

#### Scenario: Domain contains only business logic
- **WHEN** reviewing domain layer code
- **THEN** domain entities MUST contain business behavior, not just data
- **AND** domain services MUST contain domain logic that doesn't belong to a single entity
- **AND** domain value objects MUST encapsulate validation and business rules

#### Scenario: Domain defines interfaces for infrastructure
- **WHEN** domain layer needs external capabilities
- **THEN** domain MUST define interfaces (e.g., `IPluginRepository`, `IFileSystem`)
- **AND** infrastructure layer MUST implement these interfaces
- **AND** application layer MUST receive implementations via dependency injection

#### Scenario: Domain has no external dependencies
- **WHEN** checking domain layer imports
- **THEN** domain MUST only import from Python standard library and typing
- **AND** domain MUST NOT import from third-party libraries (except for type hints)
- **AND** domain MUST NOT import from CLI, application, or infrastructure layers

### Requirement: Dependency Injection

The system SHALL use dependency injection to manage dependencies and enable testability.

#### Scenario: DI container manages object creation
- **WHEN** application starts up
- **THEN** DI container MUST be configured with all service registrations
- **AND** services MUST be resolved from the container, not created directly
- **AND** container MUST support both singleton and transient lifetimes

#### Scenario: Services declare dependencies via constructor
- **WHEN** implementing a service class
- **THEN** constructor MUST declare all dependencies as typed parameters
- **AND** dependencies MUST be interfaces from domain layer, not concrete implementations
- **AND** constructor MUST NOT perform I/O or complex logic

#### Scenario: Test isolation uses mock implementations
- **WHEN** writing unit tests
- **THEN** test fixtures MUST provide a test DI container
- **AND** test container MUST register mock implementations for interfaces
- **AND** tests MUST be able to run in isolation without real infrastructure

### Requirement: Repository Pattern for Persistence

The system SHALL use repository pattern to abstract data access logic.

#### Scenario: Repository interfaces defined in domain
- **WHEN** domain needs data persistence
- **THEN** domain MUST define repository interfaces (e.g., `IPluginRepository`)
- **AND** interface MUST define methods for data operations (get, save, delete)
- **AND** interface MUST use domain entities/value objects, not DTOs

#### Scenario: Repository implementations in infrastructure
- **WHEN** implementing repository interfaces
- **THEN** implementations MUST be in infrastructure/persistence/
- **AND** implementations MUST handle all I/O operations asynchronously
- **AND** implementations MUST translate between domain objects and storage format

#### Scenario: Repositories injected into services
- **WHEN** application service needs data access
- **THEN** service MUST receive repository via constructor injection
- **AND** service MUST depend on interface, not concrete implementation
- **AND** service MUST NOT perform direct file I/O or database access

### Requirement: Application Services Orchestration

Application services SHALL orchestrate business workflows by coordinating domain objects and infrastructure.

#### Scenario: Application service implements use case
- **WHEN** implementing a user-facing operation
- **THEN** application service MUST coordinate the workflow
- **AND** service MUST delegate business logic to domain entities/services
- **AND** service MUST use repositories for data access
- **AND** service MUST return CommandResult or domain objects

#### Scenario: Application service has no business logic
- **WHEN** reviewing application service code
- **THEN** service MUST NOT contain business rules (those belong in domain)
- **AND** service MUST NOT contain I/O logic (that belongs in infrastructure)
- **AND** service MUST only orchestrate calls to domain and infrastructure

#### Scenario: Application service handles transactions
- **WHEN** use case requires multiple operations
- **THEN** application service MUST coordinate transactional boundaries
- **AND** service MUST handle rollback on failure
- **AND** service MUST ensure consistency across operations

### Requirement: Asynchronous Execution

The system SHALL use async/await patterns for all I/O operations to ensure non-blocking execution.

#### Scenario: All I/O operations are async
- **WHEN** implementing file I/O operations
- **THEN** code MUST use `aiofiles` for async file access
- **AND** code MUST use `await` for all file operations
- **AND** code MUST NOT use synchronous `open()` in async contexts

#### Scenario: Subprocess execution is async
- **WHEN** executing external commands
- **THEN** code MUST use `asyncio.create_subprocess_shell` or `asyncio.create_subprocess_exec`
- **AND** code MUST await process completion
- **AND** code MUST enforce timeout limits
- **AND** code MUST handle process cleanup properly

#### Scenario: Concurrent operations use gather
- **WHEN** multiple independent operations can run concurrently
- **THEN** code MUST use `asyncio.gather()` to run them in parallel
- **AND** code MUST handle partial failures appropriately
- **AND** code MUST NOT block on sequential operations that could be parallel

### Requirement: Error Handling Strategy

The system SHALL use CommandResult for expected operation outcomes and exceptions for unexpected errors.

#### Scenario: CommandResult for user operations
- **WHEN** implementing CLI command handlers
- **THEN** handlers MUST return CommandResult instances
- **AND** CommandResult.success MUST indicate operation outcome
- **AND** CommandResult.error MUST contain user-friendly error messages
- **AND** CommandResult.exit_code MUST reflect success (0) or failure (non-zero)

#### Scenario: Exceptions for programming errors
- **WHEN** encountering unexpected conditions
- **THEN** code MUST raise exceptions for programming errors (TypeError, ValueError)
- **AND** code MUST raise exceptions for unrecoverable system failures
- **AND** exceptions MUST NOT be used for expected validation failures

#### Scenario: Error context includes logging
- **WHEN** handling errors
- **THEN** error details MUST be logged with appropriate level (ERROR, WARNING)
- **AND** logs MUST include correlation IDs for tracing
- **AND** logs MUST NOT expose sensitive information
- **AND** user-facing errors MUST be internationalized

### Requirement: Plugin System Architecture

The system SHALL provide a plugin-based architecture supporting multiple plugin types with unified discovery and execution.

#### Scenario: Plugin types supported
- **WHEN** creating plugins
- **THEN** system MUST support Python plugins (decorator-based)
- **AND** system MUST support Shell plugins (annotation-based)
- **AND** system MUST support Config plugins (JSON-based)
- **AND** system MUST support Hybrid plugins (mixed types with subplugins)

#### Scenario: Plugin discovery is automatic
- **WHEN** system starts up
- **THEN** plugin loader MUST scan configured plugin directories
- **AND** loader MUST detect plugins by presence of plugin.json
- **AND** loader MUST determine plugin type from metadata
- **AND** loader MUST discover all functions/commands for each plugin

#### Scenario: Plugin execution is type-aware
- **WHEN** executing a plugin command
- **THEN** executor MUST route Shell/Config plugins to gs-router (shell execution)
- **AND** executor MUST route Python plugins to PluginExecutor (Python execution)
- **AND** executor MUST handle async function execution properly
- **AND** executor MUST enforce timeout limits

### Requirement: Testability by Design

The system architecture SHALL enable comprehensive testing with proper isolation.

#### Scenario: Unit tests use mocks
- **WHEN** writing unit tests
- **THEN** tests MUST use InMemoryFileSystem instead of real filesystem
- **AND** tests MUST use MockEnvironment instead of real environment
- **AND** tests MUST inject mocks via DI container
- **AND** tests MUST run without external dependencies

#### Scenario: Integration tests use real implementations
- **WHEN** writing integration tests
- **THEN** tests MUST use real implementations with temporary directories
- **AND** tests MUST clean up resources after execution
- **AND** tests MUST be idempotent and repeatable
- **AND** tests MUST NOT depend on external services

#### Scenario: Test fixtures are reusable
- **WHEN** creating test fixtures
- **THEN** fixtures MUST be defined in conftest.py
- **AND** fixtures MUST provide isolated instances per test
- **AND** fixtures MUST reset state between tests
- **AND** fixtures MUST be composable

### Requirement: No Circular Dependencies

The system SHALL be free of circular dependencies at all levels (module, class, package).

#### Scenario: Module imports are acyclic
- **WHEN** analyzing module imports
- **THEN** import graph MUST be a directed acyclic graph (DAG)
- **AND** no module MUST import from a module that depends on it
- **AND** circular imports MUST be detected by linting tools

#### Scenario: Dependency injection breaks cycles
- **WHEN** two components need to reference each other
- **THEN** one MUST depend on an interface defined in domain
- **AND** the other MUST implement that interface
- **AND** DI container MUST wire them together at runtime

#### Scenario: Cross-layer dependencies use interfaces
- **WHEN** infrastructure needs to call back to application
- **THEN** infrastructure MUST depend on domain interface
- **AND** application MUST implement the interface
- **AND** dependency direction MUST remain inward

### Requirement: Performance Optimization

The system architecture SHALL support high performance through async execution and efficient resource usage.

#### Scenario: Plugin discovery is fast
- **WHEN** loading 50 plugins
- **THEN** discovery MUST complete in less than 500ms
- **AND** discovery MUST use concurrent scanning where possible
- **AND** discovery MUST cache results appropriately

#### Scenario: Command execution has low overhead
- **WHEN** executing a plugin command
- **THEN** Python overhead MUST be less than 100ms
- **AND** Shell/Config plugin routing MUST be less than 10ms
- **AND** execution MUST not block other operations

#### Scenario: Resource cleanup is automatic
- **WHEN** operations complete or fail
- **THEN** file handles MUST be closed automatically (using context managers)
- **AND** subprocesses MUST be terminated on timeout
- **AND** memory MUST be released appropriately
