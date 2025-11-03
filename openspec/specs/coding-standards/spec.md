# Coding Standards Specification

## Purpose

This specification defines coding standards, naming conventions, and code quality requirements for Global Scripts V5.

## Requirements

### Requirement: Naming Conventions

The system SHALL follow consistent naming conventions across all code.

#### Scenario: File naming uses snake_case
- **WHEN** creating Python module files
- **THEN** file names MUST use snake_case (e.g., `plugin_manager.py`)
- **AND** file names MUST be descriptive of their contents
- **AND** file names MUST NOT use abbreviations unless widely understood

#### Scenario: Class naming uses PascalCase
- **WHEN** defining classes
- **THEN** class names MUST use PascalCase (e.g., `PluginManager`, `CommandResult`)
- **AND** interface names MUST use `I` prefix (e.g., `IPluginRepository`, `IFileSystem`)
- **AND** abstract base classes MAY use `Base` prefix (e.g., `BasePlugin`)

#### Scenario: Function and method naming uses snake_case
- **WHEN** defining functions or methods
- **THEN** names MUST use snake_case (e.g., `load_plugin()`, `execute_command()`)
- **AND** async functions MUST use `async def` keyword
- **AND** function names MUST be verbs or verb phrases describing the action

#### Scenario: Constants use UPPER_SNAKE_CASE
- **WHEN** defining constants
- **THEN** constant names MUST use UPPER_SNAKE_CASE (e.g., `DEFAULT_TIMEOUT`, `MAX_RETRIES`)
- **AND** constants MUST be defined at module level
- **AND** constants MUST be truly constant (not modified at runtime)

#### Scenario: Private members use leading underscore
- **WHEN** defining private attributes or methods
- **THEN** names MUST start with single underscore (e.g., `_internal_method()`, `_cache`)
- **AND** truly private attributes MAY use double underscore for name mangling
- **AND** protected members (for subclass use) MUST use single underscore

### Requirement: Type Annotations

All public functions and methods SHALL have complete type annotations.

#### Scenario: Function signatures are fully typed
- **WHEN** defining a public function
- **THEN** all parameters MUST have type annotations
- **AND** return type MUST be annotated
- **AND** Optional types MUST be explicit (use `Optional[T]` not just `T`)

#### Scenario: Complex types are properly annotated
- **WHEN** using collections as types
- **THEN** generic types MUST be fully specified (e.g., `Dict[str, Any]` not `dict`)
- **AND** List, Dict, Tuple MUST come from typing module for Python 3.8 compatibility
- **AND** Union types MUST be used for multiple possible types

#### Scenario: Type hints support static analysis
- **WHEN** running mypy static type checker
- **THEN** code MUST pass mypy checks without errors
- **AND** type: ignore comments MUST include justification
- **AND** Any type MUST be avoided unless absolutely necessary

#### Scenario: Return types are explicit
- **WHEN** function returns a value
- **THEN** return type MUST be annotated (e.g., `-> CommandResult`)
- **AND** functions returning nothing MUST use `-> None`
- **AND** async functions MUST use `-> Coroutine[...]` or proper async return type

### Requirement: Code Formatting

The system SHALL use Black code formatter with standard configuration.

#### Scenario: Black formatting is applied
- **WHEN** writing or modifying code
- **THEN** code MUST be formatted with Black
- **AND** line length MUST be 88 characters (Black default)
- **AND** Black formatting MUST be enforced by CI/CD

#### Scenario: Import organization follows standard
- **WHEN** organizing imports
- **THEN** imports MUST be grouped in three sections:
  1. Standard library imports
  2. Third-party imports
  3. Local application imports
- **AND** each section MUST be separated by a blank line
- **AND** imports within sections MUST be alphabetically sorted

#### Scenario: String formatting uses f-strings
- **WHEN** formatting strings
- **THEN** f-strings MUST be preferred over .format() or % formatting
- **AND** f-strings MUST be used for variable interpolation
- **AND** template strings (Jinja2) MUST be used for multi-line templates

#### Scenario: Quotes are consistent
- **WHEN** writing string literals
- **THEN** single quotes MUST be used for dict keys and internal strings
- **AND** double quotes MUST be used for user-facing messages
- **AND** triple double-quotes MUST be used for docstrings

### Requirement: Linting and Code Quality

The system SHALL use Ruff for linting and enforce code quality standards.

#### Scenario: Ruff checks pass
- **WHEN** running Ruff linter
- **THEN** code MUST pass all Ruff checks without errors
- **AND** warnings SHOULD be addressed before merging
- **AND** ruff.toml configuration MUST be followed

#### Scenario: Code complexity is limited
- **WHEN** writing functions
- **THEN** cyclomatic complexity MUST be under 10
- **AND** functions SHOULD be under 50 lines
- **AND** deeply nested code (>4 levels) MUST be refactored

#### Scenario: Dead code is removed
- **WHEN** refactoring or removing features
- **THEN** unused imports MUST be removed
- **AND** commented-out code MUST be deleted
- **AND** unreachable code MUST be eliminated

### Requirement: Documentation Standards

All public APIs SHALL have comprehensive documentation.

#### Scenario: Docstrings are complete
- **WHEN** defining public classes, functions, or methods
- **THEN** docstring MUST describe purpose and behavior
- **AND** docstring MUST document all parameters
- **AND** docstring MUST document return value
- **AND** docstring MUST document exceptions raised

#### Scenario: Docstring format is consistent
- **WHEN** writing docstrings
- **THEN** format MUST use triple double-quotes `"""`
- **AND** first line MUST be a concise summary
- **AND** detailed description MUST follow after blank line
- **AND** parameters and return values MUST be documented

#### Scenario: Code comments explain why, not what
- **WHEN** adding inline comments
- **THEN** comments MUST explain reasoning, not restate code
- **AND** complex algorithms MUST have explanatory comments
- **AND** TODO comments MUST include issue numbers or assignees

#### Scenario: Examples are provided for complex APIs
- **WHEN** documenting complex public APIs
- **THEN** docstring SHOULD include usage examples
- **AND** examples MUST be valid Python code
- **AND** examples SHOULD demonstrate common use cases

### Requirement: Error Messages and Logging

Error messages and logs SHALL be clear, actionable, and internationalized.

#### Scenario: Error messages are user-friendly
- **WHEN** returning error in CommandResult
- **THEN** error message MUST be clear and actionable
- **AND** error message MUST suggest how to fix the problem
- **AND** error message MUST be internationalized (zh/en)

#### Scenario: Logging uses structured format
- **WHEN** writing log statements
- **THEN** logs MUST use correlation IDs for request tracing
- **AND** logs MUST include appropriate context (file, line, function)
- **AND** logs MUST use appropriate log levels (DEBUG, INFO, WARNING, ERROR)

#### Scenario: Sensitive data is not logged
- **WHEN** logging information
- **THEN** passwords and secrets MUST be redacted
- **AND** file paths MUST be sanitized to avoid exposing user directories
- **AND** personal information MUST NOT be logged

#### Scenario: Log levels are appropriate
- **WHEN** choosing log level
- **THEN** DEBUG MUST be used for detailed diagnostic information
- **AND** INFO MUST be used for significant events
- **AND** WARNING MUST be used for unexpected but handled situations
- **AND** ERROR MUST be used for failures requiring attention

### Requirement: Async/Await Patterns

The system SHALL follow async/await best practices for all asynchronous code.

#### Scenario: Async functions use async def
- **WHEN** writing functions that perform I/O
- **THEN** function MUST be declared with `async def`
- **AND** function MUST await all async operations
- **AND** function MUST NOT mix sync and async I/O

#### Scenario: Blocking operations are avoided
- **WHEN** implementing async functions
- **THEN** function MUST NOT use synchronous I/O (open, requests.get, etc.)
- **AND** function MUST use async libraries (aiofiles, aiohttp, etc.)
- **AND** CPU-bound work MUST be delegated to executor if necessary

#### Scenario: Concurrent operations use gather
- **WHEN** running multiple async operations
- **THEN** `asyncio.gather()` MUST be used for concurrent execution
- **AND** gather MUST be used instead of sequential awaits when operations are independent
- **AND** error handling MUST account for partial failures

#### Scenario: Async context managers are used
- **WHEN** managing resources in async code
- **THEN** async context managers MUST be used (`async with`)
- **AND** resources MUST be properly cleaned up on exit
- **AND** exceptions MUST be handled appropriately

### Requirement: Testing Standards

All new code SHALL have corresponding tests with adequate coverage.

#### Scenario: Unit tests are written
- **WHEN** implementing new functionality
- **THEN** unit tests MUST be written for public functions/methods
- **AND** tests MUST achieve minimum 80% line coverage
- **AND** tests MUST run in isolation using mocks

#### Scenario: Test naming is descriptive
- **WHEN** writing test methods
- **THEN** test name MUST follow pattern `test_<method>_<scenario>_<expected_outcome>`
- **AND** test docstring MUST describe what is being tested
- **AND** test class name MUST be `Test<ClassName>`

#### Scenario: Tests use arrange-act-assert pattern
- **WHEN** structuring test code
- **THEN** test MUST have clear arrange section (setup)
- **AND** test MUST have clear act section (execute operation)
- **AND** test MUST have clear assert section (verify results)

#### Scenario: Tests are independent and repeatable
- **WHEN** running tests
- **THEN** tests MUST NOT depend on execution order
- **AND** tests MUST clean up state after execution
- **AND** tests MUST produce same result on repeated runs

### Requirement: Import Standards

Import statements SHALL follow consistent patterns to avoid circular dependencies.

#### Scenario: Absolute imports are preferred
- **WHEN** importing modules
- **THEN** absolute imports MUST be used (e.g., `from gscripts.core import PluginManager`)
- **AND** relative imports SHOULD be avoided unless within the same package
- **AND** circular imports MUST be prevented through proper architecture

#### Scenario: Type-only imports are separate
- **WHEN** importing for type hints only
- **THEN** imports used only for typing SHOULD use `if TYPE_CHECKING:`
- **AND** runtime imports MUST NOT be in TYPE_CHECKING block
- **AND** this pattern MUST be used to break circular import dependencies

#### Scenario: Import order follows convention
- **WHEN** organizing imports
- **THEN** standard library imports MUST come first
- **AND** third-party imports MUST come second
- **AND** local application imports MUST come last
- **AND** each group MUST be alphabetically sorted

### Requirement: Python Version Compatibility

Code SHALL be compatible with Python 3.8+ to support Ubuntu 20.04 LTS.

#### Scenario: Python 3.8 features only
- **WHEN** using Python language features
- **THEN** code MUST NOT use Python 3.9+ exclusive features
- **AND** code MUST use `typing.List` instead of `list[...]` for generics
- **AND** code MUST avoid walrus operator `:=` in critical paths

#### Scenario: Type hints use typing module
- **WHEN** adding type annotations
- **THEN** List, Dict, Tuple MUST be imported from typing module
- **AND** Optional MUST be imported from typing module
- **AND** Union MUST be imported from typing module

#### Scenario: Compatibility is tested
- **WHEN** running CI/CD pipeline
- **THEN** tests MUST run on Python 3.8
- **AND** tests MUST run on Python 3.9, 3.10, 3.11
- **AND** syntax errors MUST be caught for unsupported features

### Requirement: Code Organization

Code SHALL be organized into cohesive modules with single responsibilities.

#### Scenario: Modules have single purpose
- **WHEN** creating a module
- **THEN** module MUST have a single, well-defined purpose
- **AND** module name MUST reflect its purpose
- **AND** module SHOULD be understandable in 10 minutes

#### Scenario: Files are appropriately sized
- **WHEN** writing module files
- **THEN** files SHOULD be under 500 lines
- **AND** files over 1000 lines MUST be split into multiple modules
- **AND** related functionality SHOULD be grouped together

#### Scenario: Circular dependencies are prevented
- **WHEN** organizing modules
- **THEN** import graph MUST be acyclic
- **AND** dependency injection MUST be used to break cycles
- **AND** interfaces MUST be used to invert dependencies

### Requirement: Security Best Practices

Code SHALL follow security best practices to prevent common vulnerabilities.

#### Scenario: Input validation is performed
- **WHEN** accepting user input
- **THEN** input MUST be validated before use
- **AND** dangerous characters MUST be sanitized for shell commands
- **AND** path traversal MUST be prevented for file operations

#### Scenario: Command injection is prevented
- **WHEN** executing shell commands
- **THEN** arguments MUST be quoted using `shlex.quote()`
- **AND** user input MUST NOT be directly interpolated into commands
- **AND** command whitelist/blacklist MUST be enforced

#### Scenario: Secrets are not hardcoded
- **WHEN** handling credentials or secrets
- **THEN** secrets MUST NOT be hardcoded in source
- **AND** secrets MUST be loaded from environment or config
- **AND** secrets MUST NOT be logged or exposed in errors

#### Scenario: Timeouts are enforced
- **WHEN** executing external processes
- **THEN** timeout MUST be specified (default 30s)
- **AND** processes MUST be terminated on timeout
- **AND** timeout values MUST be configurable

### Requirement: Performance Considerations

Code SHALL be written with performance in mind while maintaining readability.

#### Scenario: Unnecessary work is avoided
- **WHEN** implementing algorithms
- **THEN** unnecessary iterations MUST be eliminated
- **AND** expensive operations MUST be cached when appropriate
- **AND** lazy evaluation SHOULD be used where beneficial

#### Scenario: I/O is asynchronous
- **WHEN** performing I/O operations
- **THEN** async I/O MUST be used to avoid blocking
- **AND** concurrent I/O SHOULD be used when operations are independent
- **AND** I/O batching SHOULD be used when processing multiple items

#### Scenario: Memory usage is optimized
- **WHEN** processing large data
- **THEN** generators SHOULD be used instead of lists where appropriate
- **AND** large objects MUST NOT be kept in memory unnecessarily
- **AND** resources MUST be released promptly using context managers

#### Scenario: Performance is measured
- **WHEN** optimizing code
- **THEN** performance MUST be measured before optimization
- **AND** optimization MUST be based on profiling data
- **AND** premature optimization MUST be avoided
