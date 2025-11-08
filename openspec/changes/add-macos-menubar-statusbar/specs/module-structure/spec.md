# Module Structure Specification Deltas

## MODIFIED Requirements

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
- **AND** menubar/ directory MUST exist for macOS menu bar application

#### Scenario: CLI layer structure
- **WHEN** organizing CLI code
- **THEN** cli/main.py MUST be the entry point
- **AND** cli/commands.py MUST handle command routing
- **AND** cli/formatters.py MUST handle output formatting
- **AND** cli/command_classes/ MUST contain command implementations
- **AND** cli/command_classes/menubar.py MUST implement menubar command

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

#### Scenario: Menu bar module structure
- **WHEN** organizing menu bar code
- **THEN** menubar/ directory MUST be at src/gscripts/menubar/
- **AND** menubar/__init__.py MUST exist
- **AND** menubar/app.py MUST contain the main rumps application
- **AND** menubar/monitors.py MUST contain metric monitor implementations
- **AND** menubar/executor.py MUST contain GS command execution integration
- **AND** menubar/config.py MUST contain menu bar configuration management
