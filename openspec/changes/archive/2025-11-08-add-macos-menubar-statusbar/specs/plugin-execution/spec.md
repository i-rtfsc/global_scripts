# Plugin Execution Specification Deltas

## ADDED Requirements

### Requirement: Command Progress Reporting
The system SHALL provide hooks for plugin functions to report progress during execution, which are forwarded to the menu bar (if enabled).

#### Scenario: Plugin yields progress updates
- **WHEN** a plugin function is a generator that yields progress dicts
- **THEN** PluginExecutor MUST detect the generator
- **AND** executor MUST iterate and collect yielded progress values
- **AND** executor MUST send progress to menu bar via IPC (if enabled)
- **AND** final return value MUST be used as CommandResult

#### Scenario: Progress format validation
- **WHEN** plugin yields a dict with "progress" key
- **THEN** value MUST be an integer between 0-100 (percentage)
- **AND** invalid values MUST be ignored with warning log
- **AND** execution continues normally

#### Scenario: No progress reporting (standard functions)
- **WHEN** plugin function returns CommandResult directly (not a generator)
- **THEN** no progress updates are sent
- **AND** only start and complete events are sent to menu bar
- **AND** execution is unchanged from current behavior
