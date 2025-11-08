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

#### Scenario: Menu bar module structure
- **WHEN** organizing menu bar code
- **THEN** menubar/ directory MUST be at src/gscripts/menubar/
- **AND** menubar/__init__.py MUST exist
- **AND** menubar/app.py MUST contain the main rumps application
- **AND** menubar/ipc.py MUST contain IPC socket server and client
- **AND** menubar/monitors.py MUST contain CPU temperature and memory monitors
- **AND** menubar/status_manager.py MUST manage command status display formatting
- **AND** menubar/__main__.py MUST provide entry point for background process
