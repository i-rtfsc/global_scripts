# GUI Integration Specification

## ADDED Requirements

### Requirement: Menu Bar Application Lifecycle
The system SHALL provide lifecycle management for the macOS menu bar application, allowing users to start, stop, and check the status of the application.

#### Scenario: Start menu bar app successfully
- **WHEN** user runs `gs menubar start` and the app is not already running
- **THEN** the menu bar application launches in the background
- **AND** a status bar icon appears in the macOS menu bar
- **AND** a success message is displayed in the terminal

#### Scenario: Prevent duplicate instances
- **WHEN** user runs `gs menubar start` and the app is already running
- **THEN** no new instance is created
- **AND** an informative message indicates the app is already running
- **AND** the existing instance continues running

#### Scenario: Stop menu bar app
- **WHEN** user runs `gs menubar stop` or selects "Quit" from the menu bar
- **THEN** the menu bar application terminates gracefully
- **AND** the status bar icon is removed
- **AND** all monitoring threads are stopped cleanly

#### Scenario: Check app status
- **WHEN** user runs `gs menubar status`
- **THEN** the system reports whether the app is running or stopped
- **AND** if running, display the process ID and uptime

### Requirement: Platform Detection and Graceful Degradation
The system SHALL detect the operating system platform and gracefully handle non-macOS environments where rumps is unavailable.

#### Scenario: Run on macOS with rumps installed
- **WHEN** user runs menubar commands on macOS with rumps installed
- **THEN** the menu bar application functions normally

#### Scenario: Run on non-macOS platform
- **WHEN** user runs `gs menubar start` on Linux or Windows
- **THEN** a clear error message indicates this feature is macOS-only
- **AND** the command exits with a non-zero status code
- **AND** no crash or traceback occurs

#### Scenario: macOS without rumps dependency
- **WHEN** user runs menubar commands on macOS but rumps is not installed
- **THEN** a helpful error message suggests installing rumps
- **AND** provides the installation command: `uv add rumps`

### Requirement: Menu Bar UI Structure
The system SHALL display a menu bar icon with a dropdown menu containing metrics, command shortcuts, and application controls.

#### Scenario: Display menu structure
- **WHEN** user clicks the menu bar icon
- **THEN** a dropdown menu appears with the following sections:
  - **Metrics Section**: Current system temperature and other configured metrics
  - **Command Shortcuts Section**: User-defined GS command shortcuts
  - **Separator**
  - **Configuration**: "Preferences..." menu item
  - **Separator**
  - **Application Controls**: "Refresh", "About", "Quit"

#### Scenario: Menu bar icon reflects status
- **WHEN** no commands are running and monitoring is idle
- **THEN** the menu bar icon shows a default/idle state (e.g., "GS")
- **WHEN** a command is executing
- **THEN** the menu bar icon updates to show a running indicator (e.g., "GS ⚙️")

### Requirement: Command Execution from Menu Bar
The system SHALL allow users to execute configured GS commands directly from the menu bar and display results.

#### Scenario: Execute command successfully
- **WHEN** user selects a command shortcut from the menu (e.g., "ADB Devices")
- **THEN** the corresponding GS command executes asynchronously (e.g., `gs android adb devices`)
- **AND** the menu bar icon shows a running indicator
- **AND** upon completion, a notification or menu item shows the result summary
- **AND** the menu bar returns to idle state

#### Scenario: Execute command with failure
- **WHEN** a selected command fails (non-zero exit code)
- **THEN** an error notification or menu item displays the error message
- **AND** the menu bar returns to idle state
- **AND** the error is logged to the GS log file

#### Scenario: View command output
- **WHEN** user selects "View Last Output" from the menu
- **THEN** the full output of the last executed command is displayed in a notification or popup

### Requirement: Configuration Management
The system SHALL allow users to configure menu bar behavior, displayed metrics, and command shortcuts via the GS configuration system.

#### Scenario: Load default configuration
- **WHEN** the menu bar app starts for the first time
- **THEN** it loads default configuration from `config/gs.json`:
  - Refresh interval: 5 seconds
  - Enabled metrics: ["cpu_temperature"]
  - Command shortcuts: [] (empty by default)

#### Scenario: User customizes configuration
- **WHEN** user edits `~/.config/global-scripts/config/gs.json` to add:
  ```json
  "menubar": {
    "refresh_interval": 10,
    "enabled_metrics": ["cpu_temperature", "current_time"],
    "command_shortcuts": [
      {"label": "ADB Devices", "command": "gs android adb devices"},
      {"label": "Git Status", "command": "gs git status"}
    ]
  }
  ```
- **THEN** the menu bar app reflects these settings after restart or manual refresh

#### Scenario: Open preferences UI
- **WHEN** user selects "Preferences..." from the menu bar
- **THEN** the system opens the configuration file in the default editor
- **AND** provides instructions for editing menubar settings

### Requirement: Process Management
The system SHALL manage the menu bar application as a separate background process with proper lifecycle hooks and cleanup.

#### Scenario: Launch as background process
- **WHEN** user runs `gs menubar start`
- **THEN** a new Python process is spawned running the rumps application
- **AND** the process ID is stored in `~/.config/global-scripts/menubar.pid`
- **AND** the CLI command returns immediately after successful launch

#### Scenario: Detect orphaned processes
- **WHEN** the menu bar app crashes or is killed externally
- **THEN** the next `gs menubar status` command detects the stale PID
- **AND** cleans up the stale PID file
- **AND** reports the app as stopped

#### Scenario: Clean shutdown
- **WHEN** the menu bar app receives a termination signal (SIGTERM/SIGINT)
- **THEN** all monitoring threads stop gracefully
- **AND** the PID file is removed
- **AND** all resources are released before exit
