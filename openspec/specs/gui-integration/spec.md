# gui-integration Specification

## Purpose
TBD - created by archiving change add-macos-menubar-statusbar. Update Purpose after archive.
## Requirements
### Requirement: Menu Bar Application Auto-Start
The system SHALL automatically start the menu bar application when GS commands are executed, if menu bar is enabled in configuration.

#### Scenario: Auto-start on first command execution
- **WHEN** user runs any `gs` command and `menubar.enabled: true` in config
- **AND** the menu bar app is not already running
- **THEN** the CLI automatically spawns the menu bar app as a background process
- **AND** the command proceeds normally without blocking

#### Scenario: Skip auto-start when disabled
- **WHEN** user runs any `gs` command and `menubar.enabled: false` in config
- **THEN** no menu bar app is started
- **AND** no IPC communication is attempted
- **AND** command execution is unaffected

#### Scenario: Reuse existing menu bar process
- **WHEN** user runs a `gs` command and menu bar app is already running
- **THEN** no new process is spawned
- **AND** the existing app receives command updates via IPC

### Requirement: Menu Bar Process Lifecycle
The system SHALL manage the menu bar application as a detached background process with automatic cleanup.

#### Scenario: Spawn background process
- **WHEN** menu bar app is auto-started
- **THEN** a new Python process is spawned running the rumps application
- **AND** the process is detached from the parent CLI process
- **AND** stdout/stderr are redirected to `~/.config/global-scripts/logs/menubar.log`
- **AND** the process ID is stored in `~/.config/global-scripts/menubar.pid`

#### Scenario: Menu bar survives CLI exit
- **WHEN** a GS command completes and the CLI process exits
- **THEN** the menu bar app continues running in the background
- **AND** the menu bar remains visible and responsive

#### Scenario: User quits menu bar manually
- **WHEN** user selects "Quit" from the menu bar dropdown
- **THEN** the menu bar app terminates gracefully
- **AND** the PID file is removed
- **AND** next `gs` command will auto-start a new instance (if enabled)

#### Scenario: Clean up on system shutdown
- **WHEN** macOS shuts down or user logs out
- **THEN** the menu bar app receives termination signal (SIGTERM)
- **AND** performs cleanup (remove PID file, close log files)
- **AND** exits within 2 seconds

### Requirement: Menu Bar UI Structure
The system SHALL display a minimal menu bar with status text and a simple dropdown menu.

#### Scenario: Display idle status
- **WHEN** no GS commands are running
- **THEN** the menu bar shows "GS" text with idle icon
- **AND** clicking opens a dropdown with: CPU temperature, memory usage, separator, "Quit"

#### Scenario: Display running command status
- **WHEN** a GS command is executing
- **THEN** the menu bar title updates to show: command name, progress %, elapsed time
- **AND** the format is: "GS: [cmd] 45% 2m15s"
- **AND** the dropdown shows CPU temperature, memory usage, separator, "Quit"

#### Scenario: Display completion status
- **WHEN** a GS command completes
- **THEN** the menu bar shows: "GS: ✓ [cmd] 1.2s" (success) or "GS: ✗ [cmd] 0.5s" (failure)
- **AND** the status remains visible for 5 seconds
- **AND** then reverts to idle state

### Requirement: Platform Detection and Graceful Degradation
The system SHALL detect the operating system and gracefully handle non-macOS environments.

#### Scenario: Run on macOS with rumps installed
- **WHEN** GS commands run on macOS with rumps available
- **AND** menubar is enabled in config
- **THEN** the menu bar functions normally

#### Scenario: Run on non-macOS platform
- **WHEN** GS runs on Linux or Windows
- **AND** menubar is enabled in config
- **THEN** the auto-start is silently skipped (no error)
- **AND** commands execute normally without menu bar
- **AND** a debug log message notes "Menu bar not available (non-macOS)"

#### Scenario: macOS without rumps dependency
- **WHEN** GS runs on macOS but rumps is not installed
- **AND** menubar is enabled
- **THEN** auto-start is skipped
- **AND** a warning message suggests: "Install rumps for menu bar: uv sync"
- **AND** commands execute normally without menu bar

### Requirement: IPC Communication Between CLI and Menu Bar
The system SHALL provide inter-process communication for CLI to send command status updates to the menu bar app.

#### Scenario: Establish IPC connection on command start
- **WHEN** CLI starts executing a command and menu bar is running
- **THEN** CLI opens IPC connection (socket or named pipe) to menu bar
- **AND** sends "command_start" message with command name
- **AND** connection remains open for duration of command

#### Scenario: Send progress updates
- **WHEN** a command reports progress (e.g., download percentage)
- **THEN** CLI sends "progress_update" message with: percentage, elapsed_time
- **AND** menu bar updates display immediately (< 100ms latency)

#### Scenario: Send completion status
- **WHEN** a command completes
- **THEN** CLI sends "command_complete" message with: success, duration, error (if any)
- **AND** closes IPC connection
- **AND** menu bar displays final status

#### Scenario: Handle IPC failures gracefully
- **WHEN** IPC connection fails (menu bar crashed or not running)
- **THEN** CLI logs a debug message
- **AND** command execution continues unaffected
- **AND** no error is shown to user

### Requirement: Configuration Management
The system SHALL use the existing GS configuration system to manage menu bar settings.

#### Scenario: Load default configuration
- **WHEN** no user configuration exists
- **THEN** the system loads default from `config/gs.json`:
  ```json
  {
    "menubar": {
      "enabled": false,
      "refresh_interval": 5,
      "show_cpu_temp": true,
      "show_memory": true
    }
  }
  ```

#### Scenario: User enables menu bar
- **WHEN** user sets `menubar.enabled: true` in `~/.config/global-scripts/config/gs.json`
- **THEN** next `gs` command will auto-start the menu bar app
- **AND** subsequent commands will use IPC to update status

#### Scenario: User disables metrics display
- **WHEN** user sets `menubar.show_cpu_temp: false` or `menubar.show_memory: false`
- **THEN** menu bar app (after restart) does not display disabled metrics in dropdown
- **AND** still shows enabled metrics and "Quit" option

#### Scenario: Configuration changes require restart
- **WHEN** user edits menu bar config while app is running
- **THEN** changes take effect only after quitting and restarting menu bar
- **AND** user must manually quit (select "Quit" from menu) or wait for next command to auto-restart

