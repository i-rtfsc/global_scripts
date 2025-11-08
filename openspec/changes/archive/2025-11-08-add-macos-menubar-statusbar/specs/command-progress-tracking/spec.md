# Command Progress Tracking Specification

## ADDED Requirements

### Requirement: Command Execution Tracking
The system SHALL track command execution lifecycle and report status to the menu bar app via IPC.

#### Scenario: Track command start
- **WHEN** PluginExecutor begins executing a command
- **AND** menu bar is enabled and running
- **THEN** executor sends IPC message: `{"type": "command_start", "command": "android adb devices", "timestamp": 1234567890}`
- **AND** starts an elapsed time counter

#### Scenario: Track command without menu bar
- **WHEN** PluginExecutor executes a command
- **AND** menu bar is not running or disabled
- **THEN** no IPC messages are sent
- **AND** command executes normally without tracking overhead

#### Scenario: Track nested command execution
- **WHEN** a plugin function calls another GS command internally
- **THEN** only the top-level command is tracked
- **AND** nested calls do not send separate IPC messages

### Requirement: Progress Reporting
The system SHALL allow commands to report progress percentage during execution.

#### Scenario: Command reports progress
- **WHEN** a plugin function yields progress updates (e.g., `yield {"progress": 45}`)
- **THEN** PluginExecutor sends IPC message: `{"type": "progress", "percentage": 45, "elapsed": 15.3}`
- **AND** menu bar updates immediately

#### Scenario: Command without progress reporting
- **WHEN** a command does not yield progress updates
- **THEN** menu bar shows elapsed time only
- **AND** no progress percentage is displayed

#### Scenario: Progress reporting for async operations
- **WHEN** a command performs async operations (file download, build)
- **THEN** the plugin can yield progress dicts at any point
- **AND** executor forwards them to menu bar in real-time

### Requirement: Command Completion Tracking
The system SHALL report command completion status with success/failure and duration.

#### Scenario: Command completes successfully
- **WHEN** a command returns `CommandResult(success=True)`
- **THEN** executor sends IPC message: `{"type": "command_complete", "success": true, "duration": 1.23}`
- **AND** menu bar displays success indicator (✓) with duration

#### Scenario: Command fails
- **WHEN** a command returns `CommandResult(success=False, error="...")`
- **THEN** executor sends IPC message: `{"type": "command_complete", "success": false, "duration": 0.5, "error": "error message"}`
- **AND** menu bar displays failure indicator (✗) with duration

#### Scenario: Command times out
- **WHEN** a command exceeds timeout limit
- **THEN** executor sends: `{"type": "command_complete", "success": false, "error": "Timeout after 30s", "duration": 30.0}`
- **AND** menu bar shows timeout error

#### Scenario: Command raises exception
- **WHEN** a command raises an unhandled exception
- **THEN** executor sends: `{"type": "command_complete", "success": false, "error": "Exception: ...", "duration": X}`
- **AND** menu bar shows error status

### Requirement: CPU Temperature Monitoring
The system SHALL collect and display CPU temperature in the menu bar dropdown (if enabled).

#### Scenario: Display temperature on macOS with sensors
- **WHEN** menu bar app is running and `show_temperature: true`
- **THEN** the dropdown menu shows: "CPU: 45°C"
- **AND** temperature updates every 5 seconds

#### Scenario: Temperature unavailable
- **WHEN** temperature sensors are not accessible
- **THEN** the dropdown shows: "CPU: N/A"
- **AND** no error is logged after the first attempt

#### Scenario: Temperature monitoring disabled
- **WHEN** user sets `show_temperature: false` in config
- **THEN** no temperature is displayed in dropdown
- **AND** no sensor reads are attempted

### Requirement: Status Display Formatting
The system SHALL format command status for menu bar display with consistent conventions.

#### Scenario: Format running command
- **WHEN** command is running with progress
- **THEN** menu bar shows: "GS: android.adb.devices 45% 2m15s"
- **AND** format is: `GS: <plugin>.<function> <progress>% <elapsed>`

#### Scenario: Format running command without progress
- **WHEN** command is running without progress reporting
- **THEN** menu bar shows: "GS: system.prompt.set 0m05s"
- **AND** format is: `GS: <plugin>.<function> <elapsed>`

#### Scenario: Format completed command (success)
- **WHEN** command completes successfully
- **THEN** menu bar shows: "GS: ✓ android.adb.devices 1.2s"
- **AND** format is: `GS: ✓ <plugin>.<function> <duration>s`

#### Scenario: Format completed command (failure)
- **WHEN** command fails
- **THEN** menu bar shows: "GS: ✗ android.build.aosp 30.0s"
- **AND** format is: `GS: ✗ <plugin>.<function> <duration>s`

#### Scenario: Truncate long command names
- **WHEN** plugin.function name exceeds 30 characters
- **THEN** it is truncated with ellipsis: "GS: very.long.plugin.na... 45% 1m"
- **AND** full name is visible in dropdown menu

### Requirement: IPC Message Protocol
The system SHALL use a simple JSON-based protocol for CLI → menu bar communication.

#### Scenario: Send command_start message
- **WHEN** command starts
- **THEN** message format is:
  ```json
  {
    "type": "command_start",
    "command": "android.adb.devices",
    "timestamp": 1234567890.123
  }
  ```

#### Scenario: Send progress_update message
- **WHEN** command reports progress
- **THEN** message format is:
  ```json
  {
    "type": "progress_update",
    "percentage": 45,
    "elapsed": 15.3
  }
  ```

#### Scenario: Send command_complete message
- **WHEN** command completes
- **THEN** message format is:
  ```json
  {
    "type": "command_complete",
    "success": true,
    "duration": 1.23,
    "error": null
  }
  ```

#### Scenario: Handle malformed messages gracefully
- **WHEN** menu bar receives invalid JSON or unknown message type
- **THEN** it logs a warning
- **AND** ignores the message
- **AND** continues processing future messages

### Requirement: IPC Transport Mechanism
The system SHALL use Unix domain sockets for CLI → menu bar communication on macOS.

#### Scenario: Create IPC socket on menu bar startup
- **WHEN** menu bar app starts
- **THEN** it creates a Unix socket at `~/.config/global-scripts/menubar.sock`
- **AND** listens for incoming connections
- **AND** accepts multiple concurrent connections (one per CLI command)

#### Scenario: CLI connects to socket
- **WHEN** CLI needs to send a message
- **THEN** it connects to `menubar.sock`
- **AND** sends JSON message followed by newline
- **AND** closes connection (or keeps open for duration)

#### Scenario: Socket cleanup on quit
- **WHEN** menu bar app quits
- **THEN** it removes the socket file
- **AND** closes all active connections gracefully

#### Scenario: Handle missing socket file
- **WHEN** CLI tries to connect but socket doesn't exist
- **THEN** CLI silently skips sending the message
- **AND** logs a debug message: "Menu bar not running (socket not found)"
- **AND** command execution continues normally
