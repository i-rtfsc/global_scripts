# API Design Specification Deltas

## ADDED Requirements

### Requirement: Menu Bar Command API

The system SHALL provide a CLI command API for managing the macOS menu bar application lifecycle.

#### Scenario: menubar start command
- **WHEN** user runs `gs menubar start`
- **THEN** command MUST launch the menu bar application as a background process
- **AND** command MUST return CommandResult with success=True if launch succeeds
- **AND** command MUST store the process ID in `~/.config/global-scripts/menubar.pid`
- **AND** command MUST return immediately after successful spawn (not block)

#### Scenario: menubar stop command
- **WHEN** user runs `gs menubar stop`
- **THEN** command MUST read the PID from menubar.pid
- **AND** command MUST send SIGTERM to the process
- **AND** command MUST wait up to 5 seconds for graceful shutdown
- **AND** command MUST return CommandResult with success=True if process stops
- **AND** command MUST remove the PID file after shutdown

#### Scenario: menubar status command
- **WHEN** user runs `gs menubar status`
- **THEN** command MUST check if the PID in menubar.pid is running
- **AND** command MUST return formatted status (Running/Stopped)
- **AND** if running, output MUST include PID and uptime
- **AND** command MUST detect and clean up stale PID files

#### Scenario: menubar config command
- **WHEN** user runs `gs menubar config`
- **THEN** command MUST open the GS config file in default editor
- **AND** command MUST highlight the menubar configuration section
- **AND** command MUST provide inline documentation comments

### Requirement: Menu Bar Process Management API

The system SHALL provide programmatic APIs for managing the menu bar application process lifecycle.

#### Scenario: Launch menu bar process
- **WHEN** calling menubar.launch()
- **THEN** function MUST spawn a new Python process running the rumps app
- **AND** function MUST use subprocess.Popen with detach=True
- **AND** function MUST redirect stdout/stderr to log file
- **AND** function MUST return the process ID

#### Scenario: Check if menu bar is running
- **WHEN** calling menubar.is_running()
- **THEN** function MUST read menubar.pid file
- **AND** function MUST check if process with that PID exists
- **AND** function MUST verify the process is actually the menubar app (not recycled PID)
- **AND** function MUST return boolean (True if running)

#### Scenario: Stop menu bar process
- **WHEN** calling menubar.stop()
- **THEN** function MUST send SIGTERM to the process
- **AND** function MUST wait for process to exit (timeout: 5s)
- **AND** function MUST send SIGKILL if SIGTERM fails
- **AND** function MUST clean up PID file
- **AND** function MUST return CommandResult indicating success/failure
