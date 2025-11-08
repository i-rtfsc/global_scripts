# Implementation Tasks

## 1. Project Setup and Dependencies

- [ ] 1.1 Add `rumps>=0.4.0` to pyproject.toml with macOS platform marker
- [ ] 1.2 Add `psutil>=5.9.0` to pyproject.toml for system metrics
- [ ] 1.3 Run `uv sync` to install new dependencies
- [ ] 1.4 Verify rumps installation on macOS test environment
- [ ] 1.5 Update requirements documentation in docs/

## 2. Core Module Structure

- [ ] 2.1 Create `src/gscripts/menubar/__init__.py` with module exports
- [ ] 2.2 Create `src/gscripts/menubar/app.py` with empty rumps.App skeleton
- [ ] 2.3 Create `src/gscripts/menubar/monitors.py` with BaseMonitor abstract class
- [ ] 2.4 Create `src/gscripts/menubar/executor.py` with GS command execution wrapper
- [ ] 2.5 Create `src/gscripts/menubar/config.py` with configuration loader
- [ ] 2.6 Add __all__ exports to menubar/__init__.py

## 3. Configuration System

- [ ] 3.1 Add default menubar configuration to `config/gs.json`:
  ```json
  "menubar": {
    "enabled": false,
    "refresh_interval": 5,
    "enabled_metrics": ["cpu_temperature"],
    "command_shortcuts": [],
    "time_format": "%H:%M:%S"
  }
  ```
- [ ] 3.2 Add i18n messages to `config/messages/zh.json` (menubar namespace)
- [ ] 3.3 Add i18n messages to `config/messages/en.json` (menubar namespace)
- [ ] 3.4 Implement MenuBarConfig dataclass in config.py with validation
- [ ] 3.5 Add configuration schema documentation to menubar module docstring

## 4. System Monitoring Implementation

- [ ] 4.1 Implement BaseMonitor abstract class with collect() and format() methods
- [ ] 4.2 Implement CPUTemperatureMonitor using psutil and fallback methods
- [ ] 4.3 Implement CurrentTimeMonitor as simple example monitor
- [ ] 4.4 Create monitor registry system for dynamic monitor loading
- [ ] 4.5 Implement background update thread with configurable interval
- [ ] 4.6 Add error handling and graceful degradation for unavailable sensors
- [ ] 4.7 Implement metric value caching with staleness detection

## 5. Menu Bar Application (rumps)

- [ ] 5.1 Implement MenuBarApp(rumps.App) main application class
- [ ] 5.2 Initialize app with title and icon in __init__
- [ ] 5.3 Create menu structure with sections (metrics, commands, controls)
- [ ] 5.4 Implement update_metrics() method to refresh menu display
- [ ] 5.5 Implement background thread for periodic metric updates
- [ ] 5.6 Add "Refresh" menu item with manual update handler
- [ ] 5.7 Add "About" menu item with version info
- [ ] 5.8 Add "Preferences..." menu item to open config file
- [ ] 5.9 Implement quit handler with cleanup

## 6. Command Execution Integration

- [ ] 6.1 Implement execute_gs_command(command: str) in executor.py
- [ ] 6.2 Use asyncio subprocess for command execution
- [ ] 6.3 Parse command output and exit code into CommandResult
- [ ] 6.4 Implement command result caching (last 10 results)
- [ ] 6.5 Add menu items for configured command shortcuts
- [ ] 6.6 Display command execution status in menu bar title/icon
- [ ] 6.7 Show command results in menu dropdown
- [ ] 6.8 Add "View Last Output" menu item for detailed results
- [ ] 6.9 Handle command errors with user-friendly messages

## 7. CLI Command Implementation

- [ ] 7.1 Create `src/gscripts/cli/command_classes/menubar.py`
- [ ] 7.2 Implement menubar_start_command(args) -> CommandResult
- [ ] 7.3 Implement menubar_stop_command(args) -> CommandResult
- [ ] 7.4 Implement menubar_status_command(args) -> CommandResult
- [ ] 7.5 Implement menubar_config_command(args) -> CommandResult
- [ ] 7.6 Register menubar command in cli/commands.py
- [ ] 7.7 Add menubar subcommand parser with start/stop/status/config
- [ ] 7.8 Add help text and usage examples for menubar command

## 8. Process Management

- [ ] 8.1 Implement PID file management (write_pid, read_pid, remove_pid)
- [ ] 8.2 Implement process spawning with subprocess.Popen(detach=True)
- [ ] 8.3 Redirect stdout/stderr to `~/.config/global-scripts/logs/menubar.log`
- [ ] 8.4 Implement is_running() with PID validation
- [ ] 8.5 Implement graceful shutdown with SIGTERM (5s timeout) + SIGKILL
- [ ] 8.6 Detect and clean up stale PID files
- [ ] 8.7 Handle signal handlers (SIGTERM, SIGINT) in rumps app

## 9. Platform Detection and Graceful Degradation

- [ ] 9.1 Add platform detection in menubar/__init__.py (sys.platform check)
- [ ] 9.2 Raise clear error if menubar commands run on non-macOS
- [ ] 9.3 Add try/except for rumps import with helpful error message
- [ ] 9.4 Add platform check to CLI command handlers
- [ ] 9.5 Document platform limitations in help text and docs

## 10. Testing

- [ ] 10.1 Write unit tests for monitors.py (mock psutil)
- [ ] 10.2 Write unit tests for executor.py (mock subprocess)
- [ ] 10.3 Write unit tests for config.py (test validation)
- [ ] 10.4 Write integration tests for menubar CLI commands
- [ ] 10.5 Write integration test for process lifecycle (start/stop/status)
- [ ] 10.6 Create manual testing checklist in tests/manual/test_menubar_ui.md
- [ ] 10.7 Test error handling (missing dependencies, failed commands)
- [ ] 10.8 Test configuration changes (edit config, verify menu updates)
- [ ] 10.9 Run full test suite: `pytest tests/ -v --cov`

## 11. Documentation

- [ ] 11.1 Create `docs/menubar-guide.md` with user guide
- [ ] 11.2 Document installation (uv sync, platform requirements)
- [ ] 11.3 Document configuration options with examples
- [ ] 11.4 Document how to add custom command shortcuts
- [ ] 11.5 Add troubleshooting section (common errors, fixes)
- [ ] 11.6 Update CLAUDE.md with menubar development guidance
- [ ] 11.7 Update README.md features list to include menu bar
- [ ] 11.8 Add docstrings to all menubar module classes and functions

## 12. Code Quality and Validation

- [ ] 12.1 Run Black formatter: `black src/gscripts/menubar/`
- [ ] 12.2 Run Ruff linter: `ruff check src/gscripts/menubar/ --fix`
- [ ] 12.3 Run MyPy type checker: `mypy src/gscripts/menubar/`
- [ ] 12.4 Verify all functions have type annotations
- [ ] 12.5 Add logging with correlation IDs to menubar operations
- [ ] 12.6 Review code for security issues (command injection, path traversal)
- [ ] 12.7 Validate OpenSpec proposal: `openspec validate add-macos-menubar-statusbar --strict`

## 13. Integration and E2E Testing

- [ ] 13.1 Test full workflow: install → configure → start → use → stop
- [ ] 13.2 Test on fresh macOS environment (clean install)
- [ ] 13.3 Test with various configurations (different metrics, commands)
- [ ] 13.4 Test error scenarios (process crashes, invalid config)
- [ ] 13.5 Test graceful degradation (missing psutil, no sensors)
- [ ] 13.6 Verify no impact on existing GS CLI functionality
- [ ] 13.7 Test menu bar app survives system sleep/wake

## 14. Future Extension Preparation

- [ ] 14.1 Add placeholder for build progress tracking (disabled by default)
- [ ] 14.2 Document extensibility points in monitors.py
- [ ] 14.3 Add "Coming Soon" section in docs for planned features
- [ ] 14.4 Mark build progress scenarios as deferred in spec comments
