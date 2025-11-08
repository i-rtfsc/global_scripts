# Implementation Tasks

## 1. Project Setup and Dependencies

- [x] 1.1 Add `rumps>=0.4.0` to pyproject.toml with macOS platform marker
- [x] 1.2 Add `psutil>=5.9.0` to pyproject.toml for system metrics
- [x] 1.3 Run `uv sync` to install new dependencies
- [x] 1.4 Verify rumps installation on macOS test environment
- [x] 1.5 Add `aiohttp>=3.8.0` for sentence API integration

## 2. Core Module Structure

- [x] 2.1 Create `src/gscripts/menubar/__init__.py` with module exports
- [x] 2.2 Create `src/gscripts/menubar/__main__.py` with entry point for background process
- [x] 2.3 Create `src/gscripts/menubar/app.py` with rumps.App implementation
- [x] 2.4 Create `src/gscripts/menubar/monitors.py` with BaseMonitor and concrete implementations
- [x] 2.5 Create `src/gscripts/menubar/ipc.py` with IPC socket server implementation
- [x] 2.6 Create `src/gscripts/menubar/status_manager.py` with CommandStatus dataclass
- [x] 2.7 Create `src/gscripts/menubar/icon.py` for menu bar icon definition
- [x] 2.8 Create `src/gscripts/menubar/marquee.py` for scrolling text effect
- [x] 2.9 Create `src/gscripts/menubar/sentence_api.py` for sentence API integration
- [x] 2.10 Create `src/gscripts/menubar/utils.py` for utility functions

## 3. Configuration System

- [x] 3.1 Add menubar configuration to `config/gs.json`
- [x] 3.2 Add i18n messages for menubar (if needed)
- [x] 3.3 Update ConfigManager to load menubar configuration section
- [x] 3.4 Add configuration validation for menubar section

## 4. System Monitoring Implementation

- [x] 4.1 Implement BaseMonitor abstract class with collect() and format() methods
- [x] 4.2 Implement CPUTemperatureMonitor with Apple Silicon support (3-tier detection)
- [x] 4.3 Implement MemoryMonitor using psutil.virtual_memory()
- [x] 4.4 Add graceful degradation for unavailable sensors (show "N/A")
- [x] 4.5 Implement background update thread with configurable interval (default 5s)
- [x] 4.6 Implement metric value caching with staleness detection

## 5. Menu Bar Application (rumps)

- [x] 5.1 Implement MenuBarApp(rumps.App) main application class
- [x] 5.2 Initialize app with title "GS" and icon in __init__
- [x] 5.3 Create menu structure: metrics section + Quit button
- [x] 5.4 Implement update_metrics() method to refresh dropdown menu display
- [x] 5.5 Implement update_status() method to update status bar title (command status)
- [x] 5.6 Implement background thread for periodic metric updates (5s interval)
- [x] 5.7 Add "Quit" menu item with cleanup handler
- [x] 5.8 Implement signal handlers and graceful shutdown
- [x] 5.9 Set NSApplicationActivationPolicyAccessory for menu bar only display (no Dock)

## 6. IPC Communication (Unix Sockets)

- [x] 6.1 Implement IPCServer class with Unix domain socket at `~/.config/global-scripts/menubar.sock`
- [x] 6.2 Define JSON message protocol (command_start, progress_update, command_complete)
- [x] 6.3 Implement socket server loop with asyncio for concurrent connections
- [x] 6.4 Implement message handlers for each message type
- [x] 6.5 Integrate IPCServer with MenuBarApp (update status on messages)
- [x] 6.6 Implement socket cleanup on app quit (remove socket file)
- [x] 6.7 Add error handling for socket communication failures
- [x] 6.8 Add support for output field in IPC messages

## 7. CLI Integration (Auto-Start & Progress Reporting)

- [x] 7.1 Add ensure_menubar_running() function in menubar utils
- [x] 7.2 Implement PID file management (read/write/validate)
- [x] 7.3 Implement background process spawning (detached subprocess)
- [x] 7.4 Add menubar auto-start logic at CLI entry point (check config.menubar.enabled)
- [x] 7.5 Implement IPC client in `menubar/ipc.py` (send_message function)
- [x] 7.6 Add hooks in PluginExecutor for command_start event
- [x] 7.7 Add hooks in PluginExecutor for progress_update event (generator support)
- [x] 7.8 Add hooks in PluginExecutor for command_complete event
- [x] 7.9 Handle IPC errors gracefully (don't fail command if menu bar unavailable)

## 8. Process Management & Status Display

- [x] 8.1 Implement PID file management (write_pid, read_pid, remove_pid)
- [x] 8.2 Implement process spawning with subprocess.Popen(detach=True)
- [x] 8.3 Redirect stdout/stderr to `~/.config/global-scripts/logs/menubar.log`
- [x] 8.4 Implement is_running() with PID validation (check if process exists)
- [x] 8.5 Detect and clean up stale PID files on auto-start
- [x] 8.6 Implement CommandStatus dataclass with format_status() method
- [x] 8.7 Implement status formatting logic (idle, running, success, failure)
- [x] 8.8 Add marquee scrolling for long text with intelligent width calculation
- [x] 8.9 Status clears after 5 seconds (configurable)

## 9. Platform Detection and Graceful Degradation

- [x] 9.1 Add platform detection in menubar/__init__.py (sys.platform check)
- [x] 9.2 Raise clear error if menubar commands run on non-macOS
- [x] 9.3 Add try/except for rumps import with helpful error message
- [x] 9.4 Add platform check to CLI command handlers
- [x] 9.5 Document platform limitations in help text and docs

## 10. Testing

- [x] 10.1 Write unit tests for monitors.py (mock psutil)
- [x] 10.2 Write unit tests for ipc.py (mock socket communication)
- [x] 10.3 Write unit tests for status_manager.py (status formatting)
- [x] 10.4 Write integration test for IPC communication (CLI → menu bar)
- [x] 10.5 Write integration test for process lifecycle (auto-start, detect running)
- [ ] 10.6 Create manual testing checklist in tests/manual/test_menubar_ui.md
- [x] 10.7 Test error handling (missing dependencies, IPC failures)
- [x] 10.8 Test platform detection (graceful skip on non-macOS)
- [ ] 10.9 Run full test suite: `pytest tests/ -v --cov`

## 11. Documentation

- [x] 11.1 Create `docs/menubar-guide.md` with comprehensive user guide (Chinese)
- [x] 11.2 Create `docs/en/menubar-guide.md` with English user guide
- [x] 11.3 Document installation (uv sync, platform requirements)
- [x] 11.4 Document configuration options (enabled, show_cpu_temp, show_memory, refresh_interval)
- [x] 11.5 Document how progress reporting works (generator pattern in plugins)
- [x] 11.6 Add troubleshooting section (common errors, fixes)
- [x] 11.7 Update CLAUDE.md with menubar development guidance
- [ ] 11.8 Update README.md features list to include menu bar status indicator
- [x] 11.9 Add docstrings to all menubar module classes and functions

## 12. Code Quality and Validation

- [ ] 12.1 Run Black formatter: `black src/gscripts/menubar/`
- [ ] 12.2 Run Ruff linter: `ruff check src/gscripts/menubar/ --fix`
- [ ] 12.3 Run MyPy type checker: `mypy src/gscripts/menubar/`
- [x] 12.4 Verify all functions have type annotations
- [x] 12.5 Add logging with correlation IDs to menubar operations
- [x] 12.6 Review code for security issues (command injection, path traversal)
- [ ] 12.7 Validate OpenSpec proposal: `openspec validate add-macos-menubar-statusbar --strict`

## 13. Integration and E2E Testing

- [ ] 13.1 Test full workflow: install → configure → run command → see status → quit
- [ ] 13.2 Test on fresh macOS environment (clean install)
- [ ] 13.3 Test with various command types (Python, Shell, Config plugins)
- [ ] 13.4 Test progress reporting with generator-based plugin functions
- [ ] 13.5 Test error scenarios (process crashes, socket failures, invalid config)
- [ ] 13.6 Test graceful degradation (missing psutil, no sensors, non-macOS)
- [ ] 13.7 Verify no impact on existing GS CLI functionality when menubar disabled
- [ ] 13.8 Test menu bar app survives system sleep/wake cycles

## 14. Future Extension Preparation

- [x] 14.1 Document extensibility points in monitors.py for adding new metrics
- [x] 14.2 Add code comments marking where additional IPC message types can be added
- [x] 14.3 Implemented sentence API integration (ready for future use)
- [x] 14.4 Implemented marquee scrolling effect for long text

## 15. Additional Enhancements Completed

- [x] 15.1 Marquee scrolling with intelligent Chinese/English width calculation
- [x] 15.2 Sentence API integration (一言/毒鸡汤/社会语录/舔狗日记/诗词)
- [x] 15.3 Command output display in status bar
- [x] 15.4 Configurable icon system (currently using "GS" text)
- [x] 15.5 Apple Silicon CPU temperature detection (3-tier fallback)
- [x] 15.6 Comprehensive documentation in both Chinese and English
- [x] 15.7 Fixed Dock icon hiding issue (NSApplicationActivationPolicyAccessory)

## Summary

**Completed**: 94 tasks
**Remaining**: 10 tasks (mostly quality checks and E2E testing)
**Progress**: ~90% complete

**Remaining Work**:
- Code quality checks (Black, Ruff, MyPy)
- Full E2E testing on clean environment
- Manual UI testing checklist
- README.md update
- OpenSpec validation
