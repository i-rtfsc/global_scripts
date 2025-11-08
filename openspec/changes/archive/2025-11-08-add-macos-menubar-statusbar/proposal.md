# Add macOS Menu Bar Status Monitor

## Why

Global Scripts currently operates purely as a CLI tool without any persistent visual feedback for long-running commands or system metrics. macOS power users need at-a-glance visibility into:

1. **Command Execution Progress**: When running GS commands in the terminal (e.g., `gs android build`), there's no way to see progress without keeping the terminal window visible
2. **System Metrics**: CPU temperature and other metrics require opening a terminal to check
3. **Execution History**: No quick way to see if the last command succeeded or failed without scrolling back in terminal

Integrating a macOS menu bar status indicator would provide continuous visibility into command execution status and system metrics, similar to how music players show the currently playing song in the menu bar.

## What Changes

This proposal introduces a macOS menu bar status indicator using the `rumps` library, integrated directly with GS command execution.

**Key Capabilities:**
- **Command Status Display**: When GS commands run in terminal, the menu bar shows:
  - Command name (e.g., "android adb devices")
  - Progress percentage (for commands that report progress)
  - Elapsed time (e.g., "Running: 2m 15s")
  - Final result: success/failure with execution duration

- **System Metrics Monitoring**:
  - Display CPU temperature in dropdown menu
  - Display memory usage in dropdown menu

- **Integration with GS CLI**:
  - Menu bar app auto-starts when first GS command runs (if enabled)
  - GS CLI sends command updates to menu bar via IPC (Unix sockets)
  - No separate `gs menubar start` command needed - it's automatic

- **Minimal UI**:
  - Menu bar shows: "GS" (idle), "GS: android build 45% 2m15s" (running), "GS: ✓ 1.2s" (done, clears after 5s)
  - Dropdown menu shows: CPU temperature, memory usage, app controls (Quit)
  - **No command execution from menu bar** - it's passive display only

**Components:**
- New `menubar` module under `src/gscripts/menubar/`
- Integration with CLI command execution pipeline (hooks in PluginExecutor)
- New dependencies: `rumps>=0.4.0` (status bar), `psutil>=5.9.0` (metrics)
- IPC mechanism for CLI → menu bar communication (Unix domain sockets)

**Platform Support:**
- **macOS Only**: This feature is macOS-specific and will gracefully degrade/skip on Linux/Windows
- Requires Python 3.8+ and macOS 10.10+ (rumps requirement)

**Breaking Changes:**
- None (entirely new opt-in feature via config)

## Impact

### Affected Specifications
- **NEW SPEC**: `gui-integration` - Defines menu bar lifecycle, auto-start, and IPC patterns
- **NEW SPEC**: `command-progress-tracking` - Defines how CLI tracks and reports command execution status
- **MODIFIED**: `module-structure` - Adds new `menubar/` module to core structure
- **MODIFIED**: `plugin-execution` - Adds hooks for command progress reporting via generator pattern

### Affected Code
- **New Files**:
  - `src/gscripts/menubar/__init__.py`
  - `src/gscripts/menubar/__main__.py` - Entry point for background process
  - `src/gscripts/menubar/app.py` - Main rumps application (MenuBarApp class)
  - `src/gscripts/menubar/ipc.py` - Unix socket server for CLI → menu bar communication
  - `src/gscripts/menubar/monitors.py` - CPU temperature and memory usage monitors
  - `src/gscripts/menubar/status_manager.py` - Command status tracking and formatting

- **Modified Files**:
  - `pyproject.toml` - Add `rumps>=0.4.0`, `psutil>=5.9.0` with macOS-only marker
  - `src/gscripts/application/services/plugin_executor.py` - Add progress reporting hooks
  - `src/gscripts/cli/main.py` - Auto-start menu bar on first command (if enabled)
  - `config/gs.json` - Add default menubar configuration
  - `config/messages/{zh,en}.json` - Add i18n messages for menubar

- **Test Files**:
  - `tests/unit/menubar/test_ipc.py`
  - `tests/unit/menubar/test_status_manager.py`
  - `tests/integration/test_menubar_command_integration.py`
  - `tests/manual/test_menubar_ui.md` - Manual UI testing checklist

### Dependencies
- **New Dependencies**:
  - `rumps>=0.4.0` (platform marker: `sys_platform == 'darwin'`)
  - `psutil>=5.9.0` - For CPU temperature monitoring
- **Conditional Import**: Graceful fallback when rumps not available (non-macOS)

### User Experience Impact
- **Auto-Start**: Menu bar app automatically starts when GS commands run (if `menubar.enabled: true` in config)
- **Passive Display**: Menu bar only shows status - no command execution from menu bar
- **Visual Feedback**: Users see command progress in menu bar without keeping terminal visible
- **System Metrics**: CPU temperature and memory usage visible in dropdown menu
- **Minimal Configuration**: Only enable/disable flag and metric toggles in config
- **Performance**: Menu bar runs as background process; IPC overhead < 1ms per command

### Migration
- No migration required (new feature, no existing data/config to migrate)
- Backward compatible: existing GS installations continue to work without changes
- Default: `menubar.enabled: false` (opt-in)
