# Add macOS Menu Bar Status Monitor

## Why

Global Scripts currently operates purely as a CLI tool without any persistent visual feedback mechanism for monitoring system status or providing quick access to frequently-used commands. macOS power users often rely on menu bar applications for at-a-glance system metrics and quick actions. Integrating a native macOS menu bar application would:

1. Provide continuous visibility into system metrics (CPU temperature, build progress) without needing to open a terminal
2. Enable one-click execution of common GS commands directly from the menu bar
3. Enhance the user experience for macOS users by integrating with native system UI patterns
4. Differentiate GS from purely CLI-based tools by offering a modern GUI presence

## What Changes

This proposal introduces a macOS menu bar application using the `rumps` (Ridiculously Uncomplicated macOS Python Statusbar apps) library as a core GS feature.

**Key Capabilities:**
- **System Monitoring Dashboard**: Display real-time metrics (CPU/system temperature) in the menu bar
- **Command Execution Interface**: Execute GS plugin commands via menu items and display results
- **Persistent Status Display**: Show current status (idle, running command, monitoring) in the status bar icon/title
- **Integration with GS CLI**: Launch and manage the menu bar app via `gs` commands (e.g., `gs menubar start`, `gs menubar stop`)
- **Configuration Support**: User-configurable metrics, refresh intervals, and command shortcuts via GS config system

**Components:**
- New `menubar` module under `src/gscripts/menubar/`
- Integration with existing GS CLI infrastructure (not a plugin, but a core feature)
- New dependency: `rumps>=0.4.0` for macOS status bar integration
- New CLI commands: `gs menubar {start|stop|status|config}`

**Platform Support:**
- **macOS Only**: This feature is macOS-specific and will gracefully degrade/skip on Linux/Windows
- Requires Python 3.8+ and macOS 10.10+ (rumps requirement)

**Breaking Changes:**
- None (entirely new opt-in feature)

## Impact

### Affected Specifications
- **NEW SPEC**: `gui-integration` - Defines GUI integration patterns and lifecycle management
- **NEW SPEC**: `system-monitoring` - Defines system metrics collection and display requirements
- **MODIFIED**: `module-structure` - Adds new `menubar/` module to core structure
- **MODIFIED**: `api-design` - Adds new CLI commands for menubar management

### Affected Code
- **New Files**:
  - `src/gscripts/menubar/__init__.py`
  - `src/gscripts/menubar/app.py` - Main rumps application
  - `src/gscripts/menubar/monitors.py` - System metric monitors
  - `src/gscripts/menubar/executor.py` - GS command executor integration
  - `src/gscripts/menubar/config.py` - Menu bar configuration management
  - `src/gscripts/cli/command_classes/menubar.py` - CLI command handler

- **Modified Files**:
  - `pyproject.toml` - Add `rumps>=0.4.0` with macOS-only marker
  - `src/gscripts/cli/commands.py` - Register menubar command
  - `config/gs.json` - Add default menubar configuration
  - `config/messages/{zh,en}.json` - Add i18n messages for menubar

- **Test Files**:
  - `tests/unit/menubar/test_monitors.py`
  - `tests/unit/menubar/test_executor.py`
  - `tests/integration/test_menubar_lifecycle.py`
  - `tests/manual/test_menubar_ui.py` - Manual UI testing checklist

### Dependencies
- **New Dependency**: `rumps>=0.4.0` (platform marker: `sys_platform == 'darwin'`)
- **Conditional Import**: Graceful fallback when rumps not available (non-macOS)

### User Experience Impact
- **Opt-In**: Users must explicitly run `gs menubar start` to launch the app
- **Configuration**: Users can customize displayed metrics and command shortcuts
- **Performance**: Menu bar app runs as separate process, minimal impact on CLI performance
- **Documentation**: Requires new user documentation for menu bar features

### Migration
- No migration required (new feature, no existing data/config to migrate)
- Backward compatible: existing GS installations continue to work without changes
