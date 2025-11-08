# Design Document: macOS Menu Bar Status Monitor

## Context

Global Scripts V5 is a Python-based CLI tool with a Clean Architecture implementation. The system currently has no persistent GUI presence and relies entirely on terminal interaction. macOS users frequently use menu bar applications for system monitoring and quick access to tools, making this a natural fit for enhancing the GS user experience on macOS.

This change introduces a native macOS menu bar application using the `rumps` library, which provides a lightweight Python wrapper around macOS NSStatusBar APIs.

**Stakeholders:**
- macOS power users (primary beneficiaries)
- DevOps engineers using GS for Android/system development
- Contributors maintaining the GS codebase

**Constraints:**
- macOS-only feature (rumps requires macOS 10.10+)
- Must not impact existing CLI functionality or performance
- Must integrate with existing GS configuration system
- Should follow Clean Architecture principles
- Python 3.8+ compatibility requirement

## Goals / Non-Goals

### Goals
1. Provide persistent visual feedback for system metrics (CPU temperature initially)
2. Enable one-click execution of common GS commands from menu bar
3. Integrate seamlessly with existing GS CLI and configuration system
4. Maintain simplicity: minimal dependencies, straightforward implementation
5. Support extensibility: easy to add new monitors or command shortcuts
6. Graceful degradation: clear error messages on non-macOS or missing dependencies

### Non-Goals
1. **Not** a replacement for CLI (complementary tool)
2. **Not** a cross-platform GUI (macOS-specific by design)
3. **Not** a comprehensive system monitor (focus on GS-relevant metrics)
4. **Not** implementing build progress tracking in initial version (deferred)
5. **Not** providing a configuration UI (use existing text-based config)
6. **Not** supporting background notifications (except critical errors)

## Decisions

### Decision 1: Use rumps for Menu Bar Integration

**Chosen Approach:** Use `rumps` library (Ridiculously Uncomplicated macOS Python Statusbar apps)

**Rationale:**
- Pure Python, no Swift/Objective-C required
- Mature library (since 2013) with proven stability
- Minimal API surface (< 10 classes/methods)
- Integrates well with Python async code
- Active maintenance and macOS version compatibility

**Alternatives Considered:**
1. **PyObjC** (direct Cocoa bindings)
   - ❌ Too complex, requires Objective-C knowledge
   - ❌ Steep learning curve for contributors
   - ✅ More control, native integration

2. **Electron/Web-based**
   - ❌ Massive dependency footprint (100+ MB)
   - ❌ Violates "minimal dependencies" principle
   - ❌ Overkill for simple menu bar app

3. **Swift native app**
   - ❌ Requires separate codebase/build system
   - ❌ Harder to integrate with Python GS CLI
   - ✅ Best performance, native feel

**Trade-offs:**
- rumps is macOS-only, but that's acceptable for this feature
- Less control than PyObjC, but 95% of use cases covered
- Slightly larger dependency than CLI-only, but still < 1 MB

### Decision 2: Menu Bar as Core Feature, Not Plugin

**Chosen Approach:** Implement as `src/gscripts/menubar/` module (core feature)

**Rationale:**
- Menu bar app manages ALL plugins, shouldn't be a plugin itself
- Requires tight integration with CLI lifecycle (start/stop commands)
- Simpler dependency management (part of core pyproject.toml)
- More discoverable for users (`gs menubar start` vs obscure plugin command)

**Alternatives Considered:**
1. **System plugin** (under `plugins/system/menubar/`)
   - ❌ Circular dependency: plugins need plugin manager, menu bar needs plugins
   - ❌ Awkward enable/disable semantics (disabling menubar disables system plugin?)
   - ✅ Follows existing plugin patterns

2. **Separate plugin** (`plugins/menubar/`)
   - ❌ Same circular dependency issue
   - ❌ Harder to integrate with core CLI commands
   - ✅ User can disable if not needed

**Trade-offs:**
- Core module increases footprint for non-macOS users (but with platform checks, impact is minimal)
- Cannot be independently versioned like a plugin
- Better integration and discoverability outweigh plugin isolation benefits

### Decision 3: Process Model - Background Process with PID Management

**Chosen Approach:** Menu bar app runs as detached background process, managed via PID file

**Rationale:**
- rumps requires running an event loop (blocking operation)
- CLI commands must return immediately (`gs menubar start` shouldn't block)
- Standard Unix pattern: daemon process with PID file
- Enables process lifecycle management (start, stop, status, detect crashes)

**Implementation Details:**
- PID file location: `~/.config/global-scripts/menubar.pid`
- Process spawn: `subprocess.Popen()` with detached session
- Logs: `~/.config/global-scripts/logs/menubar.log`
- Graceful shutdown: SIGTERM (5s) → SIGKILL (fallback)

**Alternatives Considered:**
1. **Threads/asyncio within CLI process**
   - ❌ Keeps CLI blocked or requires complex background thread management
   - ❌ Harder to stop/restart independently
   - ✅ No IPC needed, shared memory

2. **Separate executable/entry point**
   - ❌ More complex installation (multiple binaries)
   - ❌ Harder to ensure version consistency
   - ✅ Cleaner process separation

**Trade-offs:**
- PID file can become stale (crash without cleanup) → mitigated with is_running() validation
- IPC needed for CLI to communicate with running app → initial version: no IPC, restart to reconfigure

### Decision 4: Monitor Architecture - Plugin-Style Registry

**Chosen Approach:** Abstract BaseMonitor class with registry-based loading

**Pattern:**
```python
class BaseMonitor(ABC):
    @abstractmethod
    async def collect(self) -> Any:
        """Collect metric value"""
        pass

    @abstractmethod
    def format(self, value: Any) -> str:
        """Format value for menu display"""
        pass

# Registry
MONITORS = {
    "cpu_temperature": CPUTemperatureMonitor,
    "current_time": CurrentTimeMonitor,
    # Future: "build_progress": BuildProgressMonitor
}
```

**Rationale:**
- Easy to add new monitors without modifying app.py
- User can enable/disable monitors via config
- Follows GS plugin philosophy (extensibility)
- Testable in isolation

**Alternatives Considered:**
1. **Hardcoded monitors in app.py**
   - ❌ Violates Open/Closed Principle
   - ❌ Hard to test, hard to extend
   - ✅ Simpler initial implementation

2. **Dynamic discovery (like plugin system)**
   - ❌ Overkill for ~5 initial monitors
   - ❌ More complex than needed
   - ✅ Maximum flexibility

**Trade-offs:**
- Registry pattern adds slight complexity vs hardcoding
- But pays off when adding 3rd monitor (already needed for temp + time)

### Decision 5: Configuration Integration - Extend GS Config System

**Chosen Approach:** Add `menubar` section to `config/gs.json`, use existing ConfigManager

**Configuration Schema:**
```json
{
  "menubar": {
    "enabled": false,
    "refresh_interval": 5,
    "enabled_metrics": ["cpu_temperature"],
    "command_shortcuts": [
      {"label": "ADB Devices", "command": "gs android adb devices"}
    ],
    "time_format": "%H:%M:%S"
  }
}
```

**Rationale:**
- Reuses existing config system (no new config files)
- Follows GS convention (user config overrides project config)
- JSON schema is simple and human-editable
- i18n support via existing message system

**Alternatives Considered:**
1. **Separate menubar.json config file**
   - ❌ Fragmentation of configuration
   - ❌ User has to manage multiple files
   - ✅ Cleaner separation

2. **Environment variables**
   - ❌ Not suitable for complex config (shortcuts array)
   - ❌ Harder to persist user changes
   - ✅ Good for runtime overrides

**Trade-offs:**
- menubar section adds to gs.json size (minor)
- Changes require app restart (acceptable for v1, future: live reload)

### Decision 6: Command Execution - Async Subprocess with Timeout

**Chosen Approach:** Use asyncio subprocess for executing GS commands from menu bar

```python
async def execute_gs_command(command: str) -> CommandResult:
    process = await asyncio.create_subprocess_shell(
        command,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=30.0
        )
        # Parse output into CommandResult
    except asyncio.TimeoutError:
        process.kill()
        return CommandResult(success=False, error="Command timeout")
```

**Rationale:**
- Non-blocking execution (menu remains responsive)
- Consistent with GS async-first architecture
- Built-in timeout protection
- Captures output for display in menu

**Alternatives Considered:**
1. **Synchronous subprocess.run()**
   - ❌ Blocks rumps event loop
   - ❌ Freezes menu bar UI during execution
   - ✅ Simpler code

2. **Threading**
   - ❌ More complex than asyncio
   - ❌ GIL contention issues
   - ✅ Works with rumps (which isn't async-native)

**Trade-offs:**
- asyncio requires careful event loop management with rumps (which has its own event loop)
- Solution: run asyncio in separate thread or use run_in_executor

### Decision 7: Defer Build Progress Tracking to Future Version

**Chosen Approach:** Implement infrastructure (BaseMonitor, registry) but NOT build progress monitor in v1

**Rationale:**
- Build progress is complex (need to detect builds, parse logs, extract percentage)
- Different build systems (Gradle, Make, Ninja, repo sync) have different formats
- Would double implementation time and complexity
- CPU temperature + command shortcuts provide immediate value

**Future Implementation Path:**
1. Add `build_progress` to enabled_metrics config (disabled by default)
2. Create BuildProgressMonitor(BaseMonitor)
3. Integrate with Android plugin build detection
4. Parse build logs incrementally
5. Display percentage + ETA in menu

**Trade-offs:**
- Initial version has less "wow factor" without build progress
- But focusing on solid foundation enables easier future additions

## Risks / Trade-offs

### Risk 1: rumps Compatibility with Future macOS Versions
- **Risk**: rumps may break on future macOS releases
- **Likelihood**: Low (library has track record of compatibility)
- **Mitigation**:
  - Monitor rumps GitHub for issues
  - Contribute fixes upstream if needed
  - Fallback: Fork rumps if abandoned

### Risk 2: Performance Impact of Background Process
- **Risk**: Menu bar app consumes significant CPU/memory
- **Likelihood**: Low (rumps is lightweight, metrics are simple)
- **Mitigation**:
  - Profile memory usage during testing
  - Implement configurable refresh_interval (default 5s)
  - Add option to disable expensive monitors

### Risk 3: Temperature Sensor Access on M1/M2/M3 Macs
- **Risk**: psutil may not provide temperature on Apple Silicon
- **Likelihood**: Medium (known limitation)
- **Mitigation**:
  - Fallback to osx-cpu-temp command (requires separate install)
  - Graceful degradation: show "N/A" if unavailable
  - Document sensor requirements in guide

### Risk 4: User Confusion About Process Management
- **Risk**: Users don't understand background process model
- **Likelihood**: Medium (not obvious that `gs menubar start` spawns detached process)
- **Mitigation**:
  - Clear documentation with examples
  - Helpful status messages ("Menu bar is running (PID 12345)")
  - `gs menubar status` shows clear state

## Migration Plan

**No migration required** - this is an additive feature with no existing data.

### Installation Steps for Users
1. Update to GS v5.2.0 (`git pull` or package update)
2. Run `uv sync` to install rumps and psutil dependencies
3. (Optional) Configure menubar in `~/.config/global-scripts/config/gs.json`
4. Run `gs menubar start` to launch
5. Click menu bar icon to verify

### Rollback Plan
- Feature is opt-in, non-breaking
- If issues arise, users can simply not run `gs menubar start`
- If needed, can disable by setting `menubar.enabled: false` in config

### Backward Compatibility
- ✅ Existing CLI commands unaffected
- ✅ Existing plugins unaffected
- ✅ Existing configuration unaffected (menubar section is new, optional)
- ✅ Non-macOS users see graceful error, no crashes

## Open Questions

1. **Q: Should menu bar app auto-start on system login?**
   - A: Deferred to future version. Users can manually add to Login Items if desired.
   - Reason: Avoid surprising users, respect opt-in philosophy

2. **Q: Should we support notifications for command completion?**
   - A: No for v1, but design allows for it (add NotificationMonitor later)
   - Reason: Scope control, avoid notification spam

3. **Q: How to handle configuration changes without restart?**
   - A: v1 requires restart. Future: watch config file for changes, reload dynamically
   - Reason: File watching adds complexity, restart is acceptable for v1

4. **Q: Should we show an icon or just text in menu bar?**
   - A: v1 uses text ("GS" or "GS ⚙️"). Future: custom icon asset
   - Reason: Avoid design work for v1, text is functional

5. **Q: Support for multiple concurrent command executions?**
   - A: v1 supports only one at a time (queue others). Future: parallel with semaphore
   - Reason: Simpler state management, most users run one command at a time

## Implementation Notes

### Dependencies to Add
```toml
# pyproject.toml
dependencies = [
    # ... existing ...
    "rumps>=0.4.0; sys_platform == 'darwin'",  # macOS only
    "psutil>=5.9.0",  # Cross-platform, but needed for metrics
]
```

### Entry Point for Menu Bar App
```python
# src/gscripts/menubar/__main__.py
if __name__ == "__main__":
    from gscripts.menubar.app import MenuBarApp
    app = MenuBarApp()
    app.run()
```

Run via: `python -m gscripts.menubar`

### Logging Strategy
- All menubar logs go to `~/.config/global-scripts/logs/menubar.log`
- Use existing GS logger with tag "MENUBAR"
- Log lifecycle events (start, stop, config load)
- Log metric collection errors (first occurrence only, avoid spam)

### Testing Strategy
- Unit tests: Mock rumps, psutil, subprocess
- Integration tests: Test CLI commands (start/stop/status)
- Manual testing: Actual menu bar UI verification (checklist in tests/manual/)
- No automated UI tests (rumps UI is hard to automate)

## Success Criteria

This change is successful if:
1. ✅ macOS users can run `gs menubar start` and see GS icon in menu bar
2. ✅ CPU temperature displays correctly on supported hardware (or shows N/A gracefully)
3. ✅ Command shortcuts execute successfully and display results
4. ✅ Process lifecycle works (start/stop/status/restart)
5. ✅ Configuration changes take effect after restart
6. ✅ Non-macOS users get clear error (no crashes)
7. ✅ No performance impact on CLI commands (menu bar runs independently)
8. ✅ Test coverage ≥ 70% for menubar module
9. ✅ Documentation is clear and includes troubleshooting section
