# Design Document: macOS Menu Bar Command Status Indicator

## Context

Global Scripts V5 is a Python CLI tool. When running long commands (e.g., Android builds, repo syncs), users cannot see progress without keeping the terminal visible. This change adds a macOS menu bar status indicator that shows command execution progress in real-time, similar to how music players display the currently playing song.

**Stakeholders:**
- macOS power users running long GS commands
- Android/AOSP developers using GS for builds

**Constraints:**
- macOS-only (rumps requires macOS 10.10+)
- Must not block or slow down CLI execution
- Must work seamlessly with existing plugin system
- Python 3.8+ compatibility

## Goals / Non-Goals

### Goals
1. Display command name, progress %, and elapsed time in menu bar while GS commands run
2. Show success/failure status after completion
3. Display CPU temperature in dropdown (optional)
4. Auto-start menu bar when GS commands run (if enabled)
5. Use Unix sockets for CLI → menu bar IPC

### Non-Goals
1. **Not** a command launcher (no executing commands from menu bar)
2. **Not** showing full command output (only status summary)
3. **Not** a comprehensive system monitor (only CPU temp + memory)
4. **Not** cross-platform (macOS only by design)
5. **Not** showing command history (only current/last command)

## Key Design Decisions

### Decision 1: Auto-Start Architecture

**Chosen**: CLI auto-starts menu bar as background process when first command runs

**Flow**:
```
User runs: gs android adb devices
  ↓
CLI checks: is menubar.enabled=true? is menu bar running?
  ↓
If not running: spawn detached process (python -m gscripts.menubar)
  ↓
Execute command + send IPC updates to menu bar
```

**Rationale**:
- No manual `gs menubar start` needed
- Menu bar appears when useful (command running)
- Survives across multiple command invocations

### Decision 2: Unix Domain Sockets for IPC

**Chosen**: Unix sockets at `~/.config/global-scripts/menubar.sock`

**Message Protocol** (JSON over socket):
```json
// Command start
{"type": "command_start", "command": "android.adb.devices", "timestamp": 123456789.0}

// Progress update (optional, if plugin yields progress)
{"type": "progress_update", "percentage": 45, "elapsed": 15.3}

// Command complete
{"type": "command_complete", "success": true, "duration": 1.23, "error": null}
```

**Rationale**:
- Fast (< 1ms overhead per message)
- Standard Unix IPC mechanism
- Supports multiple concurrent connections (one per CLI instance)
- Easy cleanup (remove socket file on quit)

**Alternatives Considered**:
- Shared memory: Too complex
- Named pipes: Less flexible than sockets
- HTTP localhost: Overkill, port conflicts

### Decision 3: Progress Reporting via Generator Pattern

**Chosen**: Plugin functions can yield progress dicts

**Example Plugin Function**:
```python
@plugin_function(...)
async def download_file(self, args):
    total_size = 1000
    for i in range(100):
        # Do work...
        yield {"progress": i}  # Send progress to menu bar
    return CommandResult(success=True, output="Downloaded")
```

**PluginExecutor Handling**:
```python
result = plugin_func(args)
if inspect.isgenerator(result) or inspect.isasyncgen(result):
    async for progress_dict in result:
        if "progress" in progress_dict:
            send_ipc("progress_update", progress_dict["progress"])
    final_result = await result  # Get final return value
```

**Rationale**:
- Non-breaking: existing functions still work (just return CommandResult)
- Explicit: plugins opt-in by using generator pattern
- Flexible: can yield progress at any granularity

### Decision 4: Menu Bar Display Format

**Status Bar Title Formats**:
- Idle: `"GS"`
- Running with progress: `"GS: android.adb 45% 2m15s"`
- Running without progress: `"GS: system.prompt 0m05s"`
- Success: `"GS: ✓ android.adb 1.2s"` (clears after 5s)
- Failure: `"GS: ✗ android.build 30s"` (clears after 5s)

**Dropdown Menu**:
- CPU: 45°C
- Memory: 62%
- ─────────────
- Quit

**Rationale**:
- Minimal, unobtrusive
- Glanceable (no need to click)
- Similar to music player status bars

### Decision 5: System Metrics Monitoring

**Chosen**: Use `psutil` for CPU temperature and memory usage

**Implementation**:
```python
def get_cpu_temp() -> Optional[float]:
    """Get CPU temperature in Celsius"""
    try:
        import psutil
        temps = psutil.sensors_temperatures()
        if 'coretemp' in temps:
            return temps['coretemp'][0].current
    except:
        pass
    return None

def get_memory_usage() -> float:
    """Get memory usage percentage"""
    try:
        import psutil
        return psutil.virtual_memory().percent
    except:
        return 0.0
```

**Rationale**:
- psutil is cross-platform and well-maintained
- Graceful degradation if sensors unavailable (show "N/A")
- Updates every 5s (low overhead)
- Memory usage always available, temperature may not be

## Implementation Architecture

### File Structure
```
src/gscripts/menubar/
├── __init__.py          # Module exports
├── __main__.py          # Entry point: python -m gscripts.menubar
├── app.py               # MenuBarApp(rumps.App)
├── ipc.py               # IPCServer (Unix socket server)
├── status_manager.py    # CommandStatus data class + formatting
└── monitors.py          # CPUTemperatureMonitor, MemoryMonitor
```

### Integration Points

**1. CLI Auto-Start** (`cli/main.py`):
```python
def main():
    config = load_config()
    if config.get("menubar", {}).get("enabled", False):
        ensure_menubar_running()  # Spawn if not running
    # ... existing CLI logic
```

**2. PluginExecutor Hooks** (`application/services/plugin_executor.py`):
```python
async def execute_plugin(self, plugin_name, function_name, args):
    send_ipc({"type": "command_start", "command": f"{plugin_name}.{function_name}"})
    start_time = time.time()

    result = await self._call_plugin_function(plugin, function, args)

    if inspect.isasyncgen(result):
        async for progress in result:
            if "progress" in progress:
                send_ipc({"type": "progress_update", "percentage": progress["progress"]})
        result = final_value  # Get return value

    duration = time.time() - start_time
    send_ipc({"type": "command_complete", "success": result.success, "duration": duration})
    return result
```

## Risks & Mitigations

| Risk | Likelihood | Mitigation |
|------|-----------|------------|
| IPC adds latency to commands | Low | Socket I/O is async, < 1ms overhead |
| Menu bar crashes and orphans | Medium | CLI detects stale PID, auto-restarts |
| rumps incompatible with future macOS | Low | Monitor upstream, contribute fixes |
| Temperature sensors unavailable on M1/M2 | Medium | Show "N/A", document limitation |
| Memory monitoring overhead | Low | psutil cached, 5s refresh interval |

## Success Criteria

1. ✅ Running `gs android build` shows progress in menu bar
2. ✅ Completion status (✓/✗) displays for 5s then clears
3. ✅ CLI overhead < 5ms when menu bar enabled
4. ✅ Menu bar auto-starts on first command (no manual start needed)
5. ✅ Non-macOS platforms skip menu bar gracefully (no errors)
6. ✅ Test coverage ≥ 70% for menubar module
