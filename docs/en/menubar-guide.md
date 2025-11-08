# macOS Menu Bar Status Monitor Guide

[中文版](./menubar-guide.md) | **English**

## Overview

The macOS menu bar status monitor provides real-time visibility into Global Scripts command execution directly from your macOS menu bar. Monitor command progress, status, and system metrics without keeping the terminal window visible.

**Platform**: macOS 10.10+ only

**Dependencies**:
- `rumps>=0.4.0` (macOS menu bar framework)
- `psutil>=5.9.0` (system metrics)
- `aiohttp>=3.8.0` (async HTTP client for API integration)

---

## Features

### Command Status Display

- **Auto-start**: Menu bar app launches automatically when running GS commands
- **Real-time progress**: Shows command name, progress percentage, and elapsed time
- **Completion status**: Displays success (✓) or failure (✗) with duration
- **Auto-clear**: Status clears after 5 seconds to return to idle state
- **Marquee scrolling**: Automatic scrolling for long text (intelligent width calculation for Chinese/English)

### System Metrics

- **CPU Temperature**: Displays current CPU temperature
  - **Apple Silicon (M1/M2/M3/M4/M5)**: 3-tier detection method
    1. `sysctl` thermal level
    2. `ioreg` device temperature
    3. CPU usage estimation
- **Memory Usage**: Shows memory usage percentage
- **Auto-refresh**: Updates every 5 seconds

### Display Format

#### Menu Bar Title
- **Idle**: `GS`
- **Running (no progress)**: `GS version 2s`
- **Running (with progress)**: `GS android.adb 45% 2m15s`
- **Running (with output)**: `GS spider.crawl 50% 1m Found 10` (auto-scroll)
- **Success**: `GS version 1.2s ✓`
- **Failure**: `GS command 0.5s ✗`

#### Dropdown Menu
Click the menu bar icon to view:
```
┌────────────────────────┐
│ CPU: 52°C              │  ← Real-time CPU temperature
│ Memory: 45%            │  ← Real-time memory usage
├────────────────────────┤
│ Quit                   │  ← Exit application
└────────────────────────┘
```

---

## Installation

### 1. Install Dependencies

```bash
uv sync
```

### 2. Enable Menu Bar

Edit `~/.config/global-scripts/config/gs.json`:

```json
{
  "menubar": {
    "enabled": true,
    "refresh_interval": 5,
    "show_cpu_temp": true,
    "show_memory": true
  }
}
```

### 3. Run Any Command

```bash
gs version
```

The menu bar app will auto-start in the background.

---

## Configuration

### Basic Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable/disable menu bar feature |
| `refresh_interval` | number | `5` | Metric refresh interval (seconds) |
| `show_cpu_temp` | boolean | `true` | Display CPU temperature |
| `show_memory` | boolean | `true` | Display memory usage |

### Advanced Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `marquee_update_interval` | number | `0.3` | Marquee scroll speed (seconds) |

### Configuration Examples

**Minimal**:
```json
{
  "menubar": {
    "enabled": true
  }
}
```

**Full**:
```json
{
  "menubar": {
    "enabled": true,
    "refresh_interval": 10,
    "show_cpu_temp": true,
    "show_memory": true,
    "marquee_update_interval": 0.2
  }
}
```

---

## Usage

### Basic Usage

1. **First command triggers auto-start**:
   ```bash
   gs system doctor
   ```
   → Menu bar app starts in background

2. **Subsequent commands update status**:
   ```bash
   gs android build aosp
   ```
   → Menu bar shows: `GS android.build 0m30s`

3. **View dropdown menu** (click icon):
   ```
   CPU: 52°C
   Memory: 45%
   ─────────────
   Quit
   ```

### Manual Control

```bash
# Start menu bar
gs menubar start

# Stop menu bar
gs menubar stop

# Restart menu bar
gs menubar restart

# Check status
gs menubar status
```

---

## Status Flow

```
Idle → Running → Running (progress) → Success/Failure → [5s] → Idle
 GS      GS cmd      GS cmd 45% 2m      GS cmd 1s ✓/✗       GS
```

### State Details

1. **Idle**: `GS` - No command running
2. **Running (no progress)**: `GS version 5s` - Command executing
3. **Running (with progress)**: `GS spider.crawl 45% 2m15s` - Progress reported
4. **Success**: `GS version 1.2s ✓` - Command succeeded (5s display)
5. **Failure**: `GS command 0.5s ✗` - Command failed (5s display)

---

## Marquee Scrolling

### Trigger Condition

Automatic scrolling when display width exceeds 30:
- **Chinese characters**: 2 width units
- **English/numbers/symbols**: 1 width unit

**Examples**:
- `GS version 1s` → Width 13, no scroll
- `GS This is a very long sentence` → Width > 30, scrolling

### Configuration

```json
{
  "menubar": {
    "marquee_update_interval": 0.3  // Scroll speed (seconds)
  }
}
```

---

## CPU Temperature Monitoring

### Apple Silicon (M1/M2/M3/M4/M5)

3-tier fallback detection:

#### Method 1: sysctl (Thermal Level)
```bash
sysctl machdep.xcpm.cpu_thermal_level
# Returns: 0-100 thermal level
# Convert: 40 + (level * 0.6) = temperature (°C)
```
- **Pros**: Fast, no permissions needed
- **Cons**: Approximate scale

#### Method 2: ioreg (Device Temperature)
```bash
ioreg -rn AppleARMIODevice | grep temperature
# Returns: Temperature value (usually °C * 100)
# Convert: temp_raw / 100.0
```
- **Pros**: More accurate
- **Cons**: May not be available on all chips

#### Method 3: CPU Usage Estimation
```python
cpu_percent = psutil.cpu_percent()
estimated_temp = 40 + (cpu_percent * 0.4)
# 0% CPU = 40°C, 100% CPU = 80°C
```
- **Pros**: Always available
- **Cons**: Approximation only

### Intel Mac

Uses `psutil.sensors_temperatures()` to read sensor data.

---

## IPC Communication

### Protocol

- **Protocol**: Unix Domain Socket
- **Path**: `~/.config/global-scripts/menubar.sock`
- **Direction**: CLI → Menu Bar (one-way)

### Message Types

#### 1. Command Start
```json
{
  "type": "command_start",
  "command": "android.adb.devices",
  "timestamp": 1699459200.123
}
```

#### 2. Progress Update
```json
{
  "type": "progress_update",
  "percentage": 45,
  "elapsed": 15.3,
  "output": "Processed 45 files"
}
```

#### 3. Command Complete
```json
{
  "type": "command_complete",
  "success": true,
  "duration": 1.23,
  "output": "Found 3 devices",
  "error": null
}
```

---

## Troubleshooting

### CPU Temperature Shows N/A

```bash
# Test detection methods
sysctl machdep.xcpm.cpu_thermal_level  # Method 1
ioreg -rn AppleARMIODevice | grep temp  # Method 2

# Check logs
tail -100 ~/.config/global-scripts/logs/menubar.log | grep -i temp
```

### Menu Bar Not Auto-Starting

```bash
# Check configuration
cat ~/.config/global-scripts/config/gs.json | grep -A4 menubar

# Check logs
tail -50 ~/.config/global-scripts/logs/gs.log | grep -i menubar

# Test manual start
gs menubar start
```

### App Appears in Dock

```bash
# Check activation policy
tail -20 ~/.config/global-scripts/logs/menubar.log | grep activation
# Should see: "Set NSApplicationActivationPolicyAccessory (menu bar only)"

# Restart menu bar
gs menubar stop && sleep 2 && gs menubar start
```

---

## Architecture

### Components

| Component | File | Description |
|-----------|------|-------------|
| Main App | `menubar/app.py` | rumps menu bar application |
| Status Manager | `menubar/status_manager.py` | Command status formatting |
| System Monitors | `menubar/monitors.py` | CPU/memory monitoring |
| IPC Server | `menubar/ipc.py` | Unix socket server |
| Marquee | `menubar/marquee.py` | Scrolling text effect |
| Icon | `menubar/icon.py` | Menu bar icon definition |

### Background Tasks

1. **Metrics Updater**: Updates CPU/memory every 5 seconds
2. **Marquee Updater**: Updates scroll position every 0.3 seconds (if needed)
3. **IPC Server**: Listens for command status messages from CLI

---

## Comparison with ClashX

| Feature | GS Menu Bar | ClashX |
|---------|-------------|--------|
| Menu bar only | ✅ | ✅ |
| Hidden from Cmd+Tab | ✅ | ✅ |
| Real-time status | ✅ | ✅ |
| System monitoring | ✅ CPU/Memory | ✅ Network |
| Text display | ✅ | ✅ |
| Dark mode support | ✅ | ✅ |
| Marquee scrolling | ✅ | - |

---

## Best Practices

### Performance-First Configuration
```json
{
  "menubar": {
    "enabled": true,
    "refresh_interval": 10,
    "marquee_update_interval": 0.5
  }
}
```

### Visual-First Configuration
```json
{
  "menubar": {
    "enabled": true,
    "refresh_interval": 3,
    "marquee_update_interval": 0.2
  }
}
```

### Use Cases

- **Long-running commands**: Monitor progress and remaining time
- **Background execution**: Keep status visible while working
- **System monitoring**: Real-time CPU temperature and memory usage
- **Multitasking**: No need to switch terminal windows

---

## Limitations

1. **macOS only**: Menu bar feature is macOS-exclusive
2. **Requires rumps**: Must install `rumps` library
3. **Apple Silicon temp**: Temperature reading is approximate
4. **Text length**: Very long text triggers marquee scrolling
5. **Auto-clear**: Status clears after 5 seconds

---

## FAQ

### Q: How to change the menu bar icon?

A: Currently uses "GS" text icon. Future versions will support custom icon files. Temporarily modify `MENUBAR_ICON` in `src/gscripts/menubar/icon.py`.

### Q: How to extend status display time?

A: Modify `threading.Timer(5.0, self._clear_status)` parameter in `src/gscripts/menubar/app.py` (currently 5 seconds).

### Q: Marquee scrolling too fast/slow?

A: Adjust `marquee_update_interval` in configuration (default 0.3 seconds).

### Q: Windows/Linux support?

A: Not supported. Menu bar feature is macOS-only. Other platforms could consider system tray implementation.

---

## Changelog

### Version 5.2.0-dev
- ✨ Added marquee scrolling effect
- ✨ Added command output display
- ✨ Optimized Apple Silicon CPU temperature detection
- 🐛 Fixed Dock icon display issue
- 🐛 Fixed status clear time (15s → 5s)
- 🎨 Changed icon to "GS" text (configurable)

---

## Related Resources

- [Main Documentation](../README_EN.md)
- [Plugin Development Guide](./plugin-development.md)
- [Architecture Document](./architecture.md)
- [Contributing Guide](./contributing.md)
