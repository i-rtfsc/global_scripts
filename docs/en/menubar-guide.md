# macOS Menu Bar Status Monitor Guide

[中文版](../menubar-guide.md) | **English**

## Overview

The macOS menu bar status monitor provides real-time visibility into Global Scripts command execution directly from your macOS menu bar. Monitor command progress, status, and system metrics without keeping the terminal window visible.

**Platform**: macOS 10.10+ only

**Dependencies**:
- `rumps>=0.4.0` (macOS menu bar framework)
- `psutil>=5.9.0` (system metrics)
- `aiohttp>=3.8.0` (async HTTP client for Hitokoto API)

---

## Features

### Command Status Display

- **Auto-start**: Menu bar app launches automatically when running GS commands
- **Real-time progress**: Shows command name, progress percentage, and elapsed time
- **Completion status**: Displays success (✓) or failure (✗) with duration
- **Auto-clear**: Status clears after 5 seconds to return to idle state
- **Marquee scrolling**: Automatic scrolling for long text (intelligent width calculation for Chinese/English)

### System Metrics Monitoring

- **CPU Temperature**: Displays current CPU temperature
  - **Apple Silicon (M1/M2/M3/M4/M5)**: 3-tier detection method
    1. `sysctl` thermal level
    2. `ioreg` device temperature
    3. CPU usage estimation
- **Memory Usage**: Shows memory usage percentage
- **Auto-refresh**: Updates every 5 seconds

### Enhanced System Monitoring

#### CPU Submenu
Click CPU menu item to view detailed information:
```
┌────────────────────────────────┐
│ CPU: 35% 52°C               ▶  │  ← Dynamic title: usage + temp
│   Overall: 35.2%               │  ← Overall CPU usage
│   Core 0: 45.1%                │  ← Per-core usage
│   Core 1: 32.3%                │
│   Core 2: 28.5%                │
│   Core 3: 39.0%                │
│   ──────────────               │
│   Temperature: 52.3°C ↑        │  ← Current temp + trend
│   Avg (5min): 48.7°C           │  ← 5-minute average
│   Peak (session): 58.1°C       │  ← Session peak
│   ──────────────               │
│   🟢 Normal: 52.3°C            │  ← Temperature alert
│   Thresholds: Warn 60°C/Crit 75°C │  ← Configurable thresholds
└────────────────────────────────┘
```

**Temperature Trend Indicators**:
- `↑` Rising (> 2°C increase in 30s)
- `↓` Falling (> 2°C decrease in 30s)
- `→` Stable (change ≤ 2°C)

**Temperature Alert Status** (Phase 6):
- 🟢 Normal: < 60°C (default)
- 🟡 Warning: 60-75°C
- 🔴 Critical: ≥ 75°C

#### Memory Submenu
Click Memory menu item to view detailed information:
```
┌────────────────────────────────┐
│ Memory: 12.3/16GB           ▶  │  ← Dynamic title: used/total
│   Used: 12.3 / 16.0 GB (77%)   │  ← Total usage
│   ──────────────               │
│     App: 8.5 GB                │  ← Application memory
│     Wired: 2.1 GB              │  ← Wired memory (kernel)
│     Compressed: 1.2 GB         │  ← Compressed memory
│     Cached: 0.5 GB             │  ← Cached files
│   ──────────────               │
│   Swap: None                   │  ← Swap usage
│   Pressure: 🟡 Moderate        │  ← Memory pressure level
│   ──────────────               │
│   Top Processes: (optional)    │  ← Top 3 memory consumers
│     Chrome: 2.1 GB             │
│     Code: 1.8 GB               │
│     Slack: 0.9 GB              │
└────────────────────────────────┘
```

**Memory Pressure Levels**:
- 🟢 Normal (< 60%): Sufficient memory
- 🟡 Moderate (60-80%): Moderate memory
- 🔴 High (> 80%): Memory pressure

#### Disk Submenu (Phase 6.2)
Click Disk menu item to view detailed information:
```
┌────────────────────────────────┐
│ Disk: 336/926GB (37%)       ▶  │  ← Dynamic title: used/total (%)
│   Used: 336.0 / 926.0 GB (37%) │  ← Total usage
│   Free: 590.0 GB               │  ← Free space
│   Pressure: 🟢 Normal          │  ← Disk pressure level
│   ──────────────               │
│   I/O Activity:                │  ← I/O activity (optional)
│   Read: 12.3 MB/s              │  ← Read speed
│   Write: 5.7 MB/s              │  ← Write speed
└────────────────────────────────┘
```

**Disk Pressure Levels**:
- 🟢 Normal (< 80%): Sufficient disk space
- 🟡 Moderate (80-90%): Moderate disk space
- 🔴 High (> 90%): Disk pressure

**Important Fix** (macOS APFS):
- Fixed disk usage display error (showing only 11GB)
- Now correctly detects `/System/Volumes/Data` data volume
- On macOS APFS systems, user data is on data volume, not system snapshot

#### Battery Submenu (Phase 3)
Click Battery menu item to view detailed information (laptops only):
```
┌────────────────────────────────┐
│ Battery: 98% (20h 0m)       ▶  │  ← Dynamic title: charge (time)
│   Charge: 98% (Discharging)    │  ← Charge and status
│   Time Remaining: 20h 0m       │  ← Time remaining
│   ──────────────               │
│   Health: 103% (Excellent)     │  ← Battery health
│   Cycle Count: 8 / 1000        │  ← Cycle count
│   Temperature: 27.7°C          │  ← Battery temperature
│   ──────────────               │
│   Power Source: Battery        │  ← Power source
└────────────────────────────────┘
```

**Battery Health Levels**:
- Excellent (≥ 90%): Excellent battery condition
- Good (80-90%): Good battery condition
- Fair (60-80%): Some wear
- Poor (40-60%): Significant aging
- Replace (< 40%): Battery replacement needed

**Important Fix** (Battery Health Calculation):
- Fixed battery health display error (new laptops showing 2%)
- Now correctly uses `AppleRawMaxCapacity` (actual mAh capacity)
- Fixed temperature unit conversion (decikelvin → °C)

**Note**: Desktops without battery show "Battery: N/A (Desktop)"

#### Ports Submenu (Phase 5)
Click Ports menu item to view port usage status:
```
┌────────────────────────────────┐
│ Ports: 2/8                  ▶  │  ← Dynamic title: occupied/total
│   🟢 3000: Python (PID 61023)  │  ← Occupied port
│     ⏹ Kill Process             │     ← Click to kill process
│   🔴 8080: Not in use          │  ← Unoccupied port
│   🔴 80: Not in use            │
│   🔴 443: Not in use           │
│   🔴 5432: Not in use          │
│   🔴 3306: Not in use          │
│   🟢 6379: redis-server (12345)│
│     ⏹ Kill Process             │
│   🔴 27017: Not in use         │
└────────────────────────────────┘
```

**Features**:
- Real-time detection of common development port usage
- Display process name and PID
- Quick kill process (with confirmation dialog)
- Monitor 8 common ports by default (configurable)

**Configuration Options** (New):
| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `show_top_processes` | boolean | `false` | Show Top 3 processes in Memory submenu |
| `high_cpu_threshold` | number | `80.0` | High CPU warning threshold (%) |
| `show_disk` | boolean | `true` | Show disk monitoring |
| `show_battery` | boolean | `true` | Show battery monitoring (laptops) |
| `show_ports` | boolean | `true` | Show port monitoring |
| `monitored_ports` | array | `[3000, 8080, ...]` | List of ports to monitor |
| `show_temp_alert` | boolean | `true` | Show temperature alerts |
| `temp_warning_threshold` | number | `60.0` | Temperature warning threshold (°C) |
| `temp_critical_threshold` | number | `75.0` | Temperature critical threshold (°C) |
| `on_demand_monitoring` | boolean | `true` | On-demand monitoring (update only when menu open) |

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
│ Recent Commands     ▶  │  ← Command history (optional)
├────────────────────────┤
│ Shortcuts           ▶  │  ← Custom shortcuts (optional)
├────────────────────────┤
│ CPU: 35% 52°C       ▶  │  ← Click for CPU details
│ Memory: 12.3/16GB   ▶  │  ← Click for Memory details
│ Disk: 336/926GB     ▶  │  ← Click for Disk details
│ Battery: 98% (20h)  ▶  │  ← Click for Battery details
│ Ports: 2/8          ▶  │  ← Click for Ports details
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
    "on_demand_monitoring": true,
    "refresh_interval": 5,
    "show_cpu_temp": true,
    "show_memory": true,
    "show_disk": true,
    "show_battery": true,
    "show_ports": true,
    "monitored_ports": [3000, 8080, 80, 443, 5432, 3306, 6379, 27017],
    "show_temp_alert": true,
    "temp_warning_threshold": 60.0,
    "temp_critical_threshold": 75.0,
    "enable_history": true,
    "history_max_entries": 50,
    "enable_shortcuts": true,
    "sentence_type": "hitokoto",
    "sentence_refresh_interval": 300,
    "marquee_update_interval": 0.3
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

### Basic Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | `false` | Enable/disable menu bar feature |
| `on_demand_monitoring` | boolean | `true` | On-demand monitoring (update only when menu open) |
| `refresh_interval` | number | `5` | Metric refresh interval (seconds, non-demand mode) |
| `show_cpu_temp` | boolean | `true` | Display CPU temperature in menu |
| `show_memory` | boolean | `true` | Display memory usage in menu |
| `show_disk` | boolean | `true` | Display disk usage in menu |
| `show_battery` | boolean | `true` | Display battery status in menu (laptops) |
| `show_ports` | boolean | `true` | Display port monitoring in menu |

### Monitoring Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `show_top_processes` | boolean | `false` | Show Top 3 processes in Memory submenu |
| `high_cpu_threshold` | number | `80.0` | High CPU warning threshold (%) |
| `monitored_ports` | array | `[3000, 8080, ...]` | List of ports to monitor |
| `show_temp_alert` | boolean | `true` | Show temperature alerts |
| `temp_warning_threshold` | number | `60.0` | Temperature warning threshold (°C) |
| `temp_critical_threshold` | number | `75.0` | Temperature critical threshold (°C) |

### History and Shortcuts

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enable_history` | boolean | `false` | Enable command history |
| `history_max_entries` | number | `50` | Maximum history entries |
| `history_execution_mode` | string | `"background"` | History execution mode (`terminal`/`background`) |
| `enable_shortcuts` | boolean | `false` | Enable custom shortcuts |
| `shortcuts` | object | `{}` | Custom shortcut definitions |

### Advanced Configuration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `sentence_type` | string | `"hitokoto"` | Sentence type (hitokoto/etc.) |
| `sentence_refresh_interval` | number | `300` | Sentence refresh interval (seconds, default 5 min) |
| `marquee_update_interval` | number | `0.3` | Marquee scroll speed (seconds) |

### Internationalization (i18n)

The menu bar app supports Chinese and English interfaces, automatically following the system `language` configuration:

```json
{
  "language": "zh",  // or "en"
  "menubar": {
    "enabled": true
  }
}
```

**Supported Languages**:
- `zh`: Chinese (Simplified)
- `en`: English

All menu items and notification messages are automatically translated.

### Configuration Examples

**Minimal Configuration**:
```json
{
  "menubar": {
    "enabled": true
  }
}
```

**Full Configuration (Recommended)**:
```json
{
  "menubar": {
    "enabled": true,
    "on_demand_monitoring": true,
    "refresh_interval": 5,
    "show_cpu_temp": true,
    "show_memory": true,
    "show_disk": true,
    "show_battery": true,
    "show_ports": true,
    "monitored_ports": [3000, 8080, 80, 443, 5432, 3306, 6379, 27017],
    "show_temp_alert": true,
    "temp_warning_threshold": 60.0,
    "temp_critical_threshold": 75.0,
    "enable_history": true,
    "history_max_entries": 50,
    "history_execution_mode": "background",
    "enable_shortcuts": true,
    "shortcuts": {
      "📊 Status Check": {
        "command": "gs status",
        "execution_mode": "terminal"
      }
    },
    "sentence_type": "poetry",
    "sentence_refresh_interval": 600,
    "marquee_update_interval": 0.2
  }
}
```

---

## Usage

### Basic Usage

Once the menu bar is enabled, it works automatically:

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
Idle → Running (no progress) → Running (with progress) → Success/Failure → [5s] → Idle
 GS      GS cmd 5s              GS cmd 45% 2m            GS cmd 1s ✓/✗       GS
```

### State Details

#### 1. Idle State
- **Display**: `GS`
- **Trigger**: No command executing
- **Duration**: Until next command starts

#### 2. Running State (No Progress)
- **Display**: `GS version 5s`
- **Trigger**: Command starts without progress reporting
- **Updates**: Time refreshes every second

#### 3. Running State (With Progress)
- **Display**: `GS spider.crawl 45% 2m15s`
- **Trigger**: Command executing with generator yield progress reporting
- **Progress Range**: 0-100%

**Example Plugin Code**:
```python
@plugin_function
async def long_task(self, args=None):
    for i in range(100):
        # Execute task...
        yield {"progress": i}  # Report progress
    return CommandResult(success=True)
```

#### 4. Success State
- **Display**: `GS version 1.2s ✓`
- **Trigger**: Command executed successfully
- **Duration**: Displays for 5 seconds then auto-clears

#### 5. Failure State
- **Display**: `GS command 0.5s ✗`
- **Trigger**: Command failed or exception
- **Duration**: Displays for 5 seconds then auto-clears

---

## Marquee Scrolling

### Trigger Condition

Automatic scrolling when display width exceeds 30:
- **Chinese characters**: 2 width units
- **English/numbers/symbols**: 1 width unit

**Examples**:
- `GS version 1s` → Width 13, no scroll
- `GS This is a very long sentence` → Width > 30, scrolling
- `GS 这是一个比较长的句子` → Width > 30, scrolling

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

3-tier fallback detection method:

#### Method 1: sysctl (Thermal Level)
```bash
sysctl machdep.xcpm.cpu_thermal_level
# Returns: 0-100 thermal level
# Convert: 40 + (level * 0.6) = temperature (°C)
```
- **Pros**: Fast, no permissions needed
- **Cons**: Approximate thermal level

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
# Method 1: sysctl
sysctl machdep.xcpm.cpu_thermal_level

# Method 2: ioreg
ioreg -rn AppleARMIODevice | grep temperature

# Method 3: CPU usage
uv run python -c "
import psutil
cpu = psutil.cpu_percent(interval=0.5)
temp = 40 + (cpu * 0.4)
print(f'CPU: {cpu}% → Estimated temp: {temp:.1f}°C')
"

# Check logs
tail -100 ~/.config/global-scripts/logs/menubar.log | grep -i temp
```

### Battery Health Display Error

If battery health shows abnormal values (e.g., new laptop showing 2%), please update to the latest version. Fixes include:
- Use correct `AppleRawMaxCapacity` field (actual mAh capacity)
- Fix temperature unit conversion (decikelvin → °C)

```bash
# View battery information
ioreg -rn AppleSmartBattery | grep -E "(MaxCapacity|AppleRawMaxCapacity|DesignCapacity|CycleCount)"

# Expected output:
# "AppleRawMaxCapacity" = 6428    ← Actual capacity (mAh)
# "MaxCapacity" = 100              ← Percentage (not capacity!)
# "DesignCapacity" = 6249          ← Design capacity (mAh)
```

### Disk Usage Display Error

If disk usage shows too little (e.g., 11GB), please update to the latest version. Fixes include:
- macOS APFS systems now correctly detect `/System/Volumes/Data` data volume
- Automatically compare system snapshot and data volume, use larger value

```bash
# Verify fix
df -h /
df -h /System/Volumes/Data

# Check logs
tail -100 ~/.config/global-scripts/logs/menubar.log | grep -i disk
```

### Port Monitoring Not Working

```bash
# Manual test port detection
lsof -i :3000

# Expected output:
# COMMAND   PID   USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME
# node    12345  user   21u  IPv4  0x1234      0t0  TCP *:3000 (LISTEN)

# Check logs
tail -100 ~/.config/global-scripts/logs/menubar.log | grep -i port
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
gs menubar stop
sleep 2
gs menubar start
```

### Marquee Not Scrolling

Check if text width exceeds 30:
```bash
uv run python -c "
from gscripts.menubar.marquee import Marquee
text = 'GS Your text content'
m = Marquee(text, max_length=30)
print(f'Text: {text}')
print(f'Width: {m._display_width}')
print(f'Needs scroll: {m.needs_scroll}')
"
```

---

## Logs and Debugging

### Log File

```bash
~/.config/global-scripts/logs/menubar.log
```

### Real-time Viewing

```bash
# Real-time view
tail -f ~/.config/global-scripts/logs/menubar.log

# View last 50 lines
tail -50 ~/.config/global-scripts/logs/menubar.log

# Filter specific content
tail -100 ~/.config/global-scripts/logs/menubar.log | grep -i "command"
```

---

## Technical Implementation

### Architecture Components

| Component | File | Description |
|-----------|------|-------------|
| Main App | `menubar/app.py` | rumps menu bar application |
| Status Manager | `menubar/status_manager.py` | Command status formatting |
| System Monitors | `menubar/monitors.py` | CPU/memory monitoring |
| IPC Server | `menubar/ipc.py` | Unix socket server |
| Marquee | `menubar/marquee.py` | Scrolling text effect |
| Sentence API | `menubar/sentence_api.py` | Random sentence retrieval |
| Icon | `menubar/icon.py` | Menu bar icon definition |

### Background Tasks

1. **Metrics Updater**: Updates CPU temperature and memory usage every 5 seconds
2. **Sentence Updater**: Fetches new random sentence every 5 minutes (configurable)
3. **Marquee Updater**: Updates scroll position every 0.3 seconds (if needed)
4. **IPC Server**: Listens for command status messages from CLI

---

## Comparison with ClashX

| Feature | GS Menu Bar | ClashX | Notes |
|---------|-------------|--------|-------|
| Menu bar only | ✅ | ✅ | Not shown in Dock |
| Hidden from Cmd+Tab | ✅ | ✅ | Not shown in app switcher |
| Real-time status | ✅ | ✅ | Command execution status |
| System monitoring | ✅ CPU/Memory | ✅ Network | Different monitoring content |
| Text display | ✅ | ✅ | No emoji icons |
| Dark mode support | ✅ | ✅ | Auto-adapt system theme |
| Marquee scrolling | ✅ | - | GS exclusive feature |

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
- **Background execution**: Keep status visible without terminal
- **System monitoring**: Real-time CPU temperature and memory usage
- **Multitasking**: No need to switch terminal windows

### Performance Recommendations

- `refresh_interval` set to 5-10 seconds is sufficient
- `marquee_update_interval` recommended 0.2-0.5 seconds
- `sentence_refresh_interval` recommended 5-10 minutes

---

## Limitations and Notes

1. **macOS only**: Menu bar feature is macOS-exclusive
2. **Requires rumps**: Must install `rumps` library
3. **Apple Silicon temp**: Temperature reading is approximate, not precise
4. **Text length**: Very long text triggers marquee scrolling, may affect readability
5. **Auto-clear**: Status clears after 5 seconds, modify config for longer display

---

## FAQ

### Q: How to change the menu bar icon?

A: Currently uses "GS" text icon. Future versions will support custom icon files. Temporarily modify `MENUBAR_ICON` in `src/gscripts/menubar/icon.py`.

### Q: Why doesn't idle state show sentence?

A: To avoid crowding other menu bar icons, idle state only shows "GS". Sentence feature is implemented but disabled by default.

### Q: How to extend status display time?

A: Modify `threading.Timer(5.0, self._clear_status)` parameter in `src/gscripts/menubar/app.py` (currently 5 seconds).

### Q: Marquee scrolling too fast/slow?

A: Adjust `marquee_update_interval` in configuration (default 0.3 seconds).

### Q: Windows/Linux support?

A: Not supported. Menu bar feature is macOS-only. Other platforms could consider system tray implementation.

---

## Changelog

### Version 5.2.0 (2025-11-09)

**Major Updates**:
- ✨ **Disk Monitoring** (Phase 6.2): Disk usage, I/O speed, pressure levels
- ✨ **Battery Monitoring** (Phase 3): Battery health, cycle count, temperature, remaining time
- ✨ **Port Monitoring** (Phase 5): Common development port detection, process termination
- ✨ **Temperature Alerts** (Phase 6): Configurable temperature thresholds, three-level alerts (🟢/🟡/🔴)
- ✨ **On-Demand Monitoring** (Phase 6.1): Update only when menu open, saves 80% CPU usage
- ✨ **Command History** (Phase 1): Recent command recording, replay functionality
- ✨ **Custom Shortcuts** (Phase 2): Quick execution of common commands

**Critical Fixes**:
- 🐛 **Fixed Battery Health Calculation**: New laptops showing 2% health error (now correctly shows 102.9%)
  - Use `AppleRawMaxCapacity` field (actual mAh) instead of `MaxCapacity` (percentage)
  - Fix temperature unit conversion (decikelvin → °C)
- 🐛 **Fixed Disk Usage Calculation**: macOS APFS systems showing 11GB error (now correctly shows 336GB)
  - Detect `/System/Volumes/Data` data volume instead of only system snapshot
  - Automatically select volume with larger usage

**Performance Optimizations**:
- ⚡ On-demand monitoring mode reduces 80%+ CPU usage
- ⚡ All monitors support caching (1-2 seconds)
- ⚡ Port detection uses concurrent checking (ThreadPoolExecutor)

**Test Coverage**:
- ✅ Added 17 temperature alert unit tests (100% pass)
- ✅ Improved battery, disk, and port monitoring tests

### Version 5.2.0-dev (Historical)
- ✨ Added marquee scrolling effect
- ✨ Added Hitokoto API integration
- ✨ Support command output display
- ✨ Optimized Apple Silicon CPU temperature detection
- 🐛 Fixed Dock icon display issue
- 🐛 Fixed status clear time (15s → 5s)
- 🎨 Changed icon to "GS" text (configurable)

---

## Related Resources

- [Main Documentation](../../README_EN.md)
- [Plugin Development Guide](./plugin-development.md)
- [Architecture Document](./architecture.md)
- [Contributing Guide](./contributing.md)
