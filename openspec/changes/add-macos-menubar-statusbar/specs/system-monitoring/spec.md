# System Monitoring Specification

## ADDED Requirements

### Requirement: CPU Temperature Monitoring
The system SHALL collect and display CPU/system temperature metrics in the menu bar at configurable intervals.

#### Scenario: Display temperature on macOS with sensors available
- **WHEN** the menu bar app is running on macOS with temperature sensor access
- **THEN** the current CPU temperature is displayed in the menu (e.g., "CPU: 45°C")
- **AND** the temperature updates every N seconds (based on refresh_interval config)

#### Scenario: Temperature unavailable
- **WHEN** temperature sensors are not accessible (no admin permissions or unsupported hardware)
- **THEN** the temperature metric shows "CPU: N/A"
- **AND** an error is logged once (not repeatedly)
- **AND** the app continues running with other metrics

#### Scenario: Temperature exceeds threshold
- **WHEN** CPU temperature exceeds a configured warning threshold (e.g., 80°C)
- **THEN** the temperature display changes color or shows a warning icon
- **AND** a system notification is sent (configurable)

### Requirement: Metric Data Collection
The system SHALL use platform-appropriate methods to collect system metrics with error handling and fallback behavior.

#### Scenario: Use psutil for system metrics
- **WHEN** collecting metrics like CPU usage, memory, or temperature
- **THEN** the system uses the `psutil` library as the primary data source
- **AND** wraps calls in try-except to handle unavailable sensors

#### Scenario: Use macOS-specific tools as fallback
- **WHEN** psutil cannot provide temperature data
- **THEN** the system attempts to use macOS-specific commands (e.g., `osx-cpu-temp`, `powermetrics`)
- **AND** if all methods fail, displays "N/A" for that metric

#### Scenario: Metric collection timeout
- **WHEN** a metric collection call takes longer than 2 seconds
- **THEN** the call is cancelled
- **AND** the metric displays the last known value with a stale indicator
- **AND** a warning is logged

### Requirement: Real-Time Metric Updates
The system SHALL refresh displayed metrics at user-configurable intervals without blocking the UI thread.

#### Scenario: Periodic background updates
- **WHEN** the menu bar app is running
- **THEN** a background thread updates metrics every `refresh_interval` seconds (default: 5s)
- **AND** the menu bar text/icon updates reflect the new values
- **AND** the main UI thread remains responsive during updates

#### Scenario: Manual refresh
- **WHEN** user selects "Refresh" from the menu bar
- **THEN** all metrics are immediately updated (bypassing the normal interval)
- **AND** the next periodic update continues on schedule

#### Scenario: Suspend updates when menu is open
- **WHEN** the user opens the menu bar dropdown
- **THEN** metric updates are paused while the menu is visible
- **AND** updates resume when the menu is closed

### Requirement: Extensible Metric System
The system SHALL provide a plugin-style architecture for adding new metric monitors with minimal code changes.

#### Scenario: Register built-in monitors
- **WHEN** the menu bar app initializes
- **THEN** it loads all built-in metric monitors (temperature, time, etc.)
- **AND** each monitor registers its name, collection method, and display format

#### Scenario: Add custom monitor
- **WHEN** a developer creates a new monitor class inheriting from `BaseMonitor`
- **THEN** the monitor can be enabled via configuration by name
- **AND** the monitor appears in the menu bar without changes to app.py

#### Scenario: Disable individual monitors
- **WHEN** user removes a metric name from `enabled_metrics` config
- **THEN** that monitor stops collecting data
- **AND** the metric is removed from the menu display
- **AND** associated background threads are cleaned up

### Requirement: Build Progress Tracking (Future Extension)
The system SHALL support tracking build progress for long-running operations (designed for future implementation).

#### Scenario: Display build status placeholder
- **WHEN** build progress tracking is enabled in config
- **THEN** a "Build: Idle" menu item appears
- **AND** the status shows "N/A - Not Yet Implemented"
- **AND** the feature is marked as "Coming Soon" in documentation

**Note**: Full build progress tracking (detecting builds, parsing logs, showing percentage) is intentionally deferred to a future proposal to keep scope manageable.

### Requirement: Current Time Display
The system SHALL optionally display the current time in the menu bar as a simple metric example.

#### Scenario: Show current time
- **WHEN** "current_time" is included in enabled_metrics
- **THEN** the menu displays the current time (e.g., "Time: 14:35:22")
- **AND** updates every refresh_interval seconds

#### Scenario: Time format configuration
- **WHEN** user sets `time_format` in config (e.g., "%H:%M" or "%I:%M %p")
- **THEN** the time displays in the specified format
- **AND** defaults to "%H:%M:%S" if not configured

### Requirement: Error Handling and Logging
The system SHALL handle metric collection failures gracefully without crashing the menu bar app.

#### Scenario: Metric collector raises exception
- **WHEN** a metric monitor's collect() method raises an exception
- **THEN** the exception is caught and logged with full traceback
- **AND** the metric displays "Error" or last known good value
- **AND** the menu bar app continues running normally

#### Scenario: Monitor initialization failure
- **WHEN** a configured metric monitor fails to initialize (e.g., missing dependency)
- **THEN** a warning is logged indicating the monitor is disabled
- **AND** the monitor is skipped without affecting other monitors
- **AND** the failure is visible in `gs menubar status` output
