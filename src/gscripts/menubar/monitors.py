"""
System Monitors for Menu Bar

Provides monitors for CPU temperature and memory usage.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List, Tuple
from collections import deque
import time
import logging

logger = logging.getLogger(__name__)

# Import i18n manager
from ..utils.i18n import get_i18n_manager
_i18n = get_i18n_manager()


class BaseMonitor(ABC):
    """Base class for system monitors"""

    @abstractmethod
    def collect(self) -> Optional[Any]:
        """Collect metric value"""
        pass

    @abstractmethod
    def format(self, value: Any) -> str:
        """Format value for display"""
        pass

    def get_display_text(self) -> str:
        """Get formatted display text"""
        try:
            value = self.collect()
            if value is None:
                return self.format_unavailable()
            return self.format(value)
        except Exception as e:
            logger.debug(f"Error collecting metric: {e}")
            return self.format_unavailable()

    def format_unavailable(self) -> str:
        """Format text when metric unavailable"""
        return "N/A"


class CPUTemperatureMonitor(BaseMonitor):
    """Monitor CPU temperature using platform-specific methods"""

    def __init__(self, warning_threshold: float = 60.0, critical_threshold: float = 75.0):
        self.label = "CPU"
        self._last_value: Optional[float] = None
        self._sensor_unavailable = False
        self._is_apple_silicon = self._detect_apple_silicon()

        # Temperature trend tracking (Phase 5.1)
        # Store (timestamp, temperature) tuples in a rolling 5-minute window
        self._temp_history: deque = deque(maxlen=300)  # 5 min × 60 readings/min
        self._peak_temp: Optional[float] = None

        # Temperature alert thresholds (Phase 6)
        self.warning_threshold = warning_threshold
        self.critical_threshold = critical_threshold
        self._alert_state: str = "normal"  # "normal", "warning", "critical"

    def _detect_apple_silicon(self) -> bool:
        """Detect if running on Apple Silicon"""
        try:
            import platform
            return platform.processor() == 'arm' or platform.machine() == 'arm64'
        except Exception:
            return False

    def _get_apple_silicon_temp(self) -> Optional[float]:
        """Get CPU temperature on Apple Silicon using powermetrics"""
        try:
            import subprocess
            import re

            # Use powermetrics to get CPU temperature (requires sudo, but we'll try without)
            # Alternative: use sysctl or ioreg
            result = subprocess.run(
                ['sysctl', 'machdep.xcpm.cpu_thermal_level'],
                capture_output=True,
                text=True,
                timeout=1
            )

            if result.returncode == 0 and result.stdout:
                # Parse thermal level (0-100 scale)
                match = re.search(r':\s*(\d+)', result.stdout)
                if match:
                    thermal_level = int(match.group(1))
                    # Convert thermal level to approximate temperature
                    # Thermal levels typically: 0 (cool) to 100 (hot)
                    # Approximate: 40°C at level 0, up to 100°C at level 100
                    temp = 40 + (thermal_level * 0.6)
                    return temp

            # Try alternative method using ioreg (battery temperature as proxy)
            result = subprocess.run(
                ['ioreg', '-rn', 'AppleARMIODevice'],
                capture_output=True,
                text=True,
                timeout=1
            )

            if result.returncode == 0:
                # Look for temperature readings in ioreg output
                match = re.search(r'"temperature"\s*=\s*(\d+)', result.stdout)
                if match:
                    # Temperature is usually in centigrade * 100
                    temp_raw = int(match.group(1))
                    temp = temp_raw / 100.0
                    if 20 <= temp <= 120:  # Sanity check
                        return temp

            # If all else fails, estimate based on CPU usage
            try:
                import psutil
                cpu_percent = psutil.cpu_percent(interval=0.1)
                # Rough estimate: idle ~40°C, full load ~80°C
                estimated_temp = 40 + (cpu_percent * 0.4)
                return estimated_temp
            except Exception:
                pass

        except Exception as e:
            logger.debug(f"Error getting Apple Silicon temp: {e}")

        return None

    def collect(self) -> Optional[float]:
        """
        Collect CPU temperature in Celsius

        Returns:
            Temperature in Celsius, or None if unavailable
        """
        # If we already know sensors are unavailable, don't keep trying
        if self._sensor_unavailable:
            return self._last_value

        # Try Apple Silicon method first
        if self._is_apple_silicon:
            temp = self._get_apple_silicon_temp()
            if temp is not None:
                self._last_value = temp
                self._track_temperature(temp)  # Track for trend analysis
                return temp

        # Fall back to standard psutil method for Intel Macs
        try:
            import psutil

            temps = psutil.sensors_temperatures()

            # Try different sensor names (platform-dependent)
            sensor_names = ["coretemp", "cpu_thermal", "k10temp", "zenpower", "soc_thermal"]

            for sensor_name in sensor_names:
                if sensor_name in temps and len(temps[sensor_name]) > 0:
                    # Get first sensor reading
                    temp = temps[sensor_name][0].current
                    self._last_value = temp
                    self._track_temperature(temp)  # Track for trend analysis
                    return temp

            # If no known sensor found, try any available sensor
            if temps:
                first_sensor = next(iter(temps.values()))
                if first_sensor:
                    temp = first_sensor[0].current
                    self._last_value = temp
                    self._track_temperature(temp)  # Track for trend analysis
                    return temp

            # No sensors available
            if not temps or not any(temps.values()):
                logger.debug("No temperature sensors available via psutil")
                # Don't mark as permanently unavailable yet, keep trying Apple Silicon method

        except ImportError:
            logger.debug("psutil not available for temperature monitoring")
        except Exception as e:
            logger.debug(f"Error reading temperature: {e}")

        return self._last_value  # Return cached value if available

    def _track_temperature(self, temp: float) -> None:
        """
        Track temperature reading for trend analysis and alert checking.

        Args:
            temp: Temperature in Celsius
        """
        current_time = time.time()
        self._temp_history.append((current_time, temp))

        # Update peak temperature
        if self._peak_temp is None or temp > self._peak_temp:
            self._peak_temp = temp

        # Update alert state (Phase 6)
        self.update_alert_state(temp)

    def _calculate_trend(self, threshold: float = 2.0) -> str:
        """
        Calculate temperature trend based on recent history.

        Args:
            threshold: Temperature difference in °C to consider rising/falling (default: 2.0)

        Returns:
            Trend indicator: "↑" (rising), "↓" (falling), "→" (stable)
        """
        if len(self._temp_history) < 2:
            return "→"  # Not enough data

        current_time = time.time()
        current_temp = self._temp_history[-1][1]

        # Find temperature from 30 seconds ago
        comparison_time = current_time - 30.0
        comparison_temp = None

        for timestamp, temp in self._temp_history:
            if timestamp >= comparison_time:
                comparison_temp = temp
                break

        if comparison_temp is None:
            return "→"  # Not enough historical data

        diff = current_temp - comparison_temp

        if diff > threshold:
            return "↑"
        elif diff < -threshold:
            return "↓"
        else:
            return "→"

    def _calculate_avg(self) -> Optional[float]:
        """
        Calculate average temperature over last 5 minutes.

        Returns:
            Average temperature in Celsius, or None if insufficient data
        """
        if len(self._temp_history) < 6:  # Need at least 30 seconds of data
            return None

        total_temp = sum(temp for _, temp in self._temp_history)
        return total_temp / len(self._temp_history)

    def get_peak_temp(self) -> Optional[float]:
        """
        Get peak temperature for current session.

        Returns:
            Peak temperature in Celsius, or None if no data
        """
        return self._peak_temp

    def get_temp_trend(self) -> str:
        """Get current temperature trend indicator"""
        return self._calculate_trend()

    def get_temp_avg(self) -> Optional[float]:
        """Get average temperature over last 5 minutes"""
        return self._calculate_avg()

    def check_alert_state(self, temp: float) -> str:
        """
        Check temperature against thresholds and determine alert state.

        Args:
            temp: Current temperature in Celsius

        Returns:
            Alert state: "normal", "warning", or "critical"
        """
        if temp >= self.critical_threshold:
            return "critical"
        elif temp >= self.warning_threshold:
            return "warning"
        else:
            return "normal"

    def update_alert_state(self, temp: float) -> bool:
        """
        Update alert state based on current temperature.

        Args:
            temp: Current temperature in Celsius

        Returns:
            True if alert state changed, False otherwise
        """
        new_state = self.check_alert_state(temp)
        if new_state != self._alert_state:
            old_state = self._alert_state
            self._alert_state = new_state
            logger.info(f"Temperature alert state changed: {old_state} -> {new_state} (temp: {temp:.1f}°C)")
            return True
        return False

    def get_alert_state(self) -> str:
        """
        Get current alert state.

        Returns:
            Current alert state: "normal", "warning", or "critical"
        """
        return self._alert_state

    def is_alert_active(self) -> bool:
        """
        Check if any temperature alert is active.

        Returns:
            True if warning or critical alert is active
        """
        return self._alert_state in ("warning", "critical")

    def get_alert_message(self) -> Optional[str]:
        """
        Get alert message for current state.

        Returns:
            Alert message if alert active, None if normal
        """
        if self._alert_state == "critical":
            return f"🔴 Critical: CPU temperature is {self._last_value:.1f}°C (threshold: {self.critical_threshold}°C)"
        elif self._alert_state == "warning":
            return f"🟡 Warning: CPU temperature is {self._last_value:.1f}°C (threshold: {self.warning_threshold}°C)"
        return None

    def format(self, value: float) -> str:
        """Format temperature for display"""
        return f"{int(value)}°C"

    def format_unavailable(self) -> str:
        """Format when temperature unavailable"""
        return "N/A"


class MemoryMonitor(BaseMonitor):
    """Monitor memory usage using psutil"""

    def __init__(self):
        self.label = "Memory"

    def collect(self) -> Optional[float]:
        """
        Collect memory usage percentage

        Returns:
            Memory usage percentage (0-100), or None if unavailable
        """
        try:
            import psutil

            mem = psutil.virtual_memory()
            return mem.percent
        except ImportError:
            logger.debug("psutil not available for memory monitoring")
        except Exception as e:
            logger.debug(f"Error reading memory: {e}")

        return None

    def format(self, value: float) -> str:
        """Format memory usage for display"""
        return f"{int(value)}%"

    def format_unavailable(self) -> str:
        """Format when memory unavailable"""
        return "N/A"


class CPUUsageMonitor(BaseMonitor):
    """Monitor CPU usage percentage with threshold warning"""

    def __init__(self, threshold: float = 80.0, hysteresis: float = 10.0):
        """
        Initialize CPU usage monitor.

        Args:
            threshold: CPU usage % threshold to trigger warning (default: 80%)
            hysteresis: % to drop below threshold before clearing warning (default: 10%)
        """
        self.label = "CPU Usage"
        self.threshold = threshold
        self.hysteresis = hysteresis
        self._last_value: Optional[float] = None
        self._warning_active = False

    def collect(self) -> Optional[float]:
        """
        Collect CPU usage percentage.

        Returns:
            CPU usage percentage (0-100), or None if unavailable
        """
        try:
            import psutil

            # Get CPU usage over 1 second interval
            usage = psutil.cpu_percent(interval=1.0)
            self._last_value = usage

            # Update warning state with hysteresis
            if usage >= self.threshold:
                self._warning_active = True
            elif usage < (self.threshold - self.hysteresis):
                self._warning_active = False

            return usage
        except ImportError:
            logger.debug("psutil not available for CPU usage monitoring")
        except Exception as e:
            logger.debug(f"Error reading CPU usage: {e}")

        return self._last_value

    def is_warning_active(self) -> bool:
        """Check if high CPU warning is active"""
        return self._warning_active

    def format(self, value: float) -> str:
        """Format CPU usage for display"""
        return f"{int(value)}%"

    def format_unavailable(self) -> str:
        """Format when CPU usage unavailable"""
        return "N/A"


class CPUMetricsCollector:
    """
    Comprehensive CPU metrics collector for enhanced monitoring (Phase 5.2).

    Collects:
    - Overall CPU usage percentage
    - Per-core CPU usage percentages
    - Temperature with trend analysis
    """

    def __init__(self, temp_monitor: CPUTemperatureMonitor):
        """
        Initialize CPU metrics collector.

        Args:
            temp_monitor: Existing CPUTemperatureMonitor instance for temperature data
        """
        self.temp_monitor = temp_monitor
        self._last_collection_time: Optional[float] = None
        self._cached_metrics: Optional[Dict[str, Any]] = None
        self._cache_duration: float = 1.0  # Cache for 1 second

    def collect(self) -> Dict[str, Any]:
        """
        Collect comprehensive CPU metrics.

        Returns:
            Dictionary with keys:
            - overall: Overall CPU usage percentage
            - per_core: List of per-core usage percentages
            - temp_current: Current temperature (or None)
            - temp_trend: Temperature trend indicator ("↑", "↓", "→")
            - temp_avg: Average temperature over 5 minutes (or None)
            - temp_peak: Peak temperature for session (or None)
        """
        # Return cached metrics if still valid
        current_time = time.time()
        if (self._cached_metrics is not None and
                self._last_collection_time is not None and
                (current_time - self._last_collection_time) < self._cache_duration):
            return self._cached_metrics

        # Collect new metrics
        try:
            import psutil

            # Overall CPU usage
            overall_percent = psutil.cpu_percent(interval=0.1)

            # Per-core CPU usage
            per_core_percent = psutil.cpu_percent(interval=0.1, percpu=True)

            # Temperature metrics
            temp_current = self.temp_monitor.collect()
            temp_trend = self.temp_monitor.get_temp_trend()
            temp_avg = self.temp_monitor.get_temp_avg()
            temp_peak = self.temp_monitor.get_peak_temp()

            metrics = {
                "overall": overall_percent,
                "per_core": per_core_percent,
                "temp_current": temp_current,
                "temp_trend": temp_trend,
                "temp_avg": temp_avg,
                "temp_peak": temp_peak,
            }

            # Cache the results
            self._cached_metrics = metrics
            self._last_collection_time = current_time

            return metrics

        except ImportError:
            logger.debug("psutil not available for CPU metrics collection")
        except Exception as e:
            logger.debug(f"Error collecting CPU metrics: {e}")

        # Return minimal metrics on error
        return {
            "overall": None,
            "per_core": [],
            "temp_current": self.temp_monitor.collect(),
            "temp_trend": self.temp_monitor.get_temp_trend(),
            "temp_avg": self.temp_monitor.get_temp_avg(),
            "temp_peak": self.temp_monitor.get_peak_temp(),
        }


class MemoryMetricsCollector:
    """
    Comprehensive memory metrics collector for enhanced monitoring (Phase 5.3).

    Collects:
    - Total memory usage
    - Memory breakdown (App, Wired, Compressed, Cached)
    - Swap usage
    - Memory pressure indicator
    - Top memory-consuming processes (optional)
    """

    def __init__(self):
        """Initialize memory metrics collector."""
        self._last_collection_time: Optional[float] = None
        self._cached_metrics: Optional[Dict[str, Any]] = None
        self._cache_duration: float = 1.0  # Cache for 1 second

        self._last_process_collection_time: Optional[float] = None
        self._cached_processes: Optional[List[Dict[str, Any]]] = None
        self._process_cache_duration: float = 2.0  # Cache processes for 2 seconds

    def collect(self, include_processes: bool = False) -> Dict[str, Any]:
        """
        Collect comprehensive memory metrics.

        Args:
            include_processes: Whether to include top memory-consuming processes

        Returns:
            Dictionary with keys:
            - total: Total memory in GB
            - used: Used memory in GB
            - percent: Memory usage percentage
            - app: Application memory in GB
            - wired: Wired memory in GB
            - cached: Cached memory in GB
            - compressed: Compressed memory in GB
            - swap: Swap usage in GB
            - pressure: Memory pressure indicator ("🟢 Normal", "🟡 Moderate", "🔴 High")
            - top_processes: (optional) List of top 3 processes with memory usage
        """
        # Return cached metrics if still valid (excluding processes)
        current_time = time.time()
        if (not include_processes and
                self._cached_metrics is not None and
                self._last_collection_time is not None and
                (current_time - self._last_collection_time) < self._cache_duration):
            return self._cached_metrics

        try:
            import psutil

            # Virtual memory stats
            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()

            # Convert bytes to GB
            gb = 1024 ** 3

            metrics = {
                "total": mem.total / gb,
                "used": mem.used / gb,
                "percent": mem.percent,
                "app": getattr(mem, 'active', mem.used) / gb,  # Active memory (App memory)
                "wired": getattr(mem, 'wired', 0) / gb,  # Wired memory (macOS-specific)
                "cached": getattr(mem, 'cached', getattr(mem, 'buffers', 0)) / gb,  # Cached files
                "compressed": getattr(mem, 'compressed', 0) / gb,  # Compressed memory (macOS-specific)
                "swap": swap.used / gb,
                "pressure": self._calculate_pressure(mem.percent),
            }

            # Add top processes if requested
            if include_processes:
                metrics["top_processes"] = self._get_top_processes()

            # Cache the results (without processes)
            if not include_processes:
                self._cached_metrics = metrics
                self._last_collection_time = current_time

            return metrics

        except ImportError:
            logger.debug("psutil not available for memory metrics collection")
        except Exception as e:
            logger.debug(f"Error collecting memory metrics: {e}")

        # Return minimal metrics on error
        return {
            "total": 0,
            "used": 0,
            "percent": 0,
            "app": 0,
            "wired": 0,
            "cached": 0,
            "compressed": 0,
            "swap": 0,
            "pressure": "N/A",
        }

    def _calculate_pressure(self, percent: float) -> str:
        """
        Calculate memory pressure level.

        Args:
            percent: Memory usage percentage

        Returns:
            Pressure indicator: "🟢 Normal", "🟡 Moderate", "🔴 High"
        """
        if percent < 60:
            return _i18n.get_message("menubar.menu.memory_pressure_normal")
        elif percent < 80:
            return _i18n.get_message("menubar.menu.memory_pressure_moderate")
        else:
            return _i18n.get_message("menubar.menu.memory_pressure_high")

    def _get_top_processes(self) -> List[Dict[str, Any]]:
        """
        Get top 3 memory-consuming processes (Phase 5.4).

        Returns:
            List of dicts with keys: pid, name, memory (in GB)
        """
        # Return cached processes if still valid
        current_time = time.time()
        if (self._cached_processes is not None and
                self._last_process_collection_time is not None and
                (current_time - self._last_process_collection_time) < self._process_cache_duration):
            return self._cached_processes

        try:
            import psutil

            processes = []

            # Iterate through all processes
            for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
                try:
                    proc_info = proc.info
                    if proc_info['memory_info'] is not None:
                        processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'memory': proc_info['memory_info'].rss / (1024 ** 3)  # Convert to GB
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    # Skip processes we can't access
                    continue

            # Sort by memory usage descending and take top 3
            processes.sort(key=lambda p: p['memory'], reverse=True)
            top_processes = processes[:3]

            # Cache the results
            self._cached_processes = top_processes
            self._last_process_collection_time = current_time

            return top_processes

        except ImportError:
            logger.debug("psutil not available for process collection")
        except Exception as e:
            logger.debug(f"Error collecting top processes: {e}")

        return []


class DiskMetricsCollector:
    """
    Disk metrics collector for enhanced monitoring (Phase 6.2).

    Collects:
    - Disk usage (total, used, free, percent)
    - I/O read/write rates (MB/s)
    - Disk pressure indicator
    """

    def __init__(self):
        """Initialize disk metrics collector."""
        self._last_collection_time: Optional[float] = None
        self._cached_metrics: Optional[Dict[str, Any]] = None
        self._cache_duration: float = 1.0  # Cache for 1 second

        # I/O rate tracking
        self._last_io_counters = None
        self._last_io_time: Optional[float] = None

    def collect(self) -> Dict[str, Any]:
        """
        Collect comprehensive disk metrics.

        Returns:
            Dictionary with keys:
            - total: Total disk space in GB
            - used: Used disk space in GB
            - free: Free disk space in GB
            - percent: Disk usage percentage
            - io_read_rate: Read rate in MB/s
            - io_write_rate: Write rate in MB/s
            - pressure: Disk pressure indicator ("🟢 Normal", "🟡 Moderate", "🔴 High")
        """
        # Return cached metrics if still valid
        current_time = time.time()
        if (self._cached_metrics is not None and
                self._last_collection_time is not None and
                (current_time - self._last_collection_time) < self._cache_duration):
            return self._cached_metrics

        try:
            import psutil
            import platform

            # macOS APFS fix: Check both system snapshot and data volume
            # The root '/' is often a system snapshot with minimal data
            # User data is in '/System/Volumes/Data'
            if platform.system() == 'Darwin':
                # Try to get usage from the actual data volume
                try:
                    data_volume_usage = psutil.disk_usage('/System/Volumes/Data')
                    # Use data volume if it has significantly more usage
                    root_usage = psutil.disk_usage('/')
                    if data_volume_usage.used > root_usage.used:
                        usage = data_volume_usage
                    else:
                        usage = root_usage
                except:
                    # Fallback to root if data volume check fails
                    usage = psutil.disk_usage('/')
            else:
                # Non-macOS: just use root
                usage = psutil.disk_usage('/')

            # Convert bytes to GB
            gb = 1024 ** 3

            # Collect I/O stats (separate method for delta tracking)
            io_stats = self._collect_io_stats()

            metrics = {
                "total": usage.total / gb,
                "used": usage.used / gb,
                "free": usage.free / gb,
                "percent": usage.percent,
                "io_read_rate": io_stats["read_rate"],
                "io_write_rate": io_stats["write_rate"],
                "pressure": self._calculate_pressure(usage.percent),
            }

            # Cache the results (excluding I/O which needs delta tracking)
            self._cached_metrics = metrics
            self._last_collection_time = current_time

            return metrics

        except ImportError:
            logger.debug("psutil not available for disk metrics collection")
        except Exception as e:
            logger.debug(f"Error collecting disk metrics: {e}")

        # Return minimal metrics on error
        return {
            "total": 0,
            "used": 0,
            "free": 0,
            "percent": 0,
            "io_read_rate": 0.0,
            "io_write_rate": 0.0,
            "pressure": "N/A",
        }

    def _collect_io_stats(self) -> Dict[str, float]:
        """
        Collect disk I/O statistics with rate calculation.

        Returns:
            Dictionary with keys:
            - read_rate: Read rate in MB/s
            - write_rate: Write rate in MB/s
        """
        try:
            import psutil

            current_counters = psutil.disk_io_counters()
            current_time = time.time()

            if self._last_io_counters is not None and self._last_io_time is not None:
                # Calculate delta
                delta_time = current_time - self._last_io_time
                delta_read = current_counters.read_bytes - self._last_io_counters.read_bytes
                delta_write = current_counters.write_bytes - self._last_io_counters.write_bytes

                # Convert to MB/s
                read_rate = (delta_read / delta_time) / (1024 * 1024) if delta_time > 0 else 0.0
                write_rate = (delta_write / delta_time) / (1024 * 1024) if delta_time > 0 else 0.0
            else:
                # First collection, no delta available
                read_rate = 0.0
                write_rate = 0.0

            # Update last counters
            self._last_io_counters = current_counters
            self._last_io_time = current_time

            return {
                "read_rate": read_rate,
                "write_rate": write_rate,
            }

        except ImportError:
            logger.debug("psutil not available for I/O stats")
        except Exception as e:
            logger.debug(f"Error collecting I/O stats: {e}")

        return {
            "read_rate": 0.0,
            "write_rate": 0.0,
        }

    def _calculate_pressure(self, percent: float) -> str:
        """
        Calculate disk pressure level.

        Args:
            percent: Disk usage percentage

        Returns:
            Pressure indicator: "🟢 Normal", "🟡 Moderate", "🔴 High"
        """
        if percent < 80:
            return _i18n.get_message("menubar.menu.disk_pressure_normal")
        elif percent < 90:
            return _i18n.get_message("menubar.menu.disk_pressure_moderate")
        else:
            return _i18n.get_message("menubar.menu.disk_pressure_high")


class BatteryMetricsCollector:
    """
    Battery metrics collector for enhanced monitoring (Phase 3).

    Collects:
    - Battery charge level and charging state
    - Time remaining (charging/discharging)
    - Battery health percentage
    - Cycle count
    - Temperature
    - Power source
    """

    def __init__(self):
        """Initialize battery metrics collector."""
        self._last_collection_time: Optional[float] = None
        self._cached_metrics: Optional[Dict[str, Any]] = None
        self._cache_duration: float = 2.0  # Cache for 2 seconds (battery changes slowly)
        self._has_battery: Optional[bool] = None  # Cache whether device has battery

    def collect(self) -> Optional[Dict[str, Any]]:
        """
        Collect comprehensive battery metrics.

        Returns:
            Dictionary with keys:
            - has_battery: bool (False for desktop Macs)
            - percent: Battery charge percentage (0-100)
            - is_charging: bool
            - time_remaining: Time remaining in seconds (None if unknown)
            - power_source: str ("Battery", "AC Adapter", "Unknown")
            - health: float (health percentage, 0-100)
            - cycle_count: int
            - temperature: float (temperature in Celsius, None if unavailable)

            Returns None if no battery is present (desktop Mac).
        """
        # Check if device has battery (cache the result)
        if self._has_battery is False:
            return None

        # Return cached metrics if still valid
        current_time = time.time()
        if (self._cached_metrics is not None and
                self._last_collection_time is not None and
                (current_time - self._last_collection_time) < self._cache_duration):
            return self._cached_metrics

        try:
            import psutil

            # Get basic battery info from psutil
            battery = psutil.sensors_battery()

            if battery is None:
                # No battery present (desktop Mac)
                self._has_battery = False
                return None

            self._has_battery = True

            # Get advanced battery health info from ioreg (macOS-specific)
            health_info = self._get_battery_health()

            metrics = {
                "has_battery": True,
                "percent": battery.percent,
                "is_charging": battery.power_plugged,
                "time_remaining": battery.secsleft if battery.secsleft >= 0 else None,
                "power_source": "AC Adapter" if battery.power_plugged else "Battery",
                "health": health_info.get("health", None),
                "cycle_count": health_info.get("cycle_count", None),
                "temperature": health_info.get("temperature", None),
                "max_capacity": health_info.get("max_capacity", None),
                "design_capacity": health_info.get("design_capacity", None),
            }

            # Cache the results
            self._cached_metrics = metrics
            self._last_collection_time = current_time

            return metrics

        except ImportError:
            logger.debug("psutil not available for battery metrics collection")
        except Exception as e:
            logger.debug(f"Error collecting battery metrics: {e}")

        return None

    def _get_battery_health(self) -> Dict[str, Any]:
        """
        Get battery health information using ioreg (macOS-specific).

        Returns:
            Dictionary with keys:
            - health: float (health percentage, 0-100)
            - cycle_count: int
            - temperature: float (temperature in Celsius)
            - max_capacity: int (current maximum capacity in mAh)
            - design_capacity: int (original design capacity in mAh)
        """
        try:
            import subprocess
            import re

            # Use ioreg to get battery information
            result = subprocess.run(
                ['ioreg', '-rn', 'AppleSmartBattery'],
                capture_output=True,
                text=True,
                timeout=2
            )

            if result.returncode != 0:
                logger.debug("ioreg command failed")
                return {}

            output = result.stdout

            # Parse battery information
            health_info = {}

            # Cycle count
            match = re.search(r'"CycleCount"\s*=\s*(\d+)', output)
            if match:
                health_info["cycle_count"] = int(match.group(1))

            # Temperature (in decikelvin for newer Macs, convert to Celsius)
            # Temperature is in decikelvin (1/10 Kelvin), not centikelvin
            match = re.search(r'"Temperature"\s*=\s*(\d+)', output)
            if match:
                temp_decikelvin = int(match.group(1))
                temp_celsius = (temp_decikelvin / 10.0) - 273.15
                health_info["temperature"] = temp_celsius

            # IMPORTANT: AppleRawMaxCapacity is the actual capacity in mAh
            # MaxCapacity is a percentage value (0-100), NOT mAh!
            match = re.search(r'"AppleRawMaxCapacity"\s*=\s*(\d+)', output)
            if match:
                health_info["max_capacity"] = int(match.group(1))
            else:
                # Fallback: try to find MaxCapacity (but it might be percentage)
                match = re.search(r'"MaxCapacity"\s*=\s*(\d+)', output)
                if match:
                    max_cap_value = int(match.group(1))
                    # If value is > 100, it's likely in mAh. If <= 100, it's percentage.
                    if max_cap_value > 100:
                        health_info["max_capacity"] = max_cap_value

            # Design capacity (original, in mAh)
            match = re.search(r'"DesignCapacity"\s*=\s*(\d+)', output)
            if match:
                health_info["design_capacity"] = int(match.group(1))

            # Calculate health percentage
            if "max_capacity" in health_info and "design_capacity" in health_info:
                max_cap = health_info["max_capacity"]
                design_cap = health_info["design_capacity"]
                if design_cap > 0:
                    health_info["health"] = (max_cap / design_cap) * 100.0

            return health_info

        except subprocess.TimeoutExpired:
            logger.debug("ioreg command timed out")
        except Exception as e:
            logger.debug(f"Error getting battery health from ioreg: {e}")

        return {}

    def format_time_remaining(self, seconds: Optional[int]) -> str:
        """
        Format time remaining in human-readable format.

        Args:
            seconds: Time remaining in seconds

        Returns:
            Formatted string like "2h 34m" or "45m" or "Calculating..."
        """
        if seconds is None or seconds < 0:
            return _i18n.get_message("menubar.menu.battery_time_calculating")

        hours = seconds // 3600
        minutes = (seconds % 3600) // 60

        if hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"

    def get_health_status(self, health: Optional[float]) -> str:
        """
        Get health status indicator.

        Args:
            health: Health percentage (0-100)

        Returns:
            Status string: "Excellent", "Good", "Fair", "Poor", "Replace Soon"
        """
        if health is None:
            return _i18n.get_message("menubar.menu.battery_health_unknown")

        if health >= 90:
            return _i18n.get_message("menubar.menu.battery_health_excellent")
        elif health >= 80:
            return _i18n.get_message("menubar.menu.battery_health_good")
        elif health >= 60:
            return _i18n.get_message("menubar.menu.battery_health_fair")
        elif health >= 40:
            return _i18n.get_message("menubar.menu.battery_health_poor")
        else:
            return _i18n.get_message("menubar.menu.battery_health_replace")


class PortMonitor:
    """
    Port monitoring for detecting process occupation on common ports.

    Uses lsof to check which processes are listening on specified ports.
    Provides quick access to kill processes occupying ports.
    """

    def __init__(self, monitored_ports: Optional[List[int]] = None):
        """
        Initialize port monitor.

        Args:
            monitored_ports: List of ports to monitor (default: common dev ports)
        """
        self.monitored_ports = monitored_ports or [
            3000,   # Node.js/React dev server
            8080,   # Alternative HTTP
            80,     # HTTP
            443,    # HTTPS
            5432,   # PostgreSQL
            3306,   # MySQL
            6379,   # Redis
            27017,  # MongoDB
        ]

        # Cache port status (short duration as ports change frequently)
        self._cached_ports: Optional[Dict[int, Dict[str, Any]]] = None
        self._last_check_time: Optional[float] = None
        self._cache_duration: float = 2.0  # Cache for 2 seconds

    def check_port(self, port: int) -> Dict[str, Any]:
        """
        Check if a port is in use and get process information.

        Args:
            port: Port number to check

        Returns:
            Dictionary with keys:
            - in_use: bool (True if port is occupied)
            - pid: int (process ID, None if not in use)
            - process_name: str (process name, None if not in use)
            - error: str (error message if check failed, None otherwise)
        """
        try:
            import subprocess

            # Use lsof to check port (timeout 1 second)
            result = subprocess.run(
                ['lsof', '-i', f':{port}', '-P', '-n'],
                capture_output=True,
                text=True,
                timeout=1.0
            )

            # Parse lsof output
            # Format: COMMAND   PID   USER   FD   TYPE   DEVICE SIZE/OFF NODE NAME
            # Example: node    12345 user   21u  IPv4  0x1234      0t0  TCP *:3000 (LISTEN)

            if result.returncode != 0 or not result.stdout.strip():
                # Port not in use (lsof returns non-zero if no matches)
                return {
                    "in_use": False,
                    "pid": None,
                    "process_name": None,
                    "error": None,
                }

            # Parse first line of output (skip header)
            lines = result.stdout.strip().split('\n')
            if len(lines) < 2:
                return {
                    "in_use": False,
                    "pid": None,
                    "process_name": None,
                    "error": None,
                }

            # Parse process info from first data line
            parts = lines[1].split()
            if len(parts) >= 2:
                process_name = parts[0]
                try:
                    pid = int(parts[1])
                    return {
                        "in_use": True,
                        "pid": pid,
                        "process_name": process_name,
                        "error": None,
                    }
                except ValueError:
                    pass

            # Could not parse
            return {
                "in_use": True,
                "pid": None,
                "process_name": "Unknown",
                "error": None,
            }

        except subprocess.TimeoutExpired:
            logger.debug(f"lsof timeout checking port {port}")
            return {
                "in_use": False,
                "pid": None,
                "process_name": None,
                "error": "Timeout",
            }
        except PermissionError:
            logger.debug(f"Permission denied checking port {port}")
            return {
                "in_use": False,
                "pid": None,
                "process_name": None,
                "error": "Permission Denied",
            }
        except Exception as e:
            logger.debug(f"Error checking port {port}: {e}")
            return {
                "in_use": False,
                "pid": None,
                "process_name": None,
                "error": str(e),
            }

    def check_multiple_ports(self, ports: Optional[List[int]] = None) -> Dict[int, Dict[str, Any]]:
        """
        Check multiple ports concurrently.

        Args:
            ports: List of ports to check (default: self.monitored_ports)

        Returns:
            Dictionary mapping port number to port status dict
        """
        # Use cached results if still valid
        current_time = time.time()
        if (self._cached_ports is not None and
                self._last_check_time is not None and
                (current_time - self._last_check_time) < self._cache_duration):
            return self._cached_ports

        ports_to_check = ports or self.monitored_ports

        # Check ports concurrently using ThreadPoolExecutor
        try:
            from concurrent.futures import ThreadPoolExecutor, as_completed

            results = {}
            with ThreadPoolExecutor(max_workers=8) as executor:
                # Submit all port checks
                future_to_port = {
                    executor.submit(self.check_port, port): port
                    for port in ports_to_check
                }

                # Collect results as they complete
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        results[port] = future.result()
                    except Exception as e:
                        logger.debug(f"Error checking port {port}: {e}")
                        results[port] = {
                            "in_use": False,
                            "pid": None,
                            "process_name": None,
                            "error": str(e),
                        }

            # Cache results
            self._cached_ports = results
            self._last_check_time = current_time

            return results

        except ImportError:
            # Fallback: sequential checks if ThreadPoolExecutor not available
            results = {}
            for port in ports_to_check:
                results[port] = self.check_port(port)

            self._cached_ports = results
            self._last_check_time = current_time

            return results

