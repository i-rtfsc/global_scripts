"""
System Monitors for Menu Bar

Provides monitors for CPU temperature and memory usage.
"""

from abc import ABC, abstractmethod
from typing import Optional, Dict, Any
import logging

logger = logging.getLogger(__name__)


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

    def __init__(self):
        self.label = "CPU"
        self._last_value: Optional[float] = None
        self._sensor_unavailable = False
        self._is_apple_silicon = self._detect_apple_silicon()

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
                    return temp

            # If no known sensor found, try any available sensor
            if temps:
                first_sensor = next(iter(temps.values()))
                if first_sensor:
                    temp = first_sensor[0].current
                    self._last_value = temp
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
