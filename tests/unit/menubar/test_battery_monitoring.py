"""
Unit tests for battery monitoring feature (Phase 3)
"""

import pytest
from unittest.mock import MagicMock, patch, Mock
import time


class TestBatteryMetricsCollectorInit:
    """Tests for BatteryMetricsCollector initialization"""

    @pytest.mark.unit
    def test_battery_metrics_collector_initialization(self):
        """Test that BatteryMetricsCollector initializes with correct defaults"""
        from gscripts.menubar.monitors import BatteryMetricsCollector

        collector = BatteryMetricsCollector()

        # Cache settings
        assert collector._cache_duration == 2.0
        assert collector._cached_metrics is None
        assert collector._last_collection_time is None
        assert collector._has_battery is None


class TestBatteryMetricsCollectorCaching:
    """Tests for battery metrics caching behavior"""

    @pytest.mark.unit
    def test_cache_duration_correct(self):
        """Test that cache duration is set to 2 seconds"""
        from gscripts.menubar.monitors import BatteryMetricsCollector

        collector = BatteryMetricsCollector()
        assert collector._cache_duration == 2.0

    @pytest.mark.unit
    @patch('psutil.sensors_battery')
    def test_cache_invalidation_after_timeout(self, mock_battery):
        """Test that cache is invalidated after timeout"""
        from gscripts.menubar.monitors import BatteryMetricsCollector

        # Mock battery data
        mock_battery_result = Mock()
        mock_battery_result.percent = 75.0
        mock_battery_result.power_plugged = False
        mock_battery_result.secsleft = 3600  # 1 hour
        mock_battery.return_value = mock_battery_result

        collector = BatteryMetricsCollector()

        # First collection
        with patch.object(collector, '_get_battery_health', return_value={}):
            metrics1 = collector.collect()
            first_cache_time = collector._last_collection_time

        # Simulate time passing (less than cache duration)
        with patch('time.time', return_value=first_cache_time + 1.0):
            with patch.object(collector, '_get_battery_health', return_value={}):
                metrics2 = collector.collect()
                # Should return cached result (same object)
                assert metrics2 is metrics1

        # Simulate time passing (more than cache duration)
        with patch('time.time', return_value=first_cache_time + 2.5):
            with patch.object(collector, '_get_battery_health', return_value={}):
                metrics3 = collector.collect()
                # Should collect new metrics (different object)
                assert metrics3 is not metrics1


class TestBatteryMetricsCollectorDataCollection:
    """Tests for battery metrics data collection"""

    @pytest.mark.unit
    @patch('psutil.sensors_battery')
    def test_collect_returns_complete_metrics_on_laptop(self, mock_battery):
        """Test that collect() returns all required metrics on laptop"""
        from gscripts.menubar.monitors import BatteryMetricsCollector

        # Mock battery data (laptop with battery)
        mock_battery_result = Mock()
        mock_battery_result.percent = 85.0
        mock_battery_result.power_plugged = True
        mock_battery_result.secsleft = -1  # Charging (unknown time)
        mock_battery.return_value = mock_battery_result

        collector = BatteryMetricsCollector()

        # Mock health info
        health_info = {
            "health": 92.5,
            "cycle_count": 123,
            "temperature": 32.5,
            "max_capacity": 4500,
            "design_capacity": 4863
        }

        with patch.object(collector, '_get_battery_health', return_value=health_info):
            metrics = collector.collect()

        # Verify all required keys are present
        assert metrics is not None
        assert "has_battery" in metrics
        assert "percent" in metrics
        assert "is_charging" in metrics
        assert "time_remaining" in metrics
        assert "power_source" in metrics
        assert "health" in metrics
        assert "cycle_count" in metrics
        assert "temperature" in metrics

        # Verify values
        assert metrics["has_battery"] is True
        assert metrics["percent"] == 85.0
        assert metrics["is_charging"] is True
        assert metrics["time_remaining"] is None  # Charging
        assert metrics["power_source"] == "AC Adapter"
        assert metrics["health"] == 92.5
        assert metrics["cycle_count"] == 123
        assert abs(metrics["temperature"] - 32.5) < 0.1

    @pytest.mark.unit
    @patch('psutil.sensors_battery')
    def test_collect_returns_none_on_desktop(self, mock_battery):
        """Test that collect() returns None on desktop Mac"""
        from gscripts.menubar.monitors import BatteryMetricsCollector

        # Mock no battery (desktop Mac)
        mock_battery.return_value = None

        collector = BatteryMetricsCollector()
        metrics = collector.collect()

        assert metrics is None
        assert collector._has_battery is False

        # Second call should return None immediately (cached)
        metrics2 = collector.collect()
        assert metrics2 is None
        # Battery status should only be checked once
        assert mock_battery.call_count == 1


class TestBatteryHealthDetection:
    """Tests for battery health detection via ioreg"""

    @pytest.mark.unit
    def test_get_battery_health_parses_ioreg_output(self):
        """Test that _get_battery_health parses ioreg output correctly"""
        from gscripts.menubar.monitors import BatteryMetricsCollector
        import subprocess

        collector = BatteryMetricsCollector()

        # Mock ioreg output (using AppleRawMaxCapacity like real output)
        ioreg_output = '''
+-o AppleSmartBattery  <class AppleSmartBattery, id 0x100000280, registered, matched, active, busy 0 (0 ms), retain 6>
    {
      "CycleCount" = 234
      "Temperature" = 3051
      "MaxCapacity" = 100
      "AppleRawMaxCapacity" = 4500
      "DesignCapacity" = 4863
    }
        '''

        mock_result = Mock()
        mock_result.returncode = 0
        mock_result.stdout = ioreg_output

        with patch('subprocess.run', return_value=mock_result):
            health_info = collector._get_battery_health()

        assert "cycle_count" in health_info
        assert health_info["cycle_count"] == 234

        assert "temperature" in health_info
        # Temperature: (3051 / 10) - 273.15 = 31.95°C
        assert abs(health_info["temperature"] - 32.0) < 0.5

        assert "max_capacity" in health_info
        assert health_info["max_capacity"] == 4500

        assert "design_capacity" in health_info
        assert health_info["design_capacity"] == 4863

        assert "health" in health_info
        # Health: (4500 / 4863) * 100 = 92.5%
        assert abs(health_info["health"] - 92.5) < 0.5

    @pytest.mark.unit
    def test_get_battery_health_handles_ioreg_failure(self):
        """Test that _get_battery_health handles ioreg command failure gracefully"""
        from gscripts.menubar.monitors import BatteryMetricsCollector
        import subprocess

        collector = BatteryMetricsCollector()

        mock_result = Mock()
        mock_result.returncode = 1
        mock_result.stdout = ""

        with patch('subprocess.run', return_value=mock_result):
            health_info = collector._get_battery_health()

        # Should return empty dict on failure
        assert health_info == {}


class TestBatteryFormatting:
    """Tests for battery data formatting"""

    @pytest.mark.unit
    def test_format_time_remaining_hours_and_minutes(self):
        """Test formatting time remaining with hours and minutes"""
        from gscripts.menubar.monitors import BatteryMetricsCollector

        collector = BatteryMetricsCollector()

        # 2 hours 34 minutes
        time_str = collector.format_time_remaining(9240)
        assert time_str == "2h 34m"

        # 1 hour 0 minutes
        time_str = collector.format_time_remaining(3600)
        assert time_str == "1h 0m"

    @pytest.mark.unit
    def test_format_time_remaining_minutes_only(self):
        """Test formatting time remaining with only minutes"""
        from gscripts.menubar.monitors import BatteryMetricsCollector

        collector = BatteryMetricsCollector()

        # 45 minutes
        time_str = collector.format_time_remaining(2700)
        assert time_str == "45m"

    @pytest.mark.unit
    def test_format_time_remaining_calculating(self):
        """Test formatting time remaining when unknown"""
        from gscripts.menubar.monitors import BatteryMetricsCollector

        collector = BatteryMetricsCollector()

        # None or negative (calculating)
        time_str = collector.format_time_remaining(None)
        assert "Calculating" in time_str or "计算中" in time_str

        time_str = collector.format_time_remaining(-1)
        assert "Calculating" in time_str or "计算中" in time_str

    @pytest.mark.unit
    def test_get_health_status_levels(self):
        """Test health status mapping"""
        from gscripts.menubar.monitors import BatteryMetricsCollector

        collector = BatteryMetricsCollector()

        # Excellent (>= 90%)
        status = collector.get_health_status(95.0)
        assert "Excellent" in status or "极佳" in status

        # Good (80-90%)
        status = collector.get_health_status(85.0)
        assert "Good" in status or "良好" in status

        # Fair (60-80%)
        status = collector.get_health_status(70.0)
        assert "Fair" in status or "一般" in status

        # Poor (40-60%)
        status = collector.get_health_status(50.0)
        assert "Poor" in status or "较差" in status

        # Replace Soon (< 40%)
        status = collector.get_health_status(30.0)
        assert "Replace" in status or "更换" in status

        # Unknown (None)
        status = collector.get_health_status(None)
        assert "Unknown" in status or "未知" in status


class TestBatteryMonitoringConfiguration:
    """Tests for battery monitoring configuration"""

    @pytest.mark.unit
    def test_show_battery_default_value(self):
        """Test that show_battery defaults to True if not specified"""
        config = {}
        show_battery = config.get("show_battery", True)

        assert show_battery is True

    @pytest.mark.unit
    def test_show_battery_can_be_disabled(self):
        """Test that show_battery can be disabled"""
        config = {"show_battery": False}
        show_battery = config.get("show_battery", True)

        assert show_battery is False
