"""
Unit tests for menubar monitors module
"""

import pytest
import time
from unittest.mock import MagicMock, patch
from collections import deque


class TestBaseMonitor:
    """Tests for BaseMonitor abstract class"""

    @pytest.mark.unit
    def test_base_monitor_get_display_text(self):
        """Test get_display_text calls collect and format"""
        from gscripts.menubar.monitors import BaseMonitor

        class TestMonitor(BaseMonitor):
            def collect(self):
                return 42.0

            def format(self, value):
                return f"{value}°C"

        monitor = TestMonitor()
        result = monitor.get_display_text()

        assert result == "42.0°C"

    @pytest.mark.unit
    def test_base_monitor_get_display_text_none(self):
        """Test get_display_text when collect returns None"""
        from gscripts.menubar.monitors import BaseMonitor

        class TestMonitor(BaseMonitor):
            def collect(self):
                return None

            def format(self, value):
                return f"{value}°C"

        monitor = TestMonitor()
        result = monitor.get_display_text()

        assert result == "N/A"

    @pytest.mark.unit
    def test_base_monitor_get_display_text_exception(self):
        """Test get_display_text handles exceptions"""
        from gscripts.menubar.monitors import BaseMonitor

        class TestMonitor(BaseMonitor):
            def collect(self):
                raise Exception("Test error")

            def format(self, value):
                return f"{value}°C"

        monitor = TestMonitor()
        result = monitor.get_display_text()

        assert result == "N/A"


class TestCPUTemperatureMonitor:
    """Tests for CPUTemperatureMonitor"""

    @pytest.mark.unit
    def test_collect_no_psutil(self):
        """Test collect when psutil not available"""
        from gscripts.menubar.monitors import CPUTemperatureMonitor

        monitor = CPUTemperatureMonitor()

        with patch("builtins.__import__", side_effect=ImportError("No psutil")):
            result = monitor.collect()

            assert result is None

    @pytest.mark.unit
    def test_collect_with_coretemp_sensor(self):
        """Test collect with coretemp sensor"""
        from gscripts.menubar.monitors import CPUTemperatureMonitor

        # Mock psutil sensor data
        mock_sensor = MagicMock()
        mock_sensor.current = 45.0

        mock_psutil = MagicMock()
        mock_psutil.sensors_temperatures.return_value = {"coretemp": [mock_sensor]}

        monitor = CPUTemperatureMonitor()

        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            with patch("gscripts.menubar.monitors.psutil", mock_psutil):
                result = monitor.collect()

                assert result == 45.0

    @pytest.mark.unit
    def test_collect_with_alternative_sensor(self):
        """Test collect with cpu_thermal sensor"""
        from gscripts.menubar.monitors import CPUTemperatureMonitor

        mock_sensor = MagicMock()
        mock_sensor.current = 52.3

        mock_psutil = MagicMock()
        mock_psutil.sensors_temperatures.return_value = {"cpu_thermal": [mock_sensor]}

        monitor = CPUTemperatureMonitor()

        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            with patch("gscripts.menubar.monitors.psutil", mock_psutil):
                result = monitor.collect()

                assert result == 52.3

    @pytest.mark.unit
    def test_collect_no_sensors(self):
        """Test collect when no sensors available"""
        from gscripts.menubar.monitors import CPUTemperatureMonitor

        mock_psutil = MagicMock()
        mock_psutil.sensors_temperatures.return_value = {}

        monitor = CPUTemperatureMonitor()

        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            with patch("gscripts.menubar.monitors.psutil", mock_psutil):
                result = monitor.collect()

                # Should return cached value (None initially)
                assert result is None

    @pytest.mark.unit
    def test_collect_caches_value(self):
        """Test collect caches last successful value"""
        from gscripts.menubar.monitors import CPUTemperatureMonitor

        mock_sensor = MagicMock()
        mock_sensor.current = 45.0

        mock_psutil = MagicMock()
        mock_psutil.sensors_temperatures.return_value = {"coretemp": [mock_sensor]}

        monitor = CPUTemperatureMonitor()

        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            with patch("gscripts.menubar.monitors.psutil", mock_psutil):
                result1 = monitor.collect()
                assert result1 == 45.0

                # Now make it return empty
                mock_psutil.sensors_temperatures.return_value = {}
                result2 = monitor.collect()

                # Should return cached value
                assert result2 == 45.0

    @pytest.mark.unit
    def test_format(self):
        """Test format temperature value"""
        from gscripts.menubar.monitors import CPUTemperatureMonitor

        monitor = CPUTemperatureMonitor()

        assert monitor.format(45.0) == "45°C"
        assert monitor.format(52.3) == "52°C"  # Should round down
        assert monitor.format(67.9) == "67°C"

    @pytest.mark.unit
    def test_format_unavailable(self):
        """Test format_unavailable"""
        from gscripts.menubar.monitors import CPUTemperatureMonitor

        monitor = CPUTemperatureMonitor()

        assert monitor.format_unavailable() == "N/A"


class TestMemoryMonitor:
    """Tests for MemoryMonitor"""

    @pytest.mark.unit
    def test_collect_no_psutil(self):
        """Test collect when psutil not available"""
        from gscripts.menubar.monitors import MemoryMonitor

        monitor = MemoryMonitor()

        with patch("builtins.__import__", side_effect=ImportError("No psutil")):
            result = monitor.collect()

            assert result is None

    @pytest.mark.unit
    def test_collect_success(self):
        """Test collect returns memory percentage"""
        from gscripts.menubar.monitors import MemoryMonitor

        mock_memory = MagicMock()
        mock_memory.percent = 62.5

        mock_psutil = MagicMock()
        mock_psutil.virtual_memory.return_value = mock_memory

        monitor = MemoryMonitor()

        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            with patch("gscripts.menubar.monitors.psutil", mock_psutil):
                result = monitor.collect()

                assert result == 62.5

    @pytest.mark.unit
    def test_collect_exception(self):
        """Test collect handles exceptions"""
        from gscripts.menubar.monitors import MemoryMonitor

        mock_psutil = MagicMock()
        mock_psutil.virtual_memory.side_effect = Exception("Test error")

        monitor = MemoryMonitor()

        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            with patch("gscripts.menubar.monitors.psutil", mock_psutil):
                result = monitor.collect()

                assert result is None

    @pytest.mark.unit
    def test_format(self):
        """Test format memory percentage"""
        from gscripts.menubar.monitors import MemoryMonitor

        monitor = MemoryMonitor()

        assert monitor.format(62.5) == "62%"
        assert monitor.format(75.9) == "75%"  # Should round down
        assert monitor.format(100.0) == "100%"

    @pytest.mark.unit
    def test_format_unavailable(self):
        """Test format_unavailable"""
        from gscripts.menubar.monitors import MemoryMonitor

        monitor = MemoryMonitor()

        assert monitor.format_unavailable() == "N/A"

    @pytest.mark.unit
    def test_get_display_text_integration(self):
        """Test get_display_text full flow"""
        from gscripts.menubar.monitors import MemoryMonitor

        mock_memory = MagicMock()
        mock_memory.percent = 45.2

        mock_psutil = MagicMock()
        mock_psutil.virtual_memory.return_value = mock_memory

        monitor = MemoryMonitor()

        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            with patch("gscripts.menubar.monitors.psutil", mock_psutil):
                result = monitor.get_display_text()

                assert result == "45%"


class TestCPUTemperatureTrendTracking:
    """Tests for CPU temperature trend tracking (Phase 5.1)"""

    @pytest.mark.unit
    def test_track_temperature_updates_history(self):
        """Test temperature tracking adds to history"""
        from gscripts.menubar.monitors import CPUTemperatureMonitor

        monitor = CPUTemperatureMonitor()
        monitor._track_temperature(50.0)
        monitor._track_temperature(52.0)

        assert len(monitor._temp_history) == 2
        assert monitor._temp_history[0][1] == 50.0
        assert monitor._temp_history[1][1] == 52.0

    @pytest.mark.unit
    def test_track_temperature_updates_peak(self):
        """Test temperature tracking updates peak"""
        from gscripts.menubar.monitors import CPUTemperatureMonitor

        monitor = CPUTemperatureMonitor()
        monitor._track_temperature(50.0)
        monitor._track_temperature(60.0)
        monitor._track_temperature(55.0)

        assert monitor._peak_temp == 60.0

    @pytest.mark.unit
    def test_calculate_trend_rising(self):
        """Test trend calculation for rising temperature"""
        from gscripts.menubar.monitors import CPUTemperatureMonitor

        monitor = CPUTemperatureMonitor()
        current_time = time.time()

        # Add temperature 30 seconds ago
        monitor._temp_history.append((current_time - 30.0, 50.0))
        # Add current temperature (3°C higher)
        monitor._temp_history.append((current_time, 53.0))

        trend = monitor._calculate_trend()
        assert trend == "↑"

    @pytest.mark.unit
    def test_calculate_trend_falling(self):
        """Test trend calculation for falling temperature"""
        from gscripts.menubar.monitors import CPUTemperatureMonitor

        monitor = CPUTemperatureMonitor()
        current_time = time.time()

        # Add temperature 30 seconds ago
        monitor._temp_history.append((current_time - 30.0, 60.0))
        # Add current temperature (3°C lower)
        monitor._temp_history.append((current_time, 57.0))

        trend = monitor._calculate_trend()
        assert trend == "↓"

    @pytest.mark.unit
    def test_calculate_trend_stable(self):
        """Test trend calculation for stable temperature"""
        from gscripts.menubar.monitors import CPUTemperatureMonitor

        monitor = CPUTemperatureMonitor()
        current_time = time.time()

        # Add temperature 30 seconds ago
        monitor._temp_history.append((current_time - 30.0, 50.0))
        # Add current temperature (1°C change, within threshold)
        monitor._temp_history.append((current_time, 51.0))

        trend = monitor._calculate_trend()
        assert trend == "→"

    @pytest.mark.unit
    def test_calculate_avg_temperature(self):
        """Test average temperature calculation"""
        from gscripts.menubar.monitors import CPUTemperatureMonitor

        monitor = CPUTemperatureMonitor()
        current_time = time.time()

        # Add multiple temperature readings
        monitor._temp_history.append((current_time - 10, 50.0))
        monitor._temp_history.append((current_time - 5, 52.0))
        monitor._temp_history.append((current_time, 54.0))

        avg = monitor._calculate_avg()
        assert avg == pytest.approx(52.0)

    @pytest.mark.unit
    def test_get_peak_temp(self):
        """Test get_peak_temp returns correct value"""
        from gscripts.menubar.monitors import CPUTemperatureMonitor

        monitor = CPUTemperatureMonitor()
        monitor._track_temperature(50.0)
        monitor._track_temperature(65.0)
        monitor._track_temperature(60.0)

        assert monitor.get_peak_temp() == 65.0


class TestCPUMetricsCollector:
    """Tests for CPUMetricsCollector (Phase 5.2)"""

    @pytest.mark.unit
    def test_collect_comprehensive_metrics(self):
        """Test collect returns all CPU metrics"""
        from gscripts.menubar.monitors import CPUMetricsCollector, CPUTemperatureMonitor

        mock_psutil = MagicMock()
        mock_psutil.cpu_percent.side_effect = [35.2, [45.1, 32.3, 28.5, 39.0]]

        temp_monitor = CPUTemperatureMonitor()
        temp_monitor._track_temperature(52.0)

        collector = CPUMetricsCollector(temp_monitor=temp_monitor)

        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            with patch("gscripts.menubar.monitors.psutil", mock_psutil):
                metrics = collector.collect()

                assert metrics["overall"] == 35.2
                assert metrics["per_core"] == [45.1, 32.3, 28.5, 39.0]
                assert metrics["temp_current"] == 52.0
                assert metrics["temp_trend"] in ["↑", "↓", "→"]
                assert "temp_avg" in metrics
                assert "temp_peak" in metrics

    @pytest.mark.unit
    def test_collect_uses_caching(self):
        """Test collect uses 1-second cache"""
        from gscripts.menubar.monitors import CPUMetricsCollector, CPUTemperatureMonitor

        mock_psutil = MagicMock()
        mock_psutil.cpu_percent.side_effect = [35.2, [45.1, 32.3]]

        temp_monitor = CPUTemperatureMonitor()
        collector = CPUMetricsCollector(temp_monitor=temp_monitor)

        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            with patch("gscripts.menubar.monitors.psutil", mock_psutil):
                # First call
                metrics1 = collector.collect()
                # Second call within 1 second (should use cache)
                metrics2 = collector.collect()

                # Should only call cpu_percent twice (once per collect call)
                assert mock_psutil.cpu_percent.call_count == 2
                assert metrics1 == metrics2


class TestMemoryMetricsCollector:
    """Tests for MemoryMetricsCollector (Phase 5.3)"""

    @pytest.mark.unit
    def test_collect_memory_breakdown(self):
        """Test collect returns comprehensive memory metrics"""
        from gscripts.menubar.monitors import MemoryMetricsCollector

        mock_mem = MagicMock()
        mock_mem.total = 16 * (1024 ** 3)  # 16 GB
        mock_mem.used = 12 * (1024 ** 3)   # 12 GB
        mock_mem.percent = 75.0
        mock_mem.active = 8 * (1024 ** 3)  # 8 GB
        mock_mem.wired = 2 * (1024 ** 3)   # 2 GB
        mock_mem.cached = 0.5 * (1024 ** 3)  # 0.5 GB
        mock_mem.compressed = 1.2 * (1024 ** 3)  # 1.2 GB

        mock_swap = MagicMock()
        mock_swap.used = 0

        mock_psutil = MagicMock()
        mock_psutil.virtual_memory.return_value = mock_mem
        mock_psutil.swap_memory.return_value = mock_swap

        collector = MemoryMetricsCollector()

        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            with patch("gscripts.menubar.monitors.psutil", mock_psutil):
                metrics = collector.collect()

                assert metrics["total"] == pytest.approx(16.0, rel=0.1)
                assert metrics["used"] == pytest.approx(12.0, rel=0.1)
                assert metrics["percent"] == 75.0
                assert metrics["app"] == pytest.approx(8.0, rel=0.1)
                assert metrics["wired"] == pytest.approx(2.0, rel=0.1)
                assert metrics["swap"] == 0
                assert metrics["pressure"] in ["🟢 Normal", "🟡 Moderate", "🔴 High"]

    @pytest.mark.unit
    def test_calculate_pressure_normal(self):
        """Test memory pressure calculation - normal"""
        from gscripts.menubar.monitors import MemoryMetricsCollector

        collector = MemoryMetricsCollector()
        assert "Normal" in collector._calculate_pressure(50.0)

    @pytest.mark.unit
    def test_calculate_pressure_moderate(self):
        """Test memory pressure calculation - moderate"""
        from gscripts.menubar.monitors import MemoryMetricsCollector

        collector = MemoryMetricsCollector()
        assert "Moderate" in collector._calculate_pressure(70.0)

    @pytest.mark.unit
    def test_calculate_pressure_high(self):
        """Test memory pressure calculation - high"""
        from gscripts.menubar.monitors import MemoryMetricsCollector

        collector = MemoryMetricsCollector()
        assert "High" in collector._calculate_pressure(85.0)

    @pytest.mark.unit
    def test_get_top_processes(self):
        """Test top processes collection (Phase 5.4)"""
        from gscripts.menubar.monitors import MemoryMetricsCollector

        # Mock process data
        mock_proc1 = MagicMock()
        mock_proc1.info = {
            "pid": 1234,
            "name": "Chrome",
            "memory_info": MagicMock(rss=2.1 * (1024 ** 3))
        }

        mock_proc2 = MagicMock()
        mock_proc2.info = {
            "pid": 1235,
            "name": "Code",
            "memory_info": MagicMock(rss=1.8 * (1024 ** 3))
        }

        mock_proc3 = MagicMock()
        mock_proc3.info = {
            "pid": 1236,
            "name": "Slack",
            "memory_info": MagicMock(rss=0.9 * (1024 ** 3))
        }

        mock_psutil = MagicMock()
        mock_psutil.process_iter.return_value = [mock_proc1, mock_proc2, mock_proc3]

        collector = MemoryMetricsCollector()

        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            with patch("gscripts.menubar.monitors.psutil", mock_psutil):
                processes = collector._get_top_processes()

                assert len(processes) == 3
                assert processes[0]["name"] == "Chrome"
                assert processes[0]["memory"] == pytest.approx(2.1, rel=0.1)
                assert processes[1]["name"] == "Code"
                assert processes[2]["name"] == "Slack"

    @pytest.mark.unit
    def test_collect_with_processes(self):
        """Test collect with top processes included"""
        from gscripts.menubar.monitors import MemoryMetricsCollector

        mock_mem = MagicMock()
        mock_mem.total = 16 * (1024 ** 3)
        mock_mem.used = 12 * (1024 ** 3)
        mock_mem.percent = 75.0
        mock_mem.active = 8 * (1024 ** 3)
        mock_mem.wired = 2 * (1024 ** 3)
        mock_mem.cached = 0.5 * (1024 ** 3)
        mock_mem.compressed = 1.2 * (1024 ** 3)

        mock_swap = MagicMock()
        mock_swap.used = 0

        mock_psutil = MagicMock()
        mock_psutil.virtual_memory.return_value = mock_mem
        mock_psutil.swap_memory.return_value = mock_swap
        mock_psutil.process_iter.return_value = []

        collector = MemoryMetricsCollector()

        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            with patch("gscripts.menubar.monitors.psutil", mock_psutil):
                metrics = collector.collect(include_processes=True)

                assert "top_processes" in metrics
                assert isinstance(metrics["top_processes"], list)


class TestCPUUsageMonitor:
    """Tests for CPUUsageMonitor with threshold warning"""

    @pytest.mark.unit
    def test_warning_activated(self):
        """Test high CPU warning activates above threshold"""
        from gscripts.menubar.monitors import CPUUsageMonitor

        mock_psutil = MagicMock()
        mock_psutil.cpu_percent.return_value = 85.0

        monitor = CPUUsageMonitor(threshold=80.0)

        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            with patch("gscripts.menubar.monitors.psutil", mock_psutil):
                usage = monitor.collect()

                assert usage == 85.0
                assert monitor.is_warning_active() is True

    @pytest.mark.unit
    def test_warning_deactivated_with_hysteresis(self):
        """Test high CPU warning deactivates with hysteresis"""
        from gscripts.menubar.monitors import CPUUsageMonitor

        mock_psutil = MagicMock()

        monitor = CPUUsageMonitor(threshold=80.0, hysteresis=10.0)

        with patch.dict("sys.modules", {"psutil": mock_psutil}):
            with patch("gscripts.menubar.monitors.psutil", mock_psutil):
                # Activate warning
                mock_psutil.cpu_percent.return_value = 85.0
                monitor.collect()
                assert monitor.is_warning_active() is True

                # Drop to 75% (still above threshold - hysteresis = 70%)
                mock_psutil.cpu_percent.return_value = 75.0
                monitor.collect()
                assert monitor.is_warning_active() is True

                # Drop to 65% (below threshold - hysteresis)
                mock_psutil.cpu_percent.return_value = 65.0
                monitor.collect()
                assert monitor.is_warning_active() is False

