"""
Unit tests for menubar monitors module
"""

import pytest
from unittest.mock import MagicMock, patch


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
