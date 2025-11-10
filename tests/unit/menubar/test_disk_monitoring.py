"""
Unit tests for disk space monitoring feature (Phase 6.2)
"""

import pytest
from unittest.mock import MagicMock, patch, Mock
import time


class TestDiskMetricsCollectorInit:
    """Tests for DiskMetricsCollector initialization"""

    @pytest.mark.unit
    def test_disk_metrics_collector_initialization(self):
        """Test that DiskMetricsCollector initializes with correct defaults"""
        from gscripts.menubar.monitors import DiskMetricsCollector

        collector = DiskMetricsCollector()

        # Cache settings
        assert collector._cache_duration == 1.0
        assert collector._cached_metrics is None
        assert collector._last_collection_time is None

        # I/O tracking
        assert collector._last_io_counters is None
        assert collector._last_io_time is None


class TestDiskMetricsCollectorCaching:
    """Tests for disk metrics caching behavior"""

    @pytest.mark.unit
    def test_cache_duration_correct(self):
        """Test that cache duration is set to 1 second"""
        from gscripts.menubar.monitors import DiskMetricsCollector

        collector = DiskMetricsCollector()
        assert collector._cache_duration == 1.0

    @pytest.mark.unit
    @patch('psutil.disk_usage')
    @patch('psutil.disk_io_counters')
    def test_cache_invalidation_after_timeout(self, mock_io, mock_usage):
        """Test that cache is invalidated after timeout"""
        from gscripts.menubar.monitors import DiskMetricsCollector

        # Mock disk_usage
        mock_usage_result = Mock()
        mock_usage_result.total = 512 * (1024 ** 3)  # 512 GB
        mock_usage_result.used = 256 * (1024 ** 3)   # 256 GB
        mock_usage_result.free = 256 * (1024 ** 3)   # 256 GB
        mock_usage_result.percent = 50.0
        mock_usage.return_value = mock_usage_result

        # Mock disk_io_counters
        mock_io_result = Mock()
        mock_io_result.read_bytes = 1024 * 1024 * 100  # 100 MB
        mock_io_result.write_bytes = 1024 * 1024 * 50  # 50 MB
        mock_io.return_value = mock_io_result

        collector = DiskMetricsCollector()

        # First collection
        metrics1 = collector.collect()
        first_cache_time = collector._last_collection_time

        # Simulate time passing (less than cache duration)
        with patch('time.time', return_value=first_cache_time + 0.5):
            metrics2 = collector.collect()
            # Should return cached result (same object)
            assert metrics2 is metrics1

        # Simulate time passing (more than cache duration)
        with patch('time.time', return_value=first_cache_time + 1.5):
            metrics3 = collector.collect()
            # Should collect new metrics (different object)
            assert metrics3 is not metrics1


class TestDiskMetricsCollectorDataCollection:
    """Tests for disk metrics data collection"""

    @pytest.mark.unit
    @patch('psutil.disk_usage')
    @patch('psutil.disk_io_counters')
    def test_collect_returns_complete_metrics(self, mock_io, mock_usage):
        """Test that collect() returns all required metrics"""
        from gscripts.menubar.monitors import DiskMetricsCollector

        # Mock disk_usage
        mock_usage_result = Mock()
        mock_usage_result.total = 512 * (1024 ** 3)  # 512 GB
        mock_usage_result.used = 234 * (1024 ** 3)   # 234 GB
        mock_usage_result.free = 278 * (1024 ** 3)   # 278 GB
        mock_usage_result.percent = 45.7
        mock_usage.return_value = mock_usage_result

        # Mock disk_io_counters
        mock_io_result = Mock()
        mock_io_result.read_bytes = 1024 * 1024 * 100
        mock_io_result.write_bytes = 1024 * 1024 * 50
        mock_io.return_value = mock_io_result

        collector = DiskMetricsCollector()
        metrics = collector.collect()

        # Verify all required keys are present
        assert "total" in metrics
        assert "used" in metrics
        assert "free" in metrics
        assert "percent" in metrics
        assert "io_read_rate" in metrics
        assert "io_write_rate" in metrics
        assert "pressure" in metrics

        # Verify values are approximately correct (in GB)
        assert abs(metrics["total"] - 512) < 1
        assert abs(metrics["used"] - 234) < 1
        assert abs(metrics["free"] - 278) < 1
        assert abs(metrics["percent"] - 45.7) < 0.1

    @pytest.mark.unit
    @patch('psutil.disk_usage')
    @patch('psutil.disk_io_counters')
    def test_io_rate_calculation(self, mock_io, mock_usage):
        """Test that I/O rates are calculated correctly"""
        from gscripts.menubar.monitors import DiskMetricsCollector

        # Mock disk_usage
        mock_usage_result = Mock()
        mock_usage_result.total = 512 * (1024 ** 3)
        mock_usage_result.used = 256 * (1024 ** 3)
        mock_usage_result.free = 256 * (1024 ** 3)
        mock_usage_result.percent = 50.0
        mock_usage.return_value = mock_usage_result

        # Mock first I/O counters (time=0)
        mock_io_result1 = Mock()
        mock_io_result1.read_bytes = 1024 * 1024 * 100  # 100 MB
        mock_io_result1.write_bytes = 1024 * 1024 * 50  # 50 MB

        # Mock second I/O counters (time=1s, +10MB read, +5MB write)
        mock_io_result2 = Mock()
        mock_io_result2.read_bytes = 1024 * 1024 * 110  # 110 MB
        mock_io_result2.write_bytes = 1024 * 1024 * 55  # 55 MB

        mock_io.side_effect = [mock_io_result1, mock_io_result2]

        collector = DiskMetricsCollector()

        # First collection (no rates available)
        with patch('time.time', return_value=1000.0):
            metrics1 = collector.collect()
            assert metrics1["io_read_rate"] == 0.0
            assert metrics1["io_write_rate"] == 0.0

        # Second collection (1 second later)
        with patch('time.time', return_value=1001.0):
            metrics2 = collector.collect()
            # Should calculate rates: 10 MB/s read, 5 MB/s write
            assert abs(metrics2["io_read_rate"] - 10.0) < 0.1
            assert abs(metrics2["io_write_rate"] - 5.0) < 0.1


class TestDiskPressureCalculation:
    """Tests for disk pressure calculation"""

    @pytest.mark.unit
    @patch('psutil.disk_usage')
    @patch('psutil.disk_io_counters')
    def test_pressure_normal_below_80(self, mock_io, mock_usage):
        """Test that pressure is Normal when below 80%"""
        from gscripts.menubar.monitors import DiskMetricsCollector

        # Mock 50% disk usage (normal)
        mock_usage_result = Mock()
        mock_usage_result.total = 512 * (1024 ** 3)
        mock_usage_result.used = 256 * (1024 ** 3)
        mock_usage_result.free = 256 * (1024 ** 3)
        mock_usage_result.percent = 50.0
        mock_usage.return_value = mock_usage_result

        mock_io_result = Mock()
        mock_io_result.read_bytes = 0
        mock_io_result.write_bytes = 0
        mock_io.return_value = mock_io_result

        collector = DiskMetricsCollector()
        metrics = collector.collect()

        assert "🟢" in metrics["pressure"]  # Normal indicator

    @pytest.mark.unit
    @patch('psutil.disk_usage')
    @patch('psutil.disk_io_counters')
    def test_pressure_moderate_80_to_90(self, mock_io, mock_usage):
        """Test that pressure is Moderate when 80-90%"""
        from gscripts.menubar.monitors import DiskMetricsCollector

        # Mock 85% disk usage (moderate)
        mock_usage_result = Mock()
        mock_usage_result.total = 512 * (1024 ** 3)
        mock_usage_result.used = 435 * (1024 ** 3)
        mock_usage_result.free = 77 * (1024 ** 3)
        mock_usage_result.percent = 85.0
        mock_usage.return_value = mock_usage_result

        mock_io_result = Mock()
        mock_io_result.read_bytes = 0
        mock_io_result.write_bytes = 0
        mock_io.return_value = mock_io_result

        collector = DiskMetricsCollector()
        metrics = collector.collect()

        assert "🟡" in metrics["pressure"]  # Moderate indicator

    @pytest.mark.unit
    @patch('psutil.disk_usage')
    @patch('psutil.disk_io_counters')
    def test_pressure_high_above_90(self, mock_io, mock_usage):
        """Test that pressure is High when above 90%"""
        from gscripts.menubar.monitors import DiskMetricsCollector

        # Mock 95% disk usage (high)
        mock_usage_result = Mock()
        mock_usage_result.total = 512 * (1024 ** 3)
        mock_usage_result.used = 486 * (1024 ** 3)
        mock_usage_result.free = 26 * (1024 ** 3)
        mock_usage_result.percent = 95.0
        mock_usage.return_value = mock_usage_result

        mock_io_result = Mock()
        mock_io_result.read_bytes = 0
        mock_io_result.write_bytes = 0
        mock_io.return_value = mock_io_result

        collector = DiskMetricsCollector()
        metrics = collector.collect()

        assert "🔴" in metrics["pressure"]  # High indicator


class TestDiskMonitoringConfiguration:
    """Tests for disk monitoring configuration"""

    @pytest.mark.unit
    def test_show_disk_default_value(self):
        """Test that show_disk defaults to True if not specified"""
        config = {}
        show_disk = config.get("show_disk", True)

        assert show_disk is True

    @pytest.mark.unit
    def test_show_disk_can_be_disabled(self):
        """Test that show_disk can be disabled"""
        config = {"show_disk": False}
        show_disk = config.get("show_disk", True)

        assert show_disk is False
