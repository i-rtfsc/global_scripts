"""
Unit tests for CPU temperature alert monitoring (Phase 6)

Tests temperature threshold detection, alert state transitions,
and alert message generation.
"""

import pytest
from unittest.mock import Mock, patch
from gscripts.menubar.monitors import CPUTemperatureMonitor


@pytest.mark.unit
class TestCPUTemperatureAlerts:
    """Test CPU temperature alert functionality"""

    def test_monitor_initialization_with_thresholds(self):
        """Test monitor initializes with custom thresholds"""
        monitor = CPUTemperatureMonitor(warning_threshold=65.0, critical_threshold=80.0)

        assert monitor.warning_threshold == 65.0
        assert monitor.critical_threshold == 80.0
        assert monitor._alert_state == "normal"

    def test_monitor_default_thresholds(self):
        """Test monitor uses default thresholds when not specified"""
        monitor = CPUTemperatureMonitor()

        assert monitor.warning_threshold == 60.0
        assert monitor.critical_threshold == 75.0

    def test_check_alert_state_normal(self):
        """Test normal temperature returns normal state"""
        monitor = CPUTemperatureMonitor(warning_threshold=60.0, critical_threshold=75.0)

        state = monitor.check_alert_state(40.0)
        assert state == "normal"

        state = monitor.check_alert_state(59.9)
        assert state == "normal"

    def test_check_alert_state_warning(self):
        """Test warning temperature returns warning state"""
        monitor = CPUTemperatureMonitor(warning_threshold=60.0, critical_threshold=75.0)

        state = monitor.check_alert_state(60.0)
        assert state == "warning"

        state = monitor.check_alert_state(65.0)
        assert state == "warning"

        state = monitor.check_alert_state(74.9)
        assert state == "warning"

    def test_check_alert_state_critical(self):
        """Test critical temperature returns critical state"""
        monitor = CPUTemperatureMonitor(warning_threshold=60.0, critical_threshold=75.0)

        state = monitor.check_alert_state(75.0)
        assert state == "critical"

        state = monitor.check_alert_state(80.0)
        assert state == "critical"

        state = monitor.check_alert_state(100.0)
        assert state == "critical"

    def test_update_alert_state_transition_to_warning(self):
        """Test alert state transition from normal to warning"""
        monitor = CPUTemperatureMonitor(warning_threshold=60.0, critical_threshold=75.0)

        # Initially normal
        assert monitor.get_alert_state() == "normal"

        # Update to warning temperature
        changed = monitor.update_alert_state(65.0)

        assert changed is True
        assert monitor.get_alert_state() == "warning"
        assert monitor.is_alert_active() is True

    def test_update_alert_state_transition_to_critical(self):
        """Test alert state transition from warning to critical"""
        monitor = CPUTemperatureMonitor(warning_threshold=60.0, critical_threshold=75.0)

        # Start at warning
        monitor.update_alert_state(65.0)
        assert monitor.get_alert_state() == "warning"

        # Update to critical temperature
        changed = monitor.update_alert_state(80.0)

        assert changed is True
        assert monitor.get_alert_state() == "critical"
        assert monitor.is_alert_active() is True

    def test_update_alert_state_transition_back_to_normal(self):
        """Test alert state transition from critical back to normal"""
        monitor = CPUTemperatureMonitor(warning_threshold=60.0, critical_threshold=75.0)

        # Start at critical
        monitor.update_alert_state(80.0)
        assert monitor.get_alert_state() == "critical"

        # Cool down to normal
        changed = monitor.update_alert_state(50.0)

        assert changed is True
        assert monitor.get_alert_state() == "normal"
        assert monitor.is_alert_active() is False

    def test_update_alert_state_no_change(self):
        """Test update_alert_state returns False when state doesn't change"""
        monitor = CPUTemperatureMonitor(warning_threshold=60.0, critical_threshold=75.0)

        # First update
        changed = monitor.update_alert_state(45.0)
        assert changed is False  # Still normal

        # Second update, still normal
        changed = monitor.update_alert_state(50.0)
        assert changed is False

    def test_is_alert_active(self):
        """Test is_alert_active returns correct status"""
        monitor = CPUTemperatureMonitor(warning_threshold=60.0, critical_threshold=75.0)

        # Normal - no alert
        monitor.update_alert_state(40.0)
        assert monitor.is_alert_active() is False

        # Warning - alert active
        monitor.update_alert_state(65.0)
        assert monitor.is_alert_active() is True

        # Critical - alert active
        monitor.update_alert_state(80.0)
        assert monitor.is_alert_active() is True

        # Back to normal - no alert
        monitor.update_alert_state(50.0)
        assert monitor.is_alert_active() is False

    def test_get_alert_message_normal(self):
        """Test alert message returns None for normal temperature"""
        monitor = CPUTemperatureMonitor(warning_threshold=60.0, critical_threshold=75.0)
        monitor._last_value = 40.0
        monitor.update_alert_state(40.0)

        message = monitor.get_alert_message()
        assert message is None

    def test_get_alert_message_warning(self):
        """Test alert message for warning temperature"""
        monitor = CPUTemperatureMonitor(warning_threshold=60.0, critical_threshold=75.0)
        monitor._last_value = 65.0
        monitor.update_alert_state(65.0)

        message = monitor.get_alert_message()
        assert message is not None
        assert "🟡" in message
        assert "Warning" in message
        assert "65.0°C" in message
        assert "60" in message  # threshold

    def test_get_alert_message_critical(self):
        """Test alert message for critical temperature"""
        monitor = CPUTemperatureMonitor(warning_threshold=60.0, critical_threshold=75.0)
        monitor._last_value = 80.0
        monitor.update_alert_state(80.0)

        message = monitor.get_alert_message()
        assert message is not None
        assert "🔴" in message
        assert "Critical" in message
        assert "80.0°C" in message
        assert "75" in message  # threshold

    def test_track_temperature_updates_alert_state(self):
        """Test _track_temperature automatically updates alert state"""
        monitor = CPUTemperatureMonitor(warning_threshold=60.0, critical_threshold=75.0)

        # Track normal temperature
        monitor._track_temperature(40.0)
        assert monitor.get_alert_state() == "normal"

        # Track warning temperature
        monitor._track_temperature(65.0)
        assert monitor.get_alert_state() == "warning"

        # Track critical temperature
        monitor._track_temperature(80.0)
        assert monitor.get_alert_state() == "critical"

    def test_collect_integrates_with_alert_tracking(self):
        """Test collect() method integrates with alert state tracking"""
        monitor = CPUTemperatureMonitor(warning_threshold=60.0, critical_threshold=75.0)

        # Mock Apple Silicon temperature reading
        with patch.object(monitor, '_get_apple_silicon_temp', return_value=70.0):
            temp = monitor.collect()

            assert temp == 70.0
            assert monitor.get_alert_state() == "warning"
            assert monitor.is_alert_active() is True

    def test_temperature_alert_boundary_conditions(self):
        """Test alert state at exact threshold boundaries"""
        monitor = CPUTemperatureMonitor(warning_threshold=60.0, critical_threshold=75.0)

        # Just below warning
        state = monitor.check_alert_state(59.99)
        assert state == "normal"

        # Exactly at warning
        state = monitor.check_alert_state(60.0)
        assert state == "warning"

        # Just below critical
        state = monitor.check_alert_state(74.99)
        assert state == "warning"

        # Exactly at critical
        state = monitor.check_alert_state(75.0)
        assert state == "critical"

    def test_custom_thresholds_work_correctly(self):
        """Test alert logic works with custom thresholds"""
        monitor = CPUTemperatureMonitor(warning_threshold=70.0, critical_threshold=85.0)

        # Below custom warning
        state = monitor.check_alert_state(65.0)
        assert state == "normal"

        # At custom warning
        state = monitor.check_alert_state(70.0)
        assert state == "warning"

        # Between custom thresholds
        state = monitor.check_alert_state(80.0)
        assert state == "warning"

        # At custom critical
        state = monitor.check_alert_state(85.0)
        assert state == "critical"
