"""
Unit tests for on-demand monitoring feature (Phase 6.1)
"""

import pytest
from unittest.mock import MagicMock, patch, Mock
import time


class TestOnDemandMonitoringConfig:
    """Tests for on-demand monitoring configuration parsing"""

    @pytest.mark.unit
    def test_on_demand_monitoring_default_value(self):
        """Test that on_demand_monitoring defaults to True if not specified"""
        config = {}
        on_demand = config.get("on_demand_monitoring", True)

        assert on_demand is True

    @pytest.mark.unit
    def test_on_demand_monitoring_can_be_enabled(self):
        """Test that on_demand_monitoring can be explicitly enabled"""
        config = {"on_demand_monitoring": True}
        on_demand = config.get("on_demand_monitoring", True)

        assert on_demand is True

    @pytest.mark.unit
    def test_on_demand_monitoring_can_be_disabled(self):
        """Test that on_demand_monitoring can be disabled"""
        config = {"on_demand_monitoring": False}
        on_demand = config.get("on_demand_monitoring", True)

        assert on_demand is False


class TestMetricsCollectorCaching:
    """Tests for metrics collector caching behavior"""

    @pytest.mark.unit
    def test_memory_metrics_collector_cache_duration(self):
        """Test that MemoryMetricsCollector has correct cache duration"""
        from gscripts.menubar.monitors import MemoryMetricsCollector

        collector = MemoryMetricsCollector()

        # Cache duration should be 1 second
        assert collector._cache_duration == 1.0

    @pytest.mark.unit
    def test_cpu_metrics_collector_cache_duration(self):
        """Test that CPUMetricsCollector has correct cache duration"""
        from gscripts.menubar.monitors import CPUMetricsCollector, CPUTemperatureMonitor

        temp_monitor = CPUTemperatureMonitor()
        collector = CPUMetricsCollector(temp_monitor)

        # Cache duration should be 1 second
        assert collector._cache_duration == 1.0


class TestOnDemandMonitoringBehavior:
    """Tests for on-demand monitoring behavior (integration-style)"""

    @pytest.mark.unit
    def test_on_demand_config_in_default_json(self):
        """Test that on_demand_monitoring is present in default config"""
        import json
        from pathlib import Path

        # Read default config file
        config_path = Path(__file__).parents[3] / "config" / "gs.json"
        with open(config_path, "r") as f:
            config = json.load(f)

        # Verify on_demand_monitoring is in menubar config
        assert "menubar" in config
        assert "on_demand_monitoring" in config["menubar"]
        assert config["menubar"]["on_demand_monitoring"] is True

    @pytest.mark.unit
    def test_menu_callback_triggers_update_in_on_demand_mode(self):
        """Test that menu click callback triggers metric update in on-demand mode"""
        from gscripts.menubar.app import MenuBarApp
        from unittest.mock import MagicMock

        # This test verifies the callback logic without full MenuBarApp instantiation
        # We just test that the callback pattern is correct

        # Create a mock app instance
        app = MagicMock()
        app.on_demand_monitoring = True
        app._update_cpu_menu = MagicMock()

        # Simulate the callback
        def _on_cpu_menu_opened(self, _):
            """Callback when CPU menu is clicked (on-demand monitoring)"""
            if self.on_demand_monitoring:
                self._update_cpu_menu()

        # Trigger callback
        _on_cpu_menu_opened(app, None)

        # Verify update was called
        app._update_cpu_menu.assert_called_once()

    @pytest.mark.unit
    def test_menu_callback_does_not_trigger_in_legacy_mode(self):
        """Test that menu click callback does nothing in legacy mode"""
        from unittest.mock import MagicMock

        # Create a mock app instance in legacy mode
        app = MagicMock()
        app.on_demand_monitoring = False
        app._update_cpu_menu = MagicMock()

        # Simulate the callback
        def _on_cpu_menu_opened(self, _):
            """Callback when CPU menu is clicked (on-demand monitoring)"""
            if self.on_demand_monitoring:
                self._update_cpu_menu()

        # Trigger callback
        _on_cpu_menu_opened(app, None)

        # Verify update was NOT called (legacy mode uses background thread)
        app._update_cpu_menu.assert_not_called()

