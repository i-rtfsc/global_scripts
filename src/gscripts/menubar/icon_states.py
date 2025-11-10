"""
Icon State Manager

Manages dynamic menu bar icon states with animations and visual feedback.
"""

import logging
import time
from enum import Enum
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class IconState(Enum):
    """Menu bar icon states"""
    IDLE = "idle"
    LOADING = "loading"
    SUCCESS = "success"
    FAILURE = "failure"
    HIGH_CPU = "high_cpu"


@dataclass
class IconConfig:
    """Icon configuration for different states"""
    idle: str = "GS"
    loading_frames: list = None
    success: str = "✓"
    failure: str = "✗"
    high_cpu: str = "⚠️"

    def __post_init__(self):
        if self.loading_frames is None:
            # Rotating loading animation frames
            self.loading_frames = ["◐", "◓", "◑", "◒"]


class IconStateManager:
    """
    Manages menu bar icon state with animations.

    Features:
    - State-based icon display (idle, loading, success, failure, high CPU)
    - Rotating loading animation
    - Flash notifications for success/failure
    - Priority-based state override (high CPU > loading > idle)
    """

    def __init__(self, config: Optional[IconConfig] = None):
        """
        Initialize icon state manager.

        Args:
            config: Icon configuration (uses defaults if None)
        """
        self.config = config or IconConfig()
        self._current_state = IconState.IDLE
        self._loading_frame = 0
        self._flash_state: Optional[IconState] = None
        self._flash_until: Optional[float] = None
        self._high_cpu_active = False

    @property
    def current_state(self) -> IconState:
        """Get current icon state (accounting for flash and high CPU override)"""
        # Priority: Flash > High CPU > Current state
        if self._flash_state and self._is_flashing():
            return self._flash_state
        if self._high_cpu_active:
            return IconState.HIGH_CPU
        return self._current_state

    def get_icon_text(self) -> str:
        """
        Get current icon text based on state.

        Returns:
            Icon text/emoji to display
        """
        state = self.current_state

        if state == IconState.IDLE:
            return self.config.idle
        elif state == IconState.LOADING:
            # Rotate through loading frames
            return self.config.loading_frames[self._loading_frame]
        elif state == IconState.SUCCESS:
            return self.config.success
        elif state == IconState.FAILURE:
            return self.config.failure
        elif state == IconState.HIGH_CPU:
            return self.config.high_cpu

        return self.config.idle

    def set_state(self, state: IconState) -> None:
        """
        Set icon state.

        Args:
            state: New icon state
        """
        if state != self._current_state:
            logger.debug(f"Icon state changed: {self._current_state.value} -> {state.value}")
            self._current_state = state

            # Reset loading frame when entering loading state
            if state == IconState.LOADING:
                self._loading_frame = 0

    def advance_loading_frame(self) -> bool:
        """
        Advance to next loading animation frame.

        Returns:
            True if advanced, False if not in loading state
        """
        if self._current_state != IconState.LOADING:
            return False

        self._loading_frame = (self._loading_frame + 1) % len(self.config.loading_frames)
        return True

    def flash(self, state: IconState, duration: float = 1.0) -> None:
        """
        Flash an icon state temporarily.

        Args:
            state: State to flash (typically SUCCESS or FAILURE)
            duration: Flash duration in seconds (default: 1.0)
        """
        self._flash_state = state
        self._flash_until = time.time() + duration
        logger.debug(f"Flashing {state.value} for {duration}s")

    def _is_flashing(self) -> bool:
        """Check if currently in flash period"""
        if self._flash_until is None:
            return False

        if time.time() >= self._flash_until:
            # Flash expired
            self._flash_state = None
            self._flash_until = None
            return False

        return True

    def set_high_cpu(self, active: bool) -> None:
        """
        Set high CPU warning state.

        Args:
            active: True to show high CPU warning, False to clear
        """
        if active != self._high_cpu_active:
            self._high_cpu_active = active
            logger.info(f"High CPU warning: {'active' if active else 'cleared'}")

    def is_high_cpu_active(self) -> bool:
        """Check if high CPU warning is active"""
        return self._high_cpu_active

    def reset(self) -> None:
        """Reset to idle state"""
        self._current_state = IconState.IDLE
        self._loading_frame = 0
        self._flash_state = None
        self._flash_until = None
        # Note: high_cpu_active is NOT reset (it's independent)
