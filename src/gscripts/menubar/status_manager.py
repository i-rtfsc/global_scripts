"""
Command Status Manager

Manages command execution status and formatting for display in the menu bar.
Supports icon, marquee scrolling, and sentence API for idle state.
"""

from dataclasses import dataclass, field
from typing import Optional
import time

from .icon import MENUBAR_ICON
from .marquee import MarqueeManager


@dataclass
class CommandStatus:
    """Represents the current command execution status"""

    command: str = ""  # e.g., "android.adb.devices"
    is_running: bool = False
    progress: Optional[int] = None  # 0-100 percentage
    current_stage: Optional[str] = None  # Current execution stage (e.g., "compiling", "packaging")
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    success: Optional[bool] = None
    error: Optional[str] = None
    output: str = ""  # Command output/result
    idle_sentence: str = ""  # Sentence for idle state (一言)

    # Marquee manager for scrolling text
    _marquee_manager: MarqueeManager = field(default_factory=lambda: MarqueeManager(max_length=50, scroll_speed=0.3))

    def get_elapsed_time(self) -> float:
        """Get elapsed time in seconds"""
        if self.start_time is None:
            return 0.0

        end = self.end_time if self.end_time is not None else time.time()
        return end - self.start_time

    def format_duration(self, seconds: float) -> str:
        """Format duration as human-readable string"""
        if seconds < 1:
            return f"{seconds:.1f}s"
        elif seconds < 60:
            return f"{int(seconds)}s"
        else:
            minutes = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{minutes}m{secs:02d}s"

    def format_status(self, use_marquee: bool = True) -> str:
        """
        Format status for menu bar display

        New format:
            - Idle: "⚡ 一言内容"
            - Running: "⚡ cmd + time + result"  (scrolling if too long)
            - Success: "⚡ cmd + time + result ✓"  (scrolling if too long)
            - Failure: "⚡ cmd + time + error ✗"  (scrolling if too long)

        Args:
            use_marquee: Whether to use marquee scrolling for long text

        Returns:
            Formatted status string
        """
        icon = MENUBAR_ICON

        # Idle state: show only icon (no sentence to avoid blocking other icons)
        if not self.is_running and self.command == "":
            return icon  # Just "GS"

        # Running or completed state
        elapsed = self.get_elapsed_time()
        duration_str = self.format_duration(elapsed)

        # Shorten command name (e.g., "android.adb.devices" → "android.adb")
        cmd_parts = self.command.split(".")
        short_cmd = ".".join(cmd_parts[:2]) if len(cmd_parts) > 1 else cmd_parts[0]

        # Build status text
        if self.is_running:
            # Running state
            if self.progress is not None:
                # With progress
                if self.current_stage:
                    # Show: icon + cmd + [stage] + progress + time
                    status_text = f"{short_cmd} [{self.current_stage}] {self.progress}% {duration_str}"
                elif self.output:
                    # Show: icon + cmd + progress + time + output
                    status_text = f"{short_cmd} {self.progress}% {duration_str} {self.output}"
                else:
                    # Show: icon + cmd + progress + time
                    status_text = f"{short_cmd} {self.progress}% {duration_str}"
            else:
                # Without progress
                if self.current_stage:
                    # Show: icon + cmd + [stage] + time
                    status_text = f"{short_cmd} [{self.current_stage}] {duration_str}"
                elif self.output:
                    # Show: icon + cmd + time + output
                    status_text = f"{short_cmd} {duration_str} {self.output}"
                else:
                    # Show: icon + cmd + time
                    status_text = f"{short_cmd} {duration_str}"

            full_text = f"{icon} {status_text}"

        else:
            # Completed state
            result_symbol = "✓" if self.success else "✗"

            if self.output:
                # Show: icon + cmd + time + output + symbol
                status_text = f"{short_cmd} {duration_str} {self.output} {result_symbol}"
            elif self.error and not self.success:
                # Show: icon + cmd + time + error + symbol
                error_msg = self.error[:50]  # Limit error length
                status_text = f"{short_cmd} {duration_str} {error_msg} {result_symbol}"
            else:
                # Show: icon + cmd + time + symbol
                status_text = f"{short_cmd} {duration_str} {result_symbol}"

            full_text = f"{icon} {status_text}"

        # Apply marquee if text is too long
        if use_marquee:
            return self._marquee_manager.get_display_text(full_text)
        else:
            return full_text[:20]  # Fallback truncate (约5个中文字符)

    def set_idle_sentence(self, sentence: str):
        """
        Set the sentence for idle state display

        Args:
            sentence: Sentence text (一言)
        """
        self.idle_sentence = sentence

    def set_output(self, output: str):
        """
        Set command output/result

        Args:
            output: Output text to display
        """
        self.output = output[:100]  # Limit output length

    def clear(self) -> None:
        """Reset to idle state (keeps idle_sentence)"""
        self.command = ""
        self.is_running = False
        self.progress = None
        self.current_stage = None
        self.start_time = None
        self.end_time = None
        self.success = None
        self.error = None
        self.output = ""
        # Note: idle_sentence is NOT cleared, so it persists

    def needs_marquee_update(self) -> bool:
        """Check if marquee needs update (for animation)"""
        return self._marquee_manager.needs_scroll()
