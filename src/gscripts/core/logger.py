# -*- coding: utf-8 -*-
"""
Centralized logging for Global Scripts (gs_system).

- Writes all logs to GlobalConstants.gs_log_file
- Format: "%(asctime)s | %(levelname)s | %(tag)s | %(message)s"
- Date format: "%Y-%m-%d %H:%M:%S"
- Injects a 'tag' field into all records (default to logger name if not provided)
- Respects debug mode (GS_DEBUG): DEBUG level and optional console output
- Idempotent: avoids attaching duplicate handlers on repeated setup
"""
from __future__ import annotations

import logging
from logging import LoggerAdapter
from pathlib import Path
from typing import Optional

from .constants import GlobalConstants

_CONFIGURED = False
VERBOSE_LEVEL = 15  # Between DEBUG(10) and INFO(20)
if not hasattr(logging, "VERBOSE"):
    logging.addLevelName(VERBOSE_LEVEL, "VERBOSE")


def _verbose(self, message, *args, **kwargs):
    if self.isEnabledFor(VERBOSE_LEVEL):
        self._log(VERBOSE_LEVEL, message, args, **kwargs)


logging.Logger.verbose = _verbose  # type: ignore


class TagInjectingFilter(logging.Filter):
    """Ensure every LogRecord has a 'tag' attribute for formatting."""

    def filter(self, record: logging.LogRecord) -> bool:
        # If no explicit tag provided (via LoggerAdapter extra), fallback to logger name
        if not hasattr(record, "tag") or not getattr(record, "tag"):
            record.tag = record.name
        return True


def setup_logging(level: Optional[int] = None, console: bool = False) -> None:
    """
    Configure centralized logging for gs_system.

    Parameters:
        level: Optional explicit logging level (e.g. logging.DEBUG). If None,
               uses DEBUG when GlobalConstants.is_debug_mode() else INFO.
        console: If True, also log to console; in debug mode console is enabled automatically.
    """
    global _CONFIGURED

    root_logger = logging.getLogger()

    # Ensure logs directory exists
    log_file_path = Path(GlobalConstants.gs_log_file)
    log_file_path.parent.mkdir(parents=True, exist_ok=True)

    # Pre-truncate log file if it exceeds maximum size to avoid unbounded growth
    try:
        max_size = getattr(GlobalConstants, "MAX_LOG_FILE_SIZE", None)
        if max_size and log_file_path.exists():
            if log_file_path.stat().st_size > max_size:
                # Truncate by rewriting empty file (simple & atomic enough for this context)
                with open(log_file_path, "w", encoding="utf-8"):
                    pass
    except Exception:
        # Fail silently; logging must continue even if size check fails
        pass

    # Avoid duplicate configuration if a FileHandler for this file already exists
    for h in root_logger.handlers:
        try:
            if (
                isinstance(h, logging.FileHandler)
                and Path(getattr(h, "baseFilename", "")) == log_file_path
            ):
                _CONFIGURED = True
                return
        except Exception:
            # Be tolerant of handlers without baseFilename attribute
            continue

    if _CONFIGURED:
        return

    # Determine config-driven level if not explicitly provided
    if level is None:
        cfg_level = None
        try:
            import json

            cfg_path = GlobalConstants.get_main_config_path()
            if cfg_path.exists():
                with open(cfg_path, "r", encoding="utf-8") as f:
                    cfg_data = json.load(f)
                from .constants import GlobalConstants as _GC

                cfg_level = _GC.resolve_logging_level(cfg_data)
        except Exception:
            cfg_level = None
        level_candidate = (
            cfg_level
            if cfg_level is not None
            else (logging.DEBUG if GlobalConstants.is_debug_mode() else logging.INFO)
        )
    else:
        level_candidate = level

    effective_level = level_candidate

    root_logger.setLevel(effective_level)

    log_format = "%(asctime)s | %(levelname)s | %(tag)s | %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    formatter = logging.Formatter(fmt=log_format, datefmt=date_format)

    tag_filter = TagInjectingFilter()

    # File handler (always enabled)
    file_handler = logging.FileHandler(log_file_path, encoding="utf-8")
    file_handler.setLevel(effective_level)
    file_handler.setFormatter(formatter)
    file_handler.addFilter(tag_filter)
    root_logger.addHandler(file_handler)

    # Console handler (optional; enabled in debug mode or when console=True)
    enable_console = console or GlobalConstants.is_debug_mode()
    if enable_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(effective_level)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(tag_filter)
        root_logger.addHandler(console_handler)

    # NANO mode: level >= 1000 => disable logging completely
    if effective_level >= 1000:
        # Remove handlers to avoid formatting cost
        for h in list(root_logger.handlers):
            root_logger.removeHandler(h)
            try:
                h.close()
            except Exception:
                pass
        root_logger.disabled = True
        _CONFIGURED = True
        return

    _CONFIGURED = True


def get_logger(tag: Optional[str] = None, name: Optional[str] = None) -> LoggerAdapter:
    """
    Return a LoggerAdapter that injects a custom 'tag' field into records.

    Usage:
        logger = get_logger(tag="INSTALLER", name=__name__)
        logger.info("Setup complete")

    Notes:
        - If 'tag' is not provided, TagInjectingFilter will fallback to the logger's name.
        - If 'name' is None, this module name is used. Prefer passing name=__name__ in callers.
    """
    base_logger = logging.getLogger(name if name else __name__)
    extra = {"tag": tag} if tag else {}
    return LoggerAdapter(base_logger, extra)
