"""Global Scripts 6.0 Python plugin SDK (``gs_plugin``).

Exports the :class:`Plugin` class and the low-level framing helpers.
"""

from __future__ import annotations

from .framing import read_message, write_message
from .plugin import InvokeContext, Plugin

__all__ = ["Plugin", "InvokeContext", "read_message", "write_message"]

__version__ = "0.1.0"
