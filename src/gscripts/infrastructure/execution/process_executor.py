"""
Process executor — compatibility re-export.

The canonical implementation lives in :mod:`gscripts.utils.process_executor`,
a low-level, dependency-free primitive (it only depends on models, the logger
and logging utils). This module previously held a byte-for-byte copy of that
class, which meant fixes had to be applied in two places. It now re-exports the
single implementation so the clean-architecture import path
(`gscripts.infrastructure.execution.process_executor`) keeps working while
there is only one source of truth.
"""

from ...utils.process_executor import (
    ProcessConfig,
    ProcessExecutor,
    get_process_executor,
)

__all__ = ["ProcessConfig", "ProcessExecutor", "get_process_executor"]
