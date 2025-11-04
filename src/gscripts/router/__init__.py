#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Router module for Global Scripts
Provides command routing and indexing functionality
"""

from .indexer import build_router_index, write_router_index

__all__ = ["build_router_index", "write_router_index"]
