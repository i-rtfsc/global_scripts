# Manual Tests

This directory contains manual test scripts for visual verification and demonstrations.

## Available Tests

### test_color_scheme.py

Tests the color helper utilities and Rich table formatting with various color schemes.

**What it tests:**
- Plugin type colorization
- Subplugin name colorization (consistent colors for same names)
- Usage text colorization (highlighting parameters)
- Status colorization
- Number colorization
- Rich Panel and Table components
- Complete table formatting with colors

**How to run:**
```bash
# From project root
uv run python tests/manual/test_color_scheme.py
```

**Expected output:**
Visual demonstration of:
1. Color helper tool tests (types, subplugins, usage, status, numbers)
2. Rich component beautification tests (Panels, section titles)
3. Colorful table tests (plugin list, command list with full colorization)

## Purpose

These tests are meant for:
- **Manual verification** during development
- **Visual inspection** of formatting and colors
- **Demonstration** of Rich table capabilities
- **Quick testing** after color scheme changes

They are NOT meant to be part of the automated test suite.
