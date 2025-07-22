#!/bin/bash
# -*- coding: utf-8 -*-
# -*- encoding: utf-8 -*-
#
# Copyright (c) 2023 anqi.huang@outlook.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

# Global Scripts Auto-completion - SAFE VERSION
# This file provides minimal tab completion to avoid terminal crashes

# WARNING: Full completion system is temporarily disabled due to compatibility issues
# Basic completion functions are available but not auto-loaded

function gs_completion_help() {
    cat << EOF
Global Scripts Auto-completion Help

Tab completion is currently DISABLED due to terminal compatibility issues.

Available commands (type manually):
  - gs_health_check     System health check
  - gs_install_deps     Install dependencies
  - gs_list_plugins     List plugins
  - gs_plugin_info      Plugin information
  - gs_reload_plugin    Reload plugin
  - gs_plugin_search    Search plugins
  - gs_enable_plugin    Enable plugin
  - gs_disable_plugin   Disable plugin

To manually enable completion (at your own risk):
  source ${_GS_ROOT_PATH}/env/gs_completion_full.sh

EOF
}

# Only provide help function, no auto-completion setup
echo "[INFO] Tab completion disabled for stability. Use 'gs_completion_help' for available commands."