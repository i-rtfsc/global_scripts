#!/usr/bin/env fish
# ============================================
# Global Scripts - Fish Shell Configuration
# Prompt Configuration
# ============================================
# Generated automatically - do not edit manually
# Generated at: 2025-10-17 09:46:57
# Configuration source: /Users/solo/code/github/global_scripts
# File: 01-gs-prompt.fish
# ============================================

if functions -q _tide_print_item
    # 自定义 context 项，显示 user@IP 而不是 user@hostname
    function _tide_item_context
        set -l ip (get_ip)
        _tide_print_item context (set_color $tide_context_color_default)" $USER"@"$ip"
    end
end

# ============================================
# 注意事项
# ============================================
#
# 1. Tide 主配置应用方法：
#    在 Fish shell 中执行：
#      source ~/.config/fish/apply-tide-config.fish
#      exec fish
#
# 2. 或者使用原始的 tide configure 命令：
#    tide configure --auto --style=Rainbow --prompt_colors='True color' \
#      --show_time='24-hour format' --rainbow_prompt_separators=Round \
#      --powerline_prompt_heads=Round --powerline_prompt_tails=Round \
#      --powerline_prompt_style='Two lines, character and frame' \
#      --prompt_connection=Disconnected --powerline_right_prompt_frame=Yes \
#      --prompt_connection_andor_frame_color=Light --prompt_spacing=Compact \
#      --icons='Many icons' --transient=No
#
#    然后应用右侧提示符配置：
#      set -e tide_right_prompt_items
#      set -U tide_right_prompt_items status cmd_duration python node go docker direnv context jobs time
#      exec fish
#
# 3. 配置说明：
#    - 左侧: os, pwd, git, newline, character
#    - 右侧: status, cmd_duration, python, node, go, docker, direnv, context, jobs, time
#    - context 显示为 user@IP（由上面的自定义函数实现）
#    - 命令执行时长阈值: 1秒
#
# 4. 配置存储位置：
#    - Tide 配置存储在: ~/.config/fish/fish_variables
#    - 使用 universal variables (-U) 保存，重启后依然生效
#    - 本文件只定义自定义扩展，不会覆盖你的 tide configure 设置
