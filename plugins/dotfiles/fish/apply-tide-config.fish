#!/usr/bin/env fish
# ============================================
# Tide 完整配置应用脚本
# ============================================
# 此脚本包含完整的 Tide 配置，基于你的原始配置命令：
tide configure --auto --style=Rainbow --prompt_colors='True color' \
  --show_time='24-hour format' --rainbow_prompt_separators=Round \
  --powerline_prompt_heads=Round --powerline_prompt_tails=Round \
  --powerline_prompt_style='Two lines, character and frame' \
  --prompt_connection=Disconnected --powerline_right_prompt_frame=Yes \
  --prompt_connection_andor_frame_color=Light --prompt_spacing=Compact \
  --icons='Many icons' --transient=No
#
# 使用方法：
#   1. 在 Fish shell 中执行：source apply-tide-config.fish
#   2. 重启 Fish: exec fish
#
# ============================================
