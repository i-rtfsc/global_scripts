#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Shell utilities - Shell 环境检测和处理工具
"""

import os
import subprocess


def detect_current_shell() -> str:
    """检测当前使用的 shell

    Returns:
        shell 名称: 'bash', 'zsh', 'fish' 或 'unknown'
    """
    # 方法1: 通过 ps 命令检查父进程
    try:
        result = subprocess.run(
            ['ps', '-p', str(os.getppid()), '-o', 'comm='],
            capture_output=True,
            text=True,
            timeout=1
        )
        if result.returncode == 0:
            shell_name = result.stdout.strip()
            # 移除可能的路径前缀
            shell_name = os.path.basename(shell_name)
            # 移除可能的 '-' 前缀（登录 shell）
            shell_name = shell_name.lstrip('-')
            if shell_name in ('bash', 'zsh', 'fish', 'sh'):
                return shell_name
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # 方法2: 检查 SHELL 环境变量（作为备选）
    shell_path = os.environ.get('SHELL', '')
    if shell_path:
        shell_name = os.path.basename(shell_path)
        if shell_name in ('bash', 'zsh', 'fish', 'sh'):
            return shell_name

    # 方法3: 读取 /etc/passwd（仅 Linux/Unix）
    try:
        import pwd
        user_shell = pwd.getpwuid(os.getuid()).pw_shell
        shell_name = os.path.basename(user_shell)
        if shell_name in ('bash', 'zsh', 'fish', 'sh'):
            return shell_name
    except (ImportError, KeyError):
        pass

    return 'unknown'
