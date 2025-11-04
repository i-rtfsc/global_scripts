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
    # 方法0: 检查 shell 特定的环境变量（最准确）
    # Fish shell 会设置 FISH_VERSION
    if os.environ.get("FISH_VERSION"):
        return "fish"
    # Zsh 会设置 ZSH_VERSION
    if os.environ.get("ZSH_VERSION"):
        return "zsh"
    # Bash 会设置 BASH_VERSION
    if os.environ.get("BASH_VERSION"):
        return "bash"

    # 方法1: 通过 ps 命令检查父进程链（遍历多级父进程）
    try:
        current_pid = os.getppid()
        # 最多遍历 5 层父进程
        for _ in range(5):
            result = subprocess.run(
                ["ps", "-p", str(current_pid), "-o", "comm=,ppid="],
                capture_output=True,
                text=True,
                timeout=1,
            )
            if result.returncode == 0:
                parts = result.stdout.strip().split()
                if len(parts) >= 1:
                    shell_name = parts[0]
                    # 移除可能的路径前缀
                    shell_name = os.path.basename(shell_name)
                    # 移除可能的 '-' 前缀（登录 shell）
                    shell_name = shell_name.lstrip("-")
                    if shell_name in ("bash", "zsh", "fish", "sh"):
                        return shell_name
                    # 获取父进程 PID 继续向上查找
                    if len(parts) >= 2:
                        try:
                            current_pid = int(parts[1])
                        except ValueError:
                            break
                    else:
                        break
                else:
                    break
            else:
                break
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # 方法2: 检查 SHELL 环境变量（作为备选）
    shell_path = os.environ.get("SHELL", "")
    if shell_path:
        shell_name = os.path.basename(shell_path)
        if shell_name in ("bash", "zsh", "fish", "sh"):
            return shell_name

    # 方法3: 读取 /etc/passwd（仅 Linux/Unix）
    try:
        import pwd

        user_shell = pwd.getpwuid(os.getuid()).pw_shell
        shell_name = os.path.basename(user_shell)
        if shell_name in ("bash", "zsh", "fish", "sh"):
            return shell_name
    except (ImportError, KeyError):
        pass

    return "unknown"
