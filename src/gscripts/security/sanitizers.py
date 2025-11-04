#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Global Scripts - 输入清理器
提供各种输入清理和消毒功能
"""
import re
import html
import shlex
from typing import Any, List
from urllib.parse import quote


from ..core.logger import get_logger

# Module-level logger
logger = get_logger(tag="SECURITY.SANITIZERS", name=__name__)


class InputSanitizer:
    """输入清理器类"""

    @staticmethod
    def sanitize_string(
        text: str, max_length: int = 1000, allow_multiline: bool = True
    ) -> str:
        """清理字符串输入"""
        if not isinstance(text, str):
            text = str(text)

        # 限制长度
        if len(text) > max_length:
            text = text[:max_length]

        # 清理控制字符
        text = "".join(char for char in text if ord(char) >= 32 or char in "\n\r\t")

        # 如果不允许多行，移除换行符
        if not allow_multiline:
            text = text.replace("\n", " ").replace("\r", " ")

        # 清理多余的空格
        text = " ".join(text.split())

        return text.strip()

    @staticmethod
    def sanitize_plugin_name(name: str) -> str:
        """清理插件名称"""
        if not isinstance(name, str):
            name = str(name)

        # 只保留字母、数字、下划线和连字符
        name = re.sub(r"[^a-zA-Z0-9_-]", "", name)

        # 确保以字母开头
        if name and not name[0].isalpha():
            name = "plugin_" + name

        # 限制长度
        if len(name) > 50:
            name = name[:50]

        return name.lower()

    @staticmethod
    def sanitize_command_name(name: str) -> str:
        """清理命令名称"""
        if not isinstance(name, str):
            name = str(name)

        # 只保留字母、数字、下划线和连字符
        name = re.sub(r"[^a-zA-Z0-9_-]", "", name)

        # 确保以字母开头
        if name and not name[0].isalpha():
            name = "cmd_" + name

        # 限制长度
        if len(name) > 100:
            name = name[:100]

        return name.lower()

    @staticmethod
    def sanitize_path(path: str, resolve: bool = True) -> str:
        """清理文件路径"""
        if not isinstance(path, str):
            path = str(path)

        # 移除危险字符
        dangerous_chars = ["..", "~", "$", "`", "|", "&", ";", "(", ")", "{", "}"]
        for char in dangerous_chars:
            path = path.replace(char, "")

        # 清理多余的斜杠
        path = re.sub(r"/+", "/", path)
        path = path.strip("/")

        if resolve:
            try:
                from pathlib import Path

                path = str(Path(path).resolve())
            except (OSError, ValueError):
                pass

        return path

    @staticmethod
    def sanitize_shell_command(command: str, escape: bool = True) -> str:
        """清理Shell命令"""
        if not isinstance(command, str):
            command = str(command)

        # 限制长度
        if len(command) > 2000:
            command = command[:2000]

        # 移除控制字符
        command = "".join(
            char for char in command if ord(char) >= 32 or char in "\n\r\t"
        )

        if escape:
            # 转义特殊字符
            try:
                command = shlex.quote(command)
            except ValueError:
                # 如果无法转义，移除特殊字符
                command = re.sub(r"[`$(){}|&;<>]", "", command)

        return command.strip()

    @staticmethod
    def sanitize_json_data(
        data: Any, max_depth: int = 10, max_items: int = 1000
    ) -> Any:
        """清理JSON数据"""

        def _sanitize_recursive(obj, current_depth=0):
            if current_depth > max_depth:
                return None

            if isinstance(obj, dict):
                sanitized = {}
                item_count = 0
                for key, value in obj.items():
                    if item_count >= max_items:
                        break

                    # 清理键名
                    clean_key = InputSanitizer.sanitize_string(str(key), max_length=100)
                    if clean_key:
                        sanitized[clean_key] = _sanitize_recursive(
                            value, current_depth + 1
                        )
                        item_count += 1

                return sanitized

            elif isinstance(obj, list):
                sanitized = []
                for i, item in enumerate(obj):
                    if i >= max_items:
                        break
                    sanitized.append(_sanitize_recursive(item, current_depth + 1))
                return sanitized

            elif isinstance(obj, str):
                return InputSanitizer.sanitize_string(obj)

            elif isinstance(obj, (int, float, bool)) or obj is None:
                return obj

            else:
                return InputSanitizer.sanitize_string(str(obj))

        return _sanitize_recursive(data)

    @staticmethod
    def sanitize_html(text: str) -> str:
        """清理HTML内容"""
        if not isinstance(text, str):
            text = str(text)

        # HTML转义
        text = html.escape(text)

        # 移除script和style标签
        text = re.sub(
            r"<script[^>]*>.*?</script>", "", text, flags=re.IGNORECASE | re.DOTALL
        )
        text = re.sub(
            r"<style[^>]*>.*?</style>", "", text, flags=re.IGNORECASE | re.DOTALL
        )

        # 移除所有HTML标签
        text = re.sub(r"<[^>]+>", "", text)

        return text.strip()

    @staticmethod
    def sanitize_url(url: str, allowed_schemes: List[str] = None) -> str:
        """清理URL"""
        if not isinstance(url, str):
            url = str(url)

        if allowed_schemes is None:
            allowed_schemes = ["http", "https", "ftp", "ftps"]

        # 基本清理
        url = url.strip()

        # 检查协议
        if "://" in url:
            scheme = url.split("://")[0].lower()
            if scheme not in allowed_schemes:
                return ""
        else:
            # 添加默认协议
            url = "https://" + url

        # URL编码特殊字符
        try:
            url = quote(url, safe=":/?#[]@!$&'()*+,;=")
        except Exception:
            return ""

        return url

    @staticmethod
    def sanitize_config_value(value: Any, value_type: str = "string") -> Any:
        """根据类型清理配置值"""
        if value_type == "string":
            return InputSanitizer.sanitize_string(str(value))

        elif value_type == "int":
            try:
                return int(value)
            except (ValueError, TypeError):
                return 0

        elif value_type == "float":
            try:
                return float(value)
            except (ValueError, TypeError):
                return 0.0

        elif value_type == "bool":
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.lower() in ["true", "1", "yes", "on", "enabled"]
            return bool(value)

        elif value_type == "list":
            if isinstance(value, list):
                return [
                    InputSanitizer.sanitize_string(str(item)) for item in value[:100]
                ]
            return [InputSanitizer.sanitize_string(str(value))]

        elif value_type == "dict":
            if isinstance(value, dict):
                return InputSanitizer.sanitize_json_data(value)
            return {}

        else:
            return InputSanitizer.sanitize_string(str(value))

    @staticmethod
    def sanitize_log_message(message: str) -> str:
        """清理日志消息"""
        if not isinstance(message, str):
            message = str(message)

        # 限制长度
        if len(message) > 5000:
            message = message[:5000] + "...[truncated]"

        # 清理控制字符，但保留换行
        message = "".join(
            char for char in message if ord(char) >= 32 or char in "\n\r\t"
        )

        # 移除敏感信息模式
        sensitive_patterns = [
            r"password[=:]\s*\S+",
            r"token[=:]\s*\S+",
            r"key[=:]\s*\S+",
            r"secret[=:]\s*\S+",
        ]

        for pattern in sensitive_patterns:
            message = re.sub(pattern, "[REDACTED]", message, flags=re.IGNORECASE)

        return message.strip()


# 便捷函数
def clean_string(text: str) -> str:
    """清理字符串"""
    return InputSanitizer.sanitize_string(text)


def clean_command(command: str) -> str:
    """清理命令"""
    return InputSanitizer.sanitize_shell_command(command)


def clean_path(path: str) -> str:
    """清理路径"""
    return InputSanitizer.sanitize_path(path)


def clean_plugin_name(name: str) -> str:
    """清理插件名称"""
    return InputSanitizer.sanitize_plugin_name(name)
