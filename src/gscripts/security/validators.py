#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Global Scripts - 输入验证器
提供各种输入验证功能
"""
import re
import os
import shlex
from typing import Any, List, Optional, Union
from pathlib import Path



from ..core.logger import get_logger
from ..utils.logging_utils import (
    redact, redact_kv, redact_command, ctx, correlation_id, 
    duration, trunc, sanitize_path, format_size, safe_repr,
    log_context, format_exception, measure_time
)

# Module-level logger
logger = get_logger(tag="SECURITY.VALIDATORS", name=__name__)

class InputValidator:
    """输入验证器类"""
    
    # 常用正则表达式
    PATTERNS = {
        'plugin_name': re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]*$'),
        'command_name': re.compile(r'^[a-zA-Z][a-zA-Z0-9_-]*$'),
        'version': re.compile(r'^\d+\.\d+\.\d+(-[a-zA-Z0-9]+)?$'),
        'email': re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
        'url': re.compile(r'^https?://[^\s/$.?#].[^\s]*$'),
        'ip_address': re.compile(r'^(\d{1,3}\.){3}\d{1,3}$'),
        'port': re.compile(r'^\d{1,5}$'),
    }
    
    @staticmethod
    def validate_plugin_name(name: str) -> bool:
        """验证插件名称格式"""
        if not name or not isinstance(name, str):
            return False
        return bool(InputValidator.PATTERNS['plugin_name'].match(name))
    
    @staticmethod
    def validate_command_name(name: str) -> bool:
        """验证命令名称格式"""
        if not name or not isinstance(name, str):
            return False
        return bool(InputValidator.PATTERNS['command_name'].match(name))
    
    @staticmethod
    def validate_version(version: str) -> bool:
        """验证版本号格式"""
        if not version or not isinstance(version, str):
            return False
        return bool(InputValidator.PATTERNS['version'].match(version))
    
    @staticmethod
    def validate_path(path: str, must_exist: bool = False, must_be_file: bool = False, 
                     must_be_dir: bool = False) -> bool:
        """验证路径格式和存在性"""
        if not path or not isinstance(path, str):
            return False
        
        try:
            path_obj = Path(path).resolve()
            
            if must_exist and not path_obj.exists():
                return False
                
            if must_be_file and not path_obj.is_file():
                return False
                
            if must_be_dir and not path_obj.is_dir():
                return False
                
            return True
        except (OSError, ValueError):
            return False
    
    @staticmethod
    def validate_shell_command(command: str, allow_dangerous: bool = False) -> bool:
        """验证Shell命令安全性"""
        if not command or not isinstance(command, str):
            return False
        
        # 危险命令列表
        dangerous_commands = [
            'rm', 'rmdir', 'del', 'format', 'fdisk', 'mkfs',
            'dd', 'shutdown', 'reboot', 'halt', 'poweroff',
            'kill', 'killall', 'pkill', 'sudo', 'su'
        ]
        
        if not allow_dangerous:
            # 检查是否包含危险命令
            try:
                tokens = shlex.split(command)
                if tokens:
                    base_command = os.path.basename(tokens[0])
                    if base_command in dangerous_commands:
                        return False
            except ValueError:
                return False
        
        # 检查特殊字符
        dangerous_chars = ['$(', '`', '&&', '||', ';', '|', '>', '<', '&']
        if not allow_dangerous:
            for char in dangerous_chars:
                if char in command:
                    return False
        
        return True
    
    @staticmethod
    def validate_json_structure(data: Any, required_fields: List[str] = None) -> bool:
        """验证JSON结构"""
        if not isinstance(data, dict):
            return False
        
        if required_fields:
            for field in required_fields:
                if field not in data:
                    return False
        
        return True
    
    @staticmethod
    def validate_plugin_config(config: dict) -> tuple[bool, List[str]]:
        """验证插件配置格式"""
        errors = []
        
        required_fields = ['name', 'version', 'type']
        for field in required_fields:
            if field not in config:
                errors.append(f"缺少必需字段: {field}")
        
        # 验证插件名称
        if 'name' in config:
            if not InputValidator.validate_plugin_name(config['name']):
                errors.append("插件名称格式无效")
        
        # 验证版本号
        if 'version' in config:
            if not InputValidator.validate_version(config['version']):
                errors.append("版本号格式无效")
        
        # 验证插件类型
        if 'type' in config:
            valid_types = ['python', 'config', 'script', 'hybrid']
            if config['type'] not in valid_types:
                errors.append(f"插件类型无效，支持: {', '.join(valid_types)}")
        
        # 验证优先级
        if 'priority' in config:
            try:
                priority = int(config['priority'])
                if priority < 0 or priority > 100:
                    errors.append("优先级必须在0-100之间")
            except (ValueError, TypeError):
                errors.append("优先级必须为数字")
        
        return len(errors) == 0, errors
    
    @staticmethod
    def validate_command_args(args: List[str], expected_count: Optional[int] = None,
                             min_count: Optional[int] = None, max_count: Optional[int] = None) -> bool:
        """验证命令参数数量"""
        if not isinstance(args, list):
            return False
        
        arg_count = len(args)
        
        if expected_count is not None:
            return arg_count == expected_count
        
        if min_count is not None and arg_count < min_count:
            return False
            
        if max_count is not None and arg_count > max_count:
            return False
        
        return True
    
    @staticmethod
    def validate_network_address(address: str) -> bool:
        """验证网络地址（IP:PORT格式）"""
        if not address or not isinstance(address, str):
            return False
        
        if ':' in address:
            ip, port = address.split(':', 1)
            return (InputValidator.PATTERNS['ip_address'].match(ip) and 
                   InputValidator.PATTERNS['port'].match(port) and
                   1 <= int(port) <= 65535)
        else:
            return bool(InputValidator.PATTERNS['ip_address'].match(address))


# 便捷函数
def is_valid_plugin_name(name: str) -> bool:
    """检查是否为有效的插件名称"""
    return InputValidator.validate_plugin_name(name)


def is_valid_command_name(name: str) -> bool:
    """检查是否为有效的命令名称"""
    return InputValidator.validate_command_name(name)


def is_safe_shell_command(command: str) -> bool:
    """检查Shell命令是否安全"""
    return InputValidator.validate_shell_command(command, allow_dangerous=False)


def validate_config(config: dict) -> tuple[bool, List[str]]:
    """验证配置文件格式"""
    return InputValidator.validate_plugin_config(config)
