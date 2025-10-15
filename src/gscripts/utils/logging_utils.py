#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
日志工具模块
提供日志记录的辅助功能，包括敏感信息脱敏、上下文构建、性能优化等
"""

import re
import time
import hashlib
import uuid
import json
from contextvars import ContextVar
from typing import Any, Dict, Optional, Union, List, Callable
from pathlib import Path

# 全局上下文变量，用于在异步任务间传递关联ID
_correlation_id: ContextVar[Optional[str]] = ContextVar('correlation_id', default=None)

# 敏感字段名称列表
SENSITIVE_FIELDS = {
    'password', 'passwd', 'pwd', 'secret', 'token', 'key', 'api_key', 
    'apikey', 'access_token', 'refresh_token', 'private_key', 'privatekey',
    'authorization', 'auth', 'cookie', 'session', 'credential', 'credentials',
    'client_secret', 'client_id', 'api_secret', 'webhook_secret', 'signing_key',
    'encryption_key', 'decryption_key', 'salt', 'nonce', 'iv', 'passphrase'
}

# 敏感模式正则表达式
SENSITIVE_PATTERNS = [
    (re.compile(r'(password|passwd|pwd|token|key|secret|api[_-]?key|authorization|cookie|session)[=:]\s*["\']?([^"\'\s]+)', re.IGNORECASE), r'\1=***REDACTED***'),
    (re.compile(r'(Bearer|Basic|Token)\s+[\w\-\.=]+', re.IGNORECASE), r'\1 ***REDACTED***'),
    (re.compile(r'--password[=\s]+[^\s]+', re.IGNORECASE), '--password=***REDACTED***'),
    (re.compile(r'--token[=\s]+[^\s]+', re.IGNORECASE), '--token=***REDACTED***'),
    (re.compile(r'--api-key[=\s]+[^\s]+', re.IGNORECASE), '--api-key=***REDACTED***'),
    (re.compile(r'\b[A-Za-z0-9+/]{40,}\b'), lambda m: f'***KEY[{len(m.group())}]***' if len(m.group()) > 40 else m.group()),
]


def redact(obj: Any, max_depth: int = 5) -> Any:
    """
    递归脱敏对象中的敏感信息
    
    Args:
        obj: 要脱敏的对象
        max_depth: 最大递归深度
        
    Returns:
        脱敏后的对象
    """
    if max_depth <= 0:
        return '***MAX_DEPTH***'
    
    if isinstance(obj, str):
        return redact_string(obj)
    elif isinstance(obj, dict):
        return {k: redact_kv(k, v, max_depth - 1) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        return type(obj)(redact(item, max_depth - 1) for item in obj)
    elif isinstance(obj, (int, float, bool)) or obj is None:
        return obj
    else:
        # 对于其他类型，转换为字符串并脱敏
        return redact_string(str(obj))


def redact_kv(key: str, value: Any, max_depth: int = 5) -> Any:
    """
    根据键名决定是否脱敏值
    
    Args:
        key: 键名
        value: 值
        max_depth: 最大递归深度
        
    Returns:
        可能被脱敏的值
    """
    # 检查键名是否包含敏感字段
    key_lower = key.lower()
    for sensitive_field in SENSITIVE_FIELDS:
        if sensitive_field in key_lower:
            if isinstance(value, str):
                # 保留值的长度信息但隐藏内容
                return f'***REDACTED[{len(value)}]***'
            elif value is not None:
                return '***REDACTED***'
    
    # 递归处理非敏感字段
    return redact(value, max_depth)


def redact_string(text: str) -> str:
    """
    脱敏字符串中的敏感信息
    
    Args:
        text: 要脱敏的字符串
        
    Returns:
        脱敏后的字符串
    """
    result = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        if callable(replacement):
            result = pattern.sub(replacement, result)
        else:
            result = pattern.sub(replacement, result)
    return result


def redact_command(command: Union[str, List[str]]) -> str:
    """
    脱敏命令行字符串
    
    Args:
        command: 命令字符串或命令参数列表
        
    Returns:
        脱敏后的命令字符串
    """
    if isinstance(command, list):
        command = ' '.join(command)
    
    return redact_string(command)


def ctx(data: Dict[str, Any], max_items: int = 10) -> str:
    """
    构建紧凑的上下文字符串，自动脱敏
    
    Args:
        data: 上下文数据字典
        max_items: 最多包含的项目数
        
    Returns:
        格式化的上下文字符串
    """
    if not data:
        return ''
    
    # 脱敏并截断
    safe_data = {}
    for i, (k, v) in enumerate(data.items()):
        if i >= max_items:
            safe_data['...'] = f'and {len(data) - i} more items'
            break
        safe_data[k] = redact_kv(k, v, max_depth=2)
    
    # 构建紧凑格式
    items = []
    for k, v in safe_data.items():
        if isinstance(v, str) and len(v) > 100:
            v = v[:97] + '...'
        items.append(f'{k}={json.dumps(v) if not isinstance(v, str) else v}')
    
    return ', '.join(items)


def correlation_id() -> str:
    """
    获取或创建关联ID，用于跟踪请求在系统中的流转
    
    Returns:
        关联ID字符串
    """
    cid = _correlation_id.get()
    if cid is None:
        cid = str(uuid.uuid4())
        _correlation_id.set(cid)
    return cid


def set_correlation_id(cid: Optional[str]) -> None:
    """
    设置关联ID
    
    Args:
        cid: 关联ID，None则清除
    """
    _correlation_id.set(cid)


def duration(start_time: float) -> int:
    """
    计算从开始时间到现在的持续时间（毫秒）
    
    Args:
        start_time: 开始时间（time.time()或time.monotonic()的返回值）
        
    Returns:
        持续时间（毫秒）
    """
    return int((time.monotonic() - start_time) * 1000) if start_time < 1000000000 else int((time.time() - start_time) * 1000)


def trunc(value: Any, max_len: int = 1024) -> str:
    """
    截断长字符串或大对象，保留摘要信息
    
    Args:
        value: 要截断的值
        max_len: 最大长度
        
    Returns:
        截断后的字符串表示
    """
    if value is None:
        return 'None'
    
    # 转换为字符串
    if isinstance(value, bytes):
        text = f'<bytes[{len(value)}]>'
        if len(value) <= max_len:
            try:
                text = value.decode('utf-8', errors='replace')
            except:
                text = str(value)[:max_len]
    elif isinstance(value, (list, tuple)):
        if len(value) > 10:
            text = f'{type(value).__name__}[{len(value)} items, showing first 10]: {str(value[:10])}'
        else:
            text = str(value)
    elif isinstance(value, dict):
        if len(value) > 10:
            items = list(value.items())[:10]
            text = f'dict[{len(value)} items, showing first 10]: {dict(items)}'
        else:
            text = str(value)
    else:
        text = str(value)
    
    # 截断
    if len(text) > max_len:
        # 计算哈希以便识别相同的长内容
        hash_suffix = hashlib.md5(text.encode('utf-8', errors='ignore')).hexdigest()[:8]
        return f'{text[:max_len-20]}...[{len(text)}b,{hash_suffix}]'
    
    return text


def log_every(n: int) -> Callable[[int], bool]:
    """
    创建一个函数，用于在循环中限制日志频率
    
    Args:
        n: 每n次迭代记录一次
        
    Returns:
        判断函数，接收当前迭代次数，返回是否应该记录日志
        
    Example:
        should_log = log_every(100)
        for i, item in enumerate(items):
            if should_log(i):
                logger.debug(f"Processing item {i}/{len(items)}")
            process(item)
    """
    def should_log(iteration: int) -> bool:
        return iteration % n == 0
    return should_log


def format_size(size_bytes: int) -> str:
    """
    格式化文件大小为人类可读格式
    
    Args:
        size_bytes: 字节大小
        
    Returns:
        格式化的大小字符串
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size_bytes < 1024.0:
            return f'{size_bytes:.2f}{unit}'
        size_bytes /= 1024.0
    return f'{size_bytes:.2f}PB'


def safe_repr(obj: Any, max_len: int = 200) -> str:
    """
    安全地获取对象的字符串表示，处理异常情况
    
    Args:
        obj: 要表示的对象
        max_len: 最大长度
        
    Returns:
        对象的字符串表示
    """
    try:
        text = repr(obj)
    except Exception as e:
        try:
            text = str(obj)
        except Exception:
            text = f'<{type(obj).__name__} at {id(obj):#x}>'
    
    return trunc(text, max_len)


def log_context(**kwargs) -> Dict[str, Any]:
    """
    构建标准日志上下文
    
    Args:
        **kwargs: 自定义上下文字段
        
    Returns:
        包含标准字段的上下文字典
    """
    context = {
        'correlation_id': correlation_id(),
        'timestamp': time.time()
    }
    
    # 添加自定义字段，自动脱敏
    for key, value in kwargs.items():
        context[key] = redact_kv(key, value)
    
    return context


def format_exception(exc: Exception, include_type: bool = True) -> str:
    """
    格式化异常信息
    
    Args:
        exc: 异常对象
        include_type: 是否包含异常类型
        
    Returns:
        格式化的异常信息
    """
    if include_type:
        return f'{type(exc).__name__}: {str(exc)}'
    return str(exc)


def sanitize_path(path: Union[str, Path]) -> str:
    """
    清理文件路径，移除敏感用户信息
    
    Args:
        path: 文件路径
        
    Returns:
        清理后的路径字符串
    """
    path_str = str(path)
    
    # 替换用户主目录
    import os
    home = os.path.expanduser('~')
    if home in path_str:
        path_str = path_str.replace(home, '~')
    
    # 替换用户名（Unix/Linux/Mac）
    if '/Users/' in path_str:
        path_str = re.sub(r'/Users/[^/]+', '/Users/***', path_str)
    elif '/home/' in path_str:
        path_str = re.sub(r'/home/[^/]+', '/home/***', path_str)
    
    # Windows路径
    if 'C:\\Users\\' in path_str:
        path_str = re.sub(r'C:\\Users\\[^\\]+', 'C:\\Users\\***', path_str)
    
    return path_str


def measure_time():
    """
    创建一个计时器上下文，用于测量代码块执行时间
    
    Example:
        timer = measure_time()
        # ... do something ...
        elapsed_ms = timer()
        logger.debug(f"Operation took {elapsed_ms}ms")
    """
    start = time.monotonic()
    
    def get_elapsed() -> int:
        return int((time.monotonic() - start) * 1000)
    
    return get_elapsed


# 导出的公共接口
__all__ = [
    'redact',
    'redact_kv',
    'redact_string',
    'redact_command',
    'ctx',
    'correlation_id',
    'set_correlation_id',
    'duration',
    'trunc',
    'log_every',
    'format_size',
    'safe_repr',
    'log_context',
    'format_exception',
    'sanitize_path',
    'measure_time',
    'log_verbose',
]


def log_verbose(logger, msg: str, *args, **kwargs):
    """Helper to emit log at VERBOSE level if available."""
    level = getattr(logger, 'verbose', None)
    if callable(level):
        logger.verbose(msg, *args, **kwargs)
    else:
        # fallback to debug
        logger.debug(msg, *args, **kwargs)