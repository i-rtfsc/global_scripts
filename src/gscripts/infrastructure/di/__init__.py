"""
依赖注入模块
"""

from .container import DIContainer, ServiceDescriptor, get_container, reset_container

__all__ = [
    'DIContainer',
    'ServiceDescriptor',
    'get_container',
    'reset_container',
]
