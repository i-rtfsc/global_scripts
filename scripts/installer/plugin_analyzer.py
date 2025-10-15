"""
插件分析器
分析插件目录并提取插件信息
"""

from pathlib import Path
from typing import Dict
import asyncio


async def analyze_plugins(plugins_root: Path) -> Dict:
    """
    分析插件目录

    Args:
        plugins_root: 插件根目录

    Returns:
        Dict: 插件信息字典
    """
    try:
        # 使用 Phase 2 的插件加载器
        import sys
        sys.path.insert(0, str(plugins_root.parent / 'src'))

        from gscripts.plugins.loader import RefactoredPluginLoader

        loader = RefactoredPluginLoader(plugins_root)
        plugins = await loader.load_all_plugins(include_examples=False)

        return plugins

    except Exception as e:
        print(f"Warning: Failed to load plugins with new loader: {e}")

        # 回退到简单的插件发现
        plugins = {}
        if plugins_root.exists():
            for plugin_dir in plugins_root.iterdir():
                if plugin_dir.is_dir():
                    plugins[plugin_dir.name] = {
                        'name': plugin_dir.name,
                        'enabled': True,
                        'type': 'config'
                    }

        return plugins
