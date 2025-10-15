"""
Installer 模块初始化
提供安装器的主要接口
"""

from pathlib import Path
from typing import Dict

# 导出主要功能
__all__ = [
    'run_installation',
    'generate_environment',
]


async def run_installation(source_dir: Path, auto_mode: bool = False) -> bool:
    """
    运行安装流程

    Args:
        source_dir: 源代码目录
        auto_mode: 是否自动模式

    Returns:
        bool: 安装是否成功
    """
    from .config_loader import load_config, save_config
    from .plugin_analyzer import analyze_plugins
    from .env_generator import generate_env_scripts
    from .completion_generator import generate_completions

    try:
        # 1. 加载配置
        language, show_examples = load_config(auto_mode=auto_mode)

        # 2. 分析插件
        plugins = await analyze_plugins(source_dir / "plugins")

        # 3. 生成环境脚本
        success = generate_env_scripts(
            source_dir=source_dir,
            plugins=plugins,
            language=language,
            show_examples=show_examples
        )

        if not success:
            return False

        # 4. 生成补全脚本
        generate_completions(plugins)

        # 5. 保存配置
        save_config(language=language, show_examples=show_examples)

        print("\n✅ 安装完成!")
        print(f"   - 语言: {language}")
        print(f"   - 插件数量: {len(plugins)}")

        return True

    except Exception as e:
        print(f"❌ 安装失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def generate_environment(
    source_dir: Path,
    plugins: Dict,
    language: str = 'zh',
    show_examples: bool = True
) -> bool:
    """
    仅生成环境脚本（不进行完整安装）

    Args:
        source_dir: 源代码目录
        plugins: 插件字典
        language: 语言
        show_examples: 是否显示示例

    Returns:
        bool: 是否成功
    """
    from .env_generator import generate_env_scripts

    return generate_env_scripts(
        source_dir=source_dir,
        plugins=plugins,
        language=language,
        show_examples=show_examples
    )
