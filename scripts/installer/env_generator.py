"""
环境脚本生成器
使用模板引擎生成 env.sh 和 env.fish
"""

from pathlib import Path
from typing import Dict


def generate_env_scripts(
    source_dir: Path,
    plugins: Dict,
    language: str = 'zh',
    show_examples: bool = True
) -> bool:
    """
    生成环境脚本

    Args:
        source_dir: 源代码目录
        plugins: 插件字典
        language: 语言
        show_examples: 是否显示示例

    Returns:
        bool: 是否成功
    """
    try:
        # 使用 Phase 1 的模板引擎
        import sys
        sys.path.insert(0, str(source_dir / 'src'))

        from gscripts.core.template_engine import get_template_engine

        cache_dir = Path.home() / ".config" / "global-scripts" / "cache"
        cache_dir.mkdir(parents=True, exist_ok=True)

        # 生成 env.sh
        engine = get_template_engine()
        env_sh_content = engine.render_env_sh(
            source_dir=source_dir,
            cache_dir=cache_dir,
            plugins=plugins,
            language=language,
            show_examples=show_examples
        )

        # 写入文件
        env_sh_file = source_dir / "env.sh"
        with open(env_sh_file, 'w', encoding='utf-8') as f:
            f.write(env_sh_content)

        print(f"✅ 生成 env.sh: {env_sh_file}")

        return True

    except Exception as e:
        print(f"❌ 生成环境脚本失败: {e}")
        import traceback
        traceback.print_exc()
        return False
