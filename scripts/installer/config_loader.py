"""
配置加载器
从 gs.json 加载和保存配置
"""

import json
from pathlib import Path
from typing import Tuple, Optional


def load_config(auto_mode: bool = False) -> Tuple[str, bool]:
    """
    加载配置

    Args:
        auto_mode: 是否自动模式

    Returns:
        Tuple[str, bool]: (语言, 是否显示示例)
    """
    config_file = Path.cwd() / "config" / "gs.json"

    # 默认值
    language = 'zh'
    show_examples = False

    # 从文件加载
    if config_file.exists():
        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                language = config.get('language', 'zh')
                show_examples = config.get('show_examples', False)
        except Exception as e:
            print(f"Warning: Failed to load config: {e}")

    # 交互式询问（非自动模式）
    if not auto_mode:
        language = _ask_language(language)
        show_examples = _ask_show_examples(language)

    return language, show_examples


def save_config(language: str, show_examples: bool) -> bool:
    """
    保存配置

    Args:
        language: 语言
        show_examples: 是否显示示例

    Returns:
        bool: 是否保存成功
    """
    config_file = Path.cwd() / "config" / "gs.json"

    try:
        config = {}

        # 加载现有配置
        if config_file.exists():
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)

        # 更新配置
        config['language'] = language
        config['show_examples'] = show_examples

        # 保存
        config_file.parent.mkdir(parents=True, exist_ok=True)
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)

        return True

    except Exception as e:
        print(f"Error: Failed to save config: {e}")
        return False


def _ask_language(default: str = 'zh') -> str:
    """询问语言"""
    print("\n选择语言 / Select Language:")
    print("  1. 中文 (zh)")
    print("  2. English (en)")

    choice = input(f"请选择 [1-2] (默认: {'1' if default == 'zh' else '2'}): ").strip()

    if choice == '2':
        return 'en'
    elif choice == '1' or not choice:
        return 'zh'
    else:
        return default


def _ask_show_examples(language: str = 'zh') -> bool:
    """询问是否显示示例"""
    if language == 'zh':
        prompt = "是否显示示例插件？[y/N]: "
    else:
        prompt = "Show example plugins? [y/N]: "

    answer = input(prompt).strip().lower()
    return answer in ['y', 'yes']
