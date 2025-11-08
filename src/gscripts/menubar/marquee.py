"""
Marquee Effect for Menu Bar

Implements scrolling text effect when content is too long for menu bar.
"""

import time
from typing import Optional


class Marquee:
    """
    跑马灯效果

    当文本过长时，实现滚动显示效果
    """

    def __init__(self, text: str, max_length: int = 30, scroll_speed: float = 0.3):
        """
        初始化跑马灯

        Args:
            text: 要显示的完整文本
            max_length: 菜单栏最大显示长度（字符数，考虑中文占2个宽度）
            scroll_speed: 滚动速度（秒），每次移动一个字符的间隔
        """
        self.text = text
        self.max_length = max_length
        self.scroll_speed = scroll_speed
        self._position = 0
        self._last_update = time.time()

        # 计算实际显示宽度（中文算2个宽度，英文/数字/符号算1个）
        self._display_width = self._calculate_display_width(text)
        self._enabled = self._display_width > max_length

    def _calculate_display_width(self, text: str) -> int:
        """
        计算文本的显示宽度
        中文字符占2个宽度，ASCII字符占1个宽度

        Args:
            text: 文本内容

        Returns:
            显示宽度
        """
        width = 0
        for char in text:
            # 判断是否为中文字符（CJK统一表意文字）
            if '\u4e00' <= char <= '\u9fff' or '\u3000' <= char <= '\u303f':
                width += 2  # 中文字符占2个宽度
            else:
                width += 1  # 英文/数字/符号占1个宽度
        return width

    @property
    def needs_scroll(self) -> bool:
        """是否需要滚动"""
        return self._enabled

    def get_display_text(self) -> str:
        """
        获取当前应显示的文本

        Returns:
            截取后的显示文本
        """
        if not self._enabled:
            return self.text

        # 检查是否需要更新位置
        current_time = time.time()
        if current_time - self._last_update >= self.scroll_speed:
            self._position = (self._position + 1) % (len(self.text) + 3)  # +3 for spacing
            self._last_update = current_time

        # 创建循环文本（原文 + 空格 + 原文开头）
        extended_text = self.text + "   " + self.text

        # 从当前位置截取
        display_text = extended_text[self._position:self._position + self.max_length]

        return display_text

    def reset(self):
        """重置到起始位置"""
        self._position = 0
        self._last_update = time.time()

    def update_text(self, new_text: str):
        """
        更新文本内容

        Args:
            new_text: 新的文本内容
        """
        self.text = new_text
        self._display_width = self._calculate_display_width(new_text)
        self._enabled = self._display_width > self.max_length
        self.reset()


class MarqueeManager:
    """
    跑马灯管理器

    管理多个跑马灯实例（用于不同的状态）
    """

    def __init__(self, max_length: int = 30, scroll_speed: float = 0.3):
        """
        Args:
            max_length: 最大显示宽度（约10个中文字符或20个英文字符）
            scroll_speed: 滚动速度（秒）
        """
        self.max_length = max_length
        self.scroll_speed = scroll_speed
        self._current_marquee: Optional[Marquee] = None

    def set_text(self, text: str) -> Marquee:
        """
        设置要显示的文本

        Args:
            text: 文本内容

        Returns:
            Marquee 实例
        """
        self._current_marquee = Marquee(
            text=text,
            max_length=self.max_length,
            scroll_speed=self.scroll_speed
        )
        return self._current_marquee

    def get_display_text(self, text: str) -> str:
        """
        获取显示文本（自动处理长度）

        Args:
            text: 原始文本

        Returns:
            处理后的显示文本
        """
        # 如果文本变了，创建新的跑马灯
        if self._current_marquee is None or self._current_marquee.text != text:
            self._current_marquee = self.set_text(text)

        # 获取当前显示文本
        return self._current_marquee.get_display_text()

    def needs_scroll(self) -> bool:
        """当前文本是否需要滚动"""
        if self._current_marquee is None:
            return False
        return self._current_marquee.needs_scroll
