"""
Sentence API (一言)

Fetches random sentences from various APIs for display in menu bar.
"""

import asyncio
import logging
from typing import Optional
from enum import Enum

logger = logging.getLogger(__name__)


class SentenceType(Enum):
    """一言类型"""
    YIYAN = "一言"
    DUJITANG = "毒鸡汤"
    SHEHUIYULU = "社会语录"
    TIANGOURIJI = "舔狗日记"
    SHICI = "诗词"


class SentenceAPI:
    """
    一言 API 客户端

    获取各种类型的随机句子用于菜单栏显示
    """

    APIS = {
        SentenceType.DUJITANG: 'https://api.oick.cn/dutang/api.php',
        SentenceType.SHEHUIYULU: 'https://api.oick.cn/yulu/api.php',
        SentenceType.TIANGOURIJI: 'https://api.oick.cn/dog/api.php',
        SentenceType.YIYAN: 'https://v1.hitokoto.cn/?c=a&encode=text',  # 更稳定的一言API
        SentenceType.SHICI: 'https://v1.jinrishici.com/all.txt',
    }

    # Fallback API (诗词API最稳定)
    FALLBACK_API = 'https://v1.jinrishici.com/all.txt'

    def __init__(self, sentence_type: SentenceType = SentenceType.YIYAN):
        self.sentence_type = sentence_type
        self._last_sentence: Optional[str] = None

    async def fetch_sentence(self, timeout: float = 5.0) -> Optional[str]:
        """
        异步获取随机句子

        Args:
            timeout: 请求超时时间（秒）

        Returns:
            句子文本，失败返回 None
        """
        try:
            import aiohttp

            url = self.APIS.get(self.sentence_type)
            if not url:
                logger.warning(f"Unknown sentence type: {self.sentence_type}")
                url = self.FALLBACK_API

            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                    if response.status == 200:
                        text = await response.text()
                        # 清理文本：去掉多余的换行
                        sentence = text.strip().replace('\n', ' ')
                        self._last_sentence = sentence
                        return sentence
                    else:
                        logger.warning(f"Failed to fetch sentence: HTTP {response.status}, trying fallback")
                        # Try fallback API
                        return await self._fetch_fallback(session, timeout)

        except ImportError:
            logger.error("aiohttp not installed. Please install: pip install aiohttp")
            return None
        except asyncio.TimeoutError:
            logger.warning(f"Timeout fetching sentence, trying fallback")
            # Try fallback
            try:
                import aiohttp
                async with aiohttp.ClientSession() as session:
                    return await self._fetch_fallback(session, timeout)
            except Exception:
                return self._last_sentence  # 返回缓存的句子
        except Exception as e:
            logger.error(f"Error fetching sentence: {e}", exc_info=True)
            return self._last_sentence  # 返回缓存的句子

    async def _fetch_fallback(self, session, timeout: float) -> Optional[str]:
        """Fetch from fallback API (诗词)"""
        try:
            async with session.get(self.FALLBACK_API, timeout=aiohttp.ClientTimeout(total=timeout)) as response:
                if response.status == 200:
                    text = await response.text()
                    sentence = text.strip().replace('\n', ' ')
                    self._last_sentence = sentence
                    return sentence
        except Exception as e:
            logger.debug(f"Fallback API also failed: {e}")
        return self._last_sentence

    def fetch_sentence_sync(self, timeout: float = 5.0) -> Optional[str]:
        """
        同步获取随机句子（阻塞）

        Args:
            timeout: 请求超时时间（秒）

        Returns:
            句子文本，失败返回 None
        """
        try:
            # 在新的事件循环中运行异步函数
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(self.fetch_sentence(timeout))
                return result
            finally:
                loop.close()
        except Exception as e:
            logger.error(f"Error in sync fetch: {e}", exc_info=True)
            return self._last_sentence

    def get_last_sentence(self) -> str:
        """获取上次获取的句子（缓存）"""
        return self._last_sentence or "Global Scripts - 命令行工具集"


# 全局实例
_sentence_api: Optional[SentenceAPI] = None


def get_sentence_api(sentence_type: SentenceType = SentenceType.YIYAN) -> SentenceAPI:
    """
    获取一言 API 单例

    Args:
        sentence_type: 句子类型

    Returns:
        SentenceAPI 实例
    """
    global _sentence_api
    if _sentence_api is None or _sentence_api.sentence_type != sentence_type:
        _sentence_api = SentenceAPI(sentence_type)
    return _sentence_api
