"""
文件操作工具函数
处理文件系统操作、路径处理等
"""

import json
import asyncio
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union, List


from ..core.logger import get_logger
from ..utils.logging_utils import (
    correlation_id,
    safe_repr,
)

# Module-level logger
logger = get_logger(tag="UTILS.FILE_UTILS", name=__name__)

# 可选导入aiofiles
try:
    import aiofiles

    HAS_AIOFILES = True
except ImportError:
    aiofiles = None
    HAS_AIOFILES = False


class FileUtils:
    """文件操作工具类"""

    @staticmethod
    async def read_text_async(
        file_path: Union[str, Path], encoding: str = "utf-8"
    ) -> str:
        """异步读取文本文件"""
        cid = correlation_id()
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"cid={cid} read_text_async.enter path={file_path}")
        if HAS_AIOFILES:
            async with aiofiles.open(file_path, "r", encoding=encoding) as f:
                content = await f.read()
        else:
            # 同步fallback
            content = await asyncio.get_event_loop().run_in_executor(
                None, lambda: Path(file_path).read_text(encoding=encoding)
            )
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                f"cid={cid} read_text_async.leave path={file_path} size={len(content)}"
            )
        return content

    @staticmethod
    async def write_text_async(
        file_path: Union[str, Path], content: str, encoding: str = "utf-8"
    ) -> None:
        """异步写入文本文件"""
        cid = correlation_id()
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                f"cid={cid} write_text_async.enter path={file_path} size={len(content)}"
            )
        # 确保父目录存在
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)

        if HAS_AIOFILES:
            async with aiofiles.open(file_path, "w", encoding=encoding) as f:
                await f.write(content)
        else:
            # 同步fallback
            await asyncio.get_event_loop().run_in_executor(
                None, lambda: Path(file_path).write_text(content, encoding=encoding)
            )
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"cid={cid} write_text_async.leave path={file_path}")

    @staticmethod
    def read_json(file_path: Union[str, Path]) -> Dict[str, Any]:
        """同步读取JSON文件"""
        cid = correlation_id()
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                f"cid={cid} read_json path={file_path} keys={len(data) if isinstance(data, dict) else 'n/a'}"
            )
        return data

    @staticmethod
    async def read_json_async(file_path: Union[str, Path]) -> Dict[str, Any]:
        """异步读取JSON文件"""
        cid = correlation_id()
        content = await FileUtils.read_text_async(file_path)
        data = json.loads(content)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                f"cid={cid} read_json_async path={file_path} keys={len(data) if isinstance(data, dict) else 'n/a'}"
            )
        return data

    @staticmethod
    def write_json(
        file_path: Union[str, Path], data: Dict[str, Any], indent: int = 2
    ) -> None:
        """同步写入JSON文件"""
        cid = correlation_id()
        Path(file_path).parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                f"cid={cid} write_json path={file_path} keys={len(data) if isinstance(data, dict) else 'n/a'}"
            )

    @staticmethod
    async def write_json_async(
        file_path: Union[str, Path], data: Dict[str, Any], indent: int = 2
    ) -> None:
        """异步写入JSON文件"""
        cid = correlation_id()
        content = json.dumps(data, indent=indent, ensure_ascii=False)
        await FileUtils.write_text_async(file_path, content)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                f"cid={cid} write_json_async path={file_path} keys={len(data) if isinstance(data, dict) else 'n/a'}"
            )

    @staticmethod
    def ensure_directory(dir_path: Union[str, Path]) -> Path:
        """确保目录存在"""
        path = Path(dir_path)
        path.mkdir(parents=True, exist_ok=True)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"ensure_directory path={path}")
        return path

    @staticmethod
    def find_files(
        directory: Union[str, Path], pattern: str = "*", recursive: bool = True
    ) -> List[Path]:
        """查找文件"""
        path = Path(directory)
        if recursive:
            files = list(path.rglob(pattern))
        else:
            files = list(path.glob(pattern))
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                f"find_files dir={directory} pattern={pattern} recursive={recursive} count={len(files)}"
            )
        return files

    @staticmethod
    def get_file_size(file_path: Union[str, Path]) -> int:
        """获取文件大小(字节)"""
        size = Path(file_path).stat().st_size
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"get_file_size path={file_path} size={size}")
        return size

    @staticmethod
    def get_file_extension(file_path: Union[str, Path]) -> str:
        """获取文件扩展名"""
        cid = correlation_id()
        ext = Path(file_path).suffix.lower()
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"cid={cid} get_file_extension path={file_path} ext={ext}")
        return ext

    @staticmethod
    def is_config_file(file_path: Union[str, Path]) -> bool:
        """判断是否为配置文件"""
        cid = correlation_id()
        ext = FileUtils.get_file_extension(file_path)
        ok = ext in [".json"]
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"cid={cid} is_config_file path={file_path} ext={ext} ok={ok}")
        return ok

    @staticmethod
    async def load_config_file(file_path: Union[str, Path]) -> Optional[Dict[str, Any]]:
        """异步加载配置文件（自动判断格式）"""
        cid = correlation_id()
        if not Path(file_path).exists():
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug(
                    f"cid={cid} load_config_file.skip_missing path={file_path}"
                )
            return None

        ext = FileUtils.get_file_extension(file_path)
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"cid={cid} load_config_file.enter path={file_path} ext={ext}")

        try:
            if ext == ".json":
                data = await FileUtils.read_json_async(file_path)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        f"cid={cid} load_config_file.success path={file_path} keys={len(data) if isinstance(data, dict) else 'n/a'}"
                    )
                return data
            else:
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(
                        f"cid={cid} load_config_file.unsupported path={file_path} ext={ext}"
                    )
                return None
        except Exception as e:
            logger.warning(
                f"cid={cid} load_config_file.error path={file_path} ext={ext} error={type(e).__name__}: {e}"
            )
            return None

    @staticmethod
    def safe_filename(filename: str) -> str:
        """生成安全的文件名"""
        import re

        cid = correlation_id()
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                f"cid={cid} safe_filename.enter original={safe_repr(filename)} length={len(filename)}"
            )
        # 移除或替换危险字符
        safe_name = re.sub(r'[<>:"/\\|?*]', "_", filename)
        # 移除连续的点
        safe_name = re.sub(r"\.{2,}", ".", safe_name)
        # 确保不以点开头或结尾
        safe_name = safe_name.strip(".")
        result = safe_name or "unnamed"
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                f"cid={cid} safe_filename.leave original_length={len(filename)} result={safe_repr(result)}"
            )
        return result
