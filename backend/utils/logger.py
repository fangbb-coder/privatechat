"""
日志模块
基于 Loguru，支持日志轮转、级别控制与日志目录自动创建
"""
import sys
from pathlib import Path
from typing import TYPE_CHECKING

from loguru import logger as loguru_logger

if TYPE_CHECKING:
    from utils.config import Settings


def setup_logger(settings: "Settings"):
    """
    根据配置初始化日志系统

    - 控制台输出（带颜色）
    - 文件轮转（按大小 + 保留天数）
    - 移除默认 handler，避免重复输出
    """
    log_dir = Path(settings.log_dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    # 清除默认 handler
    loguru_logger.remove()

    log_level = (settings.log_level or "INFO").upper()

    # 控制台
    loguru_logger.add(
        sys.stderr,
        level=log_level,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
            "<level>{message}</level>"
        ),
        backtrace=settings.is_development,
        diagnose=settings.is_development,  # 生产环境不暴露变量值
    )

    # 文件（按大小轮转，保留 14 天）
    loguru_logger.add(
        str(log_dir / "app.log"),
        level=log_level,
        rotation="10 MB",
        retention="14 days",
        compression="zip",
        encoding="utf-8",
        format=(
            "{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | "
            "{name}:{function}:{line} - {message}"
        ),
        backtrace=True,
        diagnose=False,  # 文件中始终不暴露变量值，防敏感泄露
    )

    loguru_logger.info(f"日志系统已初始化 (级别: {log_level}, 目录: {log_dir})")
    return loguru_logger


def get_logger():
    """获取 logger 实例（已在 setup_logger 中配置）"""
    return loguru_logger
