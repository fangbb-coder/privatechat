"""
日志配置模块
使用 loguru 提供结构化日志
"""
import sys
from loguru import logger
from pathlib import Path
from config import settings


def setup_logger():
    """配置日志系统"""

    # 移除默认的处理器
    logger.remove()

    # 日志格式
    log_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
        "<level>{message}</level>"
    )

    # 控制台输出
    logger.add(
        sys.stdout,
        format=log_format,
        level=settings.log_level,
        colorize=True,
        backtrace=True,
        diagnose=True
    )

    # 文件输出
    log_file_path = Path(settings.log_file)
    log_file_path.parent.mkdir(parents=True, exist_ok=True)

    logger.add(
        settings.log_file,
        format=log_format,
        level=settings.log_level,
        rotation=f"{settings.log_file_max_size} MB",
        retention=f"{settings.log_file_backup_count} days",
        compression="zip",
        backtrace=True,
        diagnose=True,
        encoding="utf-8"
    )

    # 错误日志单独文件
    error_log_path = log_file_path.parent / "error.log"
    logger.add(
        str(error_log_path),
        format=log_format,
        level="ERROR",
        rotation=f"{settings.log_file_max_size} MB",
        retention=f"{settings.log_file_backup_count} days",
        compression="zip",
        backtrace=True,
        diagnose=True,
        encoding="utf-8"
    )

    logger.info(f"日志系统初始化完成 - 级别: {settings.log_level}")
    logger.info(f"应用: {settings.app_name} {settings.app_version}")
    logger.info(f"环境: {settings.environment}")

    return logger


# 创建日志实例
app_logger = setup_logger()


def get_logger():
    """获取日志实例"""
    return app_logger
