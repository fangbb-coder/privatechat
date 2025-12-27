"""
配置管理模块
使用 pydantic-settings 管理配置，支持环境变量和 .env 文件
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import List
import secrets
import os


class Settings(BaseSettings):
    """应用配置类"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # ==================== 应用配置 ====================
    app_name: str = "Private Chat"
    app_version: str = "v3.3"
    environment: str = "development"
    debug: bool = False

    # ==================== 安全配置 ====================
    secret_key: str = Field(
        default="your-secret-key-change-this-in-production-minimal-chat-2025",
        description="JWT 密钥，生产环境必须修改"
    )
    access_token_expire_minutes: int = 30
    remember_token_expire_minutes: int = 10080  # 7 天

    # ==================== 加密配置 ====================
    default_encryption_key: str = "PrivateChat2025Secure!"
    rsa_key_size: int = 2048
    rsa_keys_dir: str = "./keys"

    # ==================== 登录安全配置 ====================
    max_login_attempts: int = 5
    login_lock_minutes: int = 15
    rate_limit_per_minute: int = 60

    # ==================== 密码强度配置 ====================
    min_password_length: int = 8
    max_password_length: int = 64
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digits: bool = True
    password_require_special: bool = True

    # ==================== 日志配置 ====================
    log_level: str = "INFO"
    log_file: str = "./logs/app.log"
    log_file_max_size: int = 10  # MB
    log_file_backup_count: int = 5

    # ==================== WebSocket 配置 ====================
    ws_timeout: int = 30
    heartbeat_interval: int = 30

    # ==================== 消息配置 ====================
    message_recall_minutes: int = 2
    max_message_length: int = 5000

    # ==================== 管理员配置 ====================
    admin_usernames: str = "admin"

    # ==================== 服务器配置 ====================
    host: str = "0.0.0.0"
    port: int = 8080

    @property
    def admin_username_list(self) -> List[str]:
        """获取管理员用户名列表"""
        return [name.strip() for name in self.admin_usernames.split(",") if name.strip()]

    def is_admin(self, username: str) -> bool:
        """检查用户是否为管理员"""
        return username in self.admin_username_list

    def generate_secret_key(self) -> str:
        """生成随机的 SECRET_KEY"""
        return secrets.token_urlsafe(64)


# 创建全局配置实例
settings = Settings()


def get_settings() -> Settings:
    """获取配置实例（依赖注入用）"""
    return settings
