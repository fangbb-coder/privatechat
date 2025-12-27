"""
配置管理模块
使用 pydantic-settings 管理配置，支持环境变量和 .env 文件
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field
from typing import List
import secrets
import os
import json


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
    app_version: str = "v3.5.3"
    environment: str = "development"
    debug: bool = False

    # ==================== 安全配置 ====================
    # JWT 密钥将在首次启动时自动生成并保存到 .secret_key 文件
    secret_key: str = Field(
        default="",
        description="JWT 密钥（自动生成，不要手动设置）"
    )
    secret_key_file: str = "./data/.secret_key"
    access_token_expire_minutes: int = 30

    # ==================== 加密配置 ====================
    default_encryption_key: str = "PrivateChat2025Secure!"
    rsa_key_size: int = 2048
    rsa_keys_dir: str = "./keys"

    # ==================== 登录安全配置 ====================
    max_login_attempts: int = 5
    login_lock_minutes: int = 15
    rate_limit_per_minute: int = 30  # 降低频率限制，避免正常用户被限制

    # ==================== WebSocket 安全配置 ====================
    ws_connections_per_minute: int = 20  # 每分钟最多 20 个连接

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

    # ==================== CORS 配置 ====================
    allowed_origins: List[str] = ["*"]  # 允许的域名列表，*表示允许所有
    ws_allowed_origins: List[str] = ["*"]  # WebSocket允许的域名列表

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

    def get_or_generate_secret_key(self) -> str:
        """从文件加载或生成密钥"""
        # 确保目录存在
        secret_key_dir = os.path.dirname(self.secret_key_file)
        if secret_key_dir and not os.path.exists(secret_key_dir):
            os.makedirs(secret_key_dir, exist_ok=True)

        # 如果文件存在，读取密钥
        if os.path.exists(self.secret_key_file):
            try:
                with open(self.secret_key_file, 'r') as f:
                    return f.read().strip()
            except:
                pass

        # 生成新密钥
        new_key = self.generate_secret_key()
        try:
            with open(self.secret_key_file, 'w') as f:
                f.write(new_key)
            os.chmod(self.secret_key_file, 0o600)  # 仅所有者可读写
            return new_key
        except:
            return new_key


# 创建全局配置实例
settings = Settings()

# 自动生成或加载JWT密钥
if not settings.secret_key:
    settings.secret_key = settings.get_or_generate_secret_key()


def get_settings() -> Settings:
    """获取配置实例（依赖注入用）"""
    return settings
