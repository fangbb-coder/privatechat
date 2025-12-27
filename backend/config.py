"""
配置管理模块
使用 pydantic-settings 管理配置，支持环境变量和 .env 文件
"""
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, field_validator, model_validator
from typing import List
import secrets
import os
import json
from loguru import logger


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
    app_version: str = "v3.6.0"
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
    refresh_token_expire_days: int = 7
    max_active_sessions: int = 5  # 每个用户最大活跃会话数

    @field_validator('access_token_expire_minutes')
    def validate_access_token_expire_minutes(cls, v):
        if v < 5:
            raise ValueError("access token 过期时间不能少于 5 分钟")
        if v > 1440:  # 24 小时
            raise ValueError("access token 过期时间不能超过 1440 分钟（24 小时）")
        return v

    @field_validator('refresh_token_expire_days')
    def validate_refresh_token_expire_days(cls, v):
        if v < 1:
            raise ValueError("refresh token 过期时间不能少于 1 天")
        if v > 90:  # 3 个月
            raise ValueError("refresh token 过期时间不能超过 90 天")
        return v

    @field_validator('max_active_sessions')
    def validate_max_active_sessions(cls, v):
        if v < 1:
            raise ValueError("最大活跃会话数不能少于 1")
        if v > 20:
            raise ValueError("最大活跃会话数不能超过 20")
        return v

    # ==================== 加密配置 ====================
    default_encryption_key: str = "PrivateChat2025Secure!"
    rsa_key_size: int = 2048
    rsa_keys_dir: str = "./keys"

    # ==================== 登录安全配置 ====================
    max_login_attempts: int = 5
    login_lock_minutes: int = 15
    ip_lock_minutes: int = 30  # IP 锁定时长
    ip_lock_threshold: int = 20  # 触发 IP 锁定的失败次数阈值
    ip_lock_check_window: int = 10  # IP 检查窗口（分钟）
    rate_limit_per_minute: int = 30  # API 请求频率限制
    rate_limit_max_ips: int = 10000  # 速率限制器最大 IP 数量

    @field_validator('max_login_attempts')
    def validate_max_login_attempts(cls, v):
        if v < 3:
            raise ValueError("最大登录尝试次数不能少于 3")
        if v > 20:
            raise ValueError("最大登录尝试次数不能超过 20")
        return v

    @field_validator('login_lock_minutes')
    def validate_login_lock_minutes(cls, v):
        if v < 1:
            raise ValueError("登录锁定时长不能少于 1 分钟")
        if v > 1440:  # 24 小时
            raise ValueError("登录锁定时长不能超过 1440 分钟（24 小时）")
        return v

    @field_validator('ip_lock_minutes')
    def validate_ip_lock_minutes(cls, v):
        if v < 5:
            raise ValueError("IP 锁定时长不能少于 5 分钟")
        if v > 1440:  # 24 小时
            raise ValueError("IP 锁定时长不能超过 1440 分钟（24 小时）")
        return v

    @field_validator('ip_lock_threshold')
    def validate_ip_lock_threshold(cls, v):
        if v < 5:
            raise ValueError("IP 锁定阈值不能少于 5")
        if v > 100:
            raise ValueError("IP 锁定阈值不能超过 100")
        return v

    @field_validator('rate_limit_per_minute')
    def validate_rate_limit_per_minute(cls, v):
        if v < 5:
            raise ValueError("请求频率限制不能少于 5/分钟")
        if v > 1000:
            raise ValueError("请求频率限制不能超过 1000/分钟")
        return v

    # ==================== WebSocket 安全配置 ====================
    ws_connections_per_minute: int = 20  # 每分钟最多 20 个连接

    # ==================== 密码强度配置 ====================
    min_password_length: int = 8
    max_password_length: int = 64
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digits: bool = True
    password_require_special: bool = True
    password_history_count: int = 5  # 记录最近 N 个密码历史

    @field_validator('min_password_length')
    def validate_min_password_length(cls, v):
        if v < 4:
            raise ValueError("最小密码长度不能少于 4")
        if v > 32:
            raise ValueError("最小密码长度不能超过 32")
        return v

    @field_validator('max_password_length')
    def validate_max_password_length(cls, v):
        if v < 8:
            raise ValueError("最大密码长度不能少于 8")
        if v > 128:
            raise ValueError("最大密码长度不能超过 128")
        return v

    @model_validator(mode='after')
    def validate_password_length_range(cls, values):
        min_len = values.min_password_length if hasattr(values, 'min_password_length') else 8
        max_len = values.max_password_length if hasattr(values, 'max_password_length') else 64
        if max_len <= min_len:
            raise ValueError("最大密码长度必须大于最小密码长度")
        return values

    @field_validator('password_history_count')
    def validate_password_history_count(cls, v):
        if v < 1:
            raise ValueError("密码历史记录数不能少于 1")
        if v > 20:
            raise ValueError("密码历史记录数不能超过 20")
        return v

    # ==================== 日志配置 ====================
    log_level: str = "DEBUG"
    log_file: str = "./logs/app.log"
    log_file_max_size_mb: int = 10  # MB
    log_file_backup_count: int = 5

    # ==================== WebSocket 配置 ====================
    ws_timeout_seconds: int = 30
    ws_heartbeat_interval_seconds: int = 30

    # ==================== 消息配置 ====================
    message_recall_minutes: int = 2
    max_message_length: int = 5000
    message_cleanup_count: int = 1000  # 消息数量达到此值时开始清理

    # ==================== 管理员配置 ====================
    admin_usernames: str = "admin"

    # ==================== 服务器配置 ====================
    host: str = "0.0.0.0"
    port: int = 8080

    # ==================== CORS 配置 ====================
    # 生产环境应该配置具体的域名列表
    # 开发环境可以使用 ["*"] 或 ["http://localhost:port", "http://127.0.0.1:port"]
    allowed_origins: List[str] = []  # 允许的域名列表，空列表表示禁止所有跨域请求
    ws_allowed_origins: List[str] = []  # WebSocket允许的域名列表

    @model_validator(mode='after')
    def auto_config_origins_for_dev(self):
        """开发环境自动配置允许的 Origin"""
        if self.environment == "development":
            # 如果 ws_allowed_origins 为空，自动添加本地地址
            if not self.ws_allowed_origins:
                port = self.port
                self.ws_allowed_origins = [
                    f"http://127.0.0.1:{port}",
                    f"http://localhost:{port}",
                ]
            # 如果 allowed_origins 为空，自动添加本地地址
            if not self.allowed_origins:
                port = self.port
                self.allowed_origins = [
                    f"http://127.0.0.1:{port}",
                    f"http://localhost:{port}",
                ]
        return self

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
            except (OSError, IOError) as e:
                pass

        # 生成新密钥
        new_key = self.generate_secret_key()
        try:
            with open(self.secret_key_file, 'w') as f:
                f.write(new_key)
            os.chmod(self.secret_key_file, 0o600)  # 仅所有者可读写
            return new_key
        except (OSError, IOError) as e:
            pass


# 创建全局配置实例
settings = Settings()

# 自动生成或加载JWT密钥
if not settings.secret_key:
    settings.secret_key = settings.get_or_generate_secret_key()


def get_settings() -> Settings:
    """获取配置实例（依赖注入用）"""
    return settings
