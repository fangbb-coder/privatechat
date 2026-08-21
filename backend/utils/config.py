"""
配置管理模块
基于 pydantic-settings，从环境变量 / .env 文件加载配置
"""
import os
import secrets
import warnings
from pathlib import Path
from typing import List, Union

from pydantic import AnyHttpUrl, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


# 项目根目录（backend/ 的上一级）
BASE_DIR = Path(__file__).resolve().parent.parent.parent
BACKEND_DIR = Path(__file__).resolve().parent.parent


def _parse_origins(raw: Union[str, List[str], None]) -> List[str]:
    """兼容字符串 / 列表格式的域名配置"""
    if raw is None or raw == "":
        return []
    if isinstance(raw, list):
        return [str(x).strip() for x in raw if str(x).strip()]
    # 字符串：可能是 JSON 数组或逗号分隔
    raw = raw.strip()
    if raw.startswith("["):
        import json
        try:
            parsed = json.loads(raw)
            return [str(x).strip() for x in parsed if str(x).strip()]
        except json.JSONDecodeError:
            pass
    return [x.strip() for x in raw.split(",") if x.strip()]


class Settings(BaseSettings):
    """应用配置"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ==================== 应用 ====================
    app_name: str = "Private Chat"
    app_version: str = "3.6.1"
    environment: str = Field("development", description="development / production")

    host: str = "0.0.0.0"
    port: int = 8080

    # ==================== 密钥（H2: 密钥分离）====================
    # JWT 签名密钥（留空则自动生成，生产环境必须显式设置）
    secret_key: str = Field(default_factory=lambda: secrets.token_urlsafe(48))
    # 数据库字段加密密钥（独立于 JWT 密钥）
    db_encryption_key: str = Field(default_factory=lambda: secrets.token_urlsafe(32))

    # ==================== 默认管理员（C3: 移除硬编码，改环境变量）====================
    admin_usernames: str = "admin"
    # 首次启动创建管理员时使用的密码；未设置则随机生成并打印一次
    admin_password: str = ""

    # ==================== Token ====================
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    max_active_sessions: int = 5

    # ==================== 密码策略 ====================
    min_password_length: int = 8
    max_password_length: int = 64
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digits: bool = True
    password_require_special: bool = True
    password_history_count: int = 5

    # ==================== 登录安全 ====================
    max_login_attempts: int = 5
    login_lock_minutes: int = 15
    ip_lock_minutes: int = 30
    ip_lock_threshold: int = 20

    # ==================== 速率限制 ====================
    rate_limit_per_minute: int = 60
    rate_limit_max_ips: int = 10000
    ws_connections_per_minute: int = 20

    # ==================== 消息 ====================
    message_recall_minutes: int = 2
    max_message_length: int = 5000
    # M2: messages 字典最大条数，防止内存泄漏
    max_stored_messages: int = 1000
    default_encryption_key: str = "PrivateChat2025Secure!"

    # ==================== RSA ====================
    rsa_key_size: int = 2048
    rsa_keys_dir: str = Field(
        default_factory=lambda: str(BACKEND_DIR / "keys"),
        description="RSA 密钥存储目录",
    )

    # ==================== 数据库 ====================
    database_path: str = Field(
        default_factory=lambda: str(BASE_DIR / "data" / "chat.db"),
        description="SQLite 数据库路径",
    )

    # ==================== CORS / Host（H3）====================
    allowed_origins: List[str] = Field(default_factory=list)
    allowed_hosts: List[str] = Field(default_factory=list)
    ws_allowed_origins: List[str] = Field(default_factory=lambda: ["*"])

    # ==================== 日志 ====================
    log_level: str = "INFO"
    log_dir: str = Field(default_factory=lambda: str(BASE_DIR / "logs"))

    # ==================== 解析器 ====================
    @field_validator("allowed_origins", mode="before")
    @classmethod
    def _parse_allowed_origins(cls, v):
        return _parse_origins(v)

    @field_validator("ws_allowed_origins", mode="before")
    @classmethod
    def _parse_ws_origins(cls, v):
        return _parse_origins(v)

    @field_validator("allowed_hosts", mode="before")
    @classmethod
    def _parse_allowed_hosts(cls, v):
        return _parse_origins(v)

    @field_validator("environment")
    @classmethod
    def _normalize_env(cls, v):
        v = (v or "development").strip().lower()
        if v not in ("development", "production", "staging"):
            v = "development"
        return v

    # ==================== 配置校验（启动时）====================
    @model_validator(mode="after")
    def _validate_config(self):
        errors = []

        # 生产环境必须显式设置密钥
        if self.environment == "production":
            if not self.secret_key or self.secret_key == "":
                errors.append("production 环境必须显式设置 SECRET_KEY")
            if len(self.secret_key) < 32:
                errors.append("production 环境 SECRET_KEY 长度必须 >= 32")
            if not self.db_encryption_key or len(self.db_encryption_key) < 32:
                errors.append("production 环境 DB_ENCRYPTION_KEY 长度必须 >= 32")
            if not self.allowed_origins:
                errors.append("production 环境必须配置 ALLOWED_ORIGINS")
            if not self.allowed_hosts:
                errors.append("production 环境必须配置 ALLOWED_HOSTS")
            if "*" in self.allowed_hosts:
                errors.append("production 环境 ALLOWED_HOSTS 不能为 ['*']")
            if "*" in self.ws_allowed_origins:
                warnings.warn("生产环境 WS_ALLOWED_ORIGINS 含 '*'，建议配置具体域名")

        if self.min_password_length < 8:
            errors.append("MIN_PASSWORD_LENGTH 不能小于 8")
        if self.access_token_expire_minutes <= 0:
            errors.append("ACCESS_TOKEN_EXPIRE_MINUTES 必须 > 0")

        if errors:
            raise ValueError("配置校验失败:\n  - " + "\n  - ".join(errors))

        return self

    # ==================== 便捷属性 ====================
    @property
    def admin_username_list(self) -> List[str]:
        return [u.strip() for u in self.admin_usernames.split(",") if u.strip()]

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_development(self) -> bool:
        return self.environment == "development"


# 单例
settings = Settings()
