"""
Private Chat v3.6.0 - 安全增强版加密聊天系统
新功能：
- 密码强度检查
- 登录失败限制（增强：IP级别锁定）
- IP 频率限制
- WebSocket Origin 验证
- 消息加密密码强制设置
- CSP 防护 XSS 攻击
- JWT 密钥自动生成
- 错误消息优化（区分账户禁用、锁定、密码错误）
- 消息撤回
- 在线用户列表
- 管理员功能
- 日志系统
- 健康检查
- 监控指标
"""
import os
# 阻止 slowapi/starlette 读取 .env 文件（避免编码问题，settings 已通过 pydantic-settings 读取）
os.environ['STARLETTE_ENV_FILE'] = ''

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from jose import JWTError, jwt
from typing import List, Optional, Dict
from datetime import datetime, timedelta
import time
import secrets
import uuid
import sqlite3
import json

# 导入自定义模块
from config import settings
from logger import setup_logger, get_logger
from utils import (
    AESEncryptor,
    RSAKeyManager,
    PasswordHasher,
    PasswordValidator,
    LoginAttemptTracker,
    IPRateLimiter,
    WSConnectionRateLimiter,
    DatabaseEncryptor,
    RSAEncryptor,
    mask_sensitive_data
)
from models.user import (
    UserRegister,
    UserLogin,
    UserChangePassword,
    UserInfo,
    TokenResponse,
    RefreshTokenRequest,
    Message,
    MessageRecall,
    OnlineUser,
    SystemAnnouncement,
    StatsResponse
)

# 初始化日志
logger = setup_logger(settings)
logger.info("Private Chat v3.6 启动中...")

# ==================== FastAPI 应用初始化 ====================
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="安全的私有加密聊天系统 - 支持 AES-256 加密、JWT 认证、消息撤回等功能"
)

# ==================== CORS 配置 ====================
# 配置 CORS 中间件
allowed_origins = settings.allowed_origins if settings.allowed_origins else []
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Range", "X-Total-Count"],
    max_age=600,
)

# ==================== 安全 HTTP 头中间件 ====================
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """添加安全 HTTP 响应头"""

    async def dispatch(self, request: StarletteRequest, call_next):
        response = await call_next(request)

        # 安全 HTTP 头
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # 内容安全策略 (CSP)
        # 允许内联脚本（用于消息加密/解密）
        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; "
            "font-src 'self' data:; "
            "connect-src 'self' ws: wss:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none';"
        )
        response.headers["Content-Security-Policy"] = csp

        # 缓存控制
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"

        return response

# 添加安全头中间件（在生产环境）
if settings.environment != "development":
    app.add_middleware(SecurityHeadersMiddleware)

# 添加受信任主机中间件（生产环境）
if settings.environment == "production":
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=["*"]  # 生产环境应该配置具体的主机列表
    )

# 挂载静态文件目录
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

# ==================== 速率限制 ====================
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ==================== OAuth2 方案 ====================
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# ==================== 初始化 RSA 密钥管理器 ====================
rsa_key_manager = RSAKeyManager(
    keys_dir=settings.rsa_keys_dir,
    key_size=settings.rsa_key_size
)
private_key_pem, public_key_pem = rsa_key_manager.load_or_generate()
logger.info(f"RSA 密钥已加载/生成，密钥长度: {settings.rsa_key_size} 位")

# ==================== 用户数据库 ====================
class UserDB:
    """用户数据库管理 - 使用 SQLite 持久化存储 + 字段级加密 + 缓存优化"""

    def __init__(self, db_path: str = "./data/users.db"):
        self.db_path = db_path
        self.encryptor = DatabaseEncryptor()
        self._user_cache: Dict[str, dict] = {}  # 用户名到用户信息的缓存
        self._username_to_encrypted: Dict[str, str] = {}  # 用户名到加密用户名的映射缓存
        self._ensure_db_directory()
        self._init_db()
        self._ensure_default_admin()
        self._build_cache()  # 构建缓存

    def _ensure_db_directory(self):
        """确保数据库目录存在"""
        import os
        db_dir = os.path.dirname(self.db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)
            logger.info(f"创建数据库目录: {db_dir}")

    def _get_connection(self):
        """获取数据库连接"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """初始化数据库表"""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    hashed_password TEXT NOT NULL,
                    is_admin INTEGER DEFAULT 0,
                    is_disabled INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL
                )
            """)
            # 创建密码历史表
            conn.execute("""
                CREATE TABLE IF NOT EXISTS password_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    hashed_password TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    UNIQUE(username, id)
                )
            """)
            # 创建 refresh token 表
            conn.execute("""
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    token TEXT NOT NULL UNIQUE,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    is_revoked INTEGER DEFAULT 0
                )
            """)
            conn.commit()
            logger.info("用户数据库初始化完成（敏感字段已加密，密码历史已启用，refresh token 已启用）")

    def _ensure_default_admin(self):
        """确保默认管理员账户存在"""
        with self._get_connection() as conn:
            # 检查是否存在管理员（需要解密用户名来检查）
            rows = conn.execute("SELECT * FROM users WHERE is_admin = 1").fetchall()

            has_admin = False
            for row in rows:
                try:
                    decrypted_username = self.encryptor.decrypt(row["username"])
                    if decrypted_username == "admin":
                        has_admin = True
                        break
                except ValueError as e:
                    logger.debug(f"解密用户名失败: {e}")
                    continue

            if not has_admin:
                # 创建默认管理员（加密用户名和密码）
                admin_hashed = PasswordHasher.hash_password("Admin@2025")
                encrypted_username = self.encryptor.encrypt("admin")
                encrypted_password = self.encryptor.encrypt(admin_hashed)

                conn.execute(
                    "INSERT INTO users (username, hashed_password, is_admin, is_disabled, created_at) VALUES (?, ?, ?, ?, ?)",
                    (encrypted_username, encrypted_password, 1, 0, datetime.now().isoformat())
                )
                conn.commit()
                logger.info("默认管理员账户已创建 - 用户名: admin, 密码: Admin@2025（已加密存储）")
                # 更新缓存
                self._build_cache()

    def add_user(self, username: str, hashed_password: str):
        """添加用户"""
        # 加密用户名
        encrypted_username = self.encryptor.encrypt(username)
        # hashed_password 已经是 bcrypt 哈希，不需要再次加密

        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO users (username, hashed_password, is_admin, is_disabled, created_at) VALUES (?, ?, ?, ?, ?)",
                (encrypted_username, hashed_password, 0, 0, datetime.now().isoformat())
            )
            conn.commit()
            logger.info(f"新用户注册: {username}")

    def _build_cache(self):
        """构建用户缓存以提高查询性能"""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM users").fetchall()
            for row in rows:
                try:
                    decrypted_username = self.encryptor.decrypt(row["username"])
                    encrypted_username = row["username"]
                    # 构建缓存
                    self._username_to_encrypted[decrypted_username] = encrypted_username
                    self._user_cache[decrypted_username] = {
                        "username": decrypted_username,
                        "hashed_password": row["hashed_password"],  # bcrypt 哈希，不需要解密
                        "is_admin": bool(row["is_admin"]),
                        "is_disabled": bool(row["is_disabled"]),
                        "created_at": datetime.fromisoformat(row["created_at"]),
                        "_encrypted_username": encrypted_username
                    }
                except Exception as e:
                    logger.warning(f"构建缓存失败: {str(e)}")
                    continue
            logger.info(f"用户缓存构建完成，缓存用户数: {len(self._user_cache)}")

    def _update_cache(self, username: str):
        """更新缓存中的用户信息"""
        user = self._get_user_from_db(username)
        if user:
            self._user_cache[username] = user
            self._username_to_encrypted[username] = user["_encrypted_username"]
        elif username in self._user_cache:
            del self._user_cache[username]
            del self._username_to_encrypted[username]

    def _get_user_from_db(self, username: str) -> Optional[dict]:
        """从数据库获取用户信息（不使用缓存）"""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM users").fetchall()
            for row in rows:
                try:
                    decrypted_username = self.encryptor.decrypt(row["username"])
                    if decrypted_username == username:
                        return {
                            "username": decrypted_username,
                            "hashed_password": row["hashed_password"],  # bcrypt 哈希，不需要解密
                            "is_admin": bool(row["is_admin"]),
                            "is_disabled": bool(row["is_disabled"]),
                            "created_at": datetime.fromisoformat(row["created_at"]),
                            "_encrypted_username": row["username"]
                        }
                except Exception as e:
                    logger.warning(f"解密用户数据失败: {str(e)}")
                    continue
            return None

    def get_user(self, username: str) -> Optional[dict]:
        """获取用户信息（优先从缓存获取）"""
        # 先尝试从缓存获取
        if username in self._user_cache:
            return self._user_cache[username]

        # 缓存中不存在，从数据库获取并更新缓存
        user = self._get_user_from_db(username)
        if user:
            self._user_cache[username] = user
            self._username_to_encrypted[username] = user["_encrypted_username"]
        return user

    def is_disabled(self, username: str) -> bool:
        """检查用户是否被禁用"""
        user = self.get_user(username)
        return user["is_disabled"] if user else False

    def is_admin(self, username: str) -> bool:
        """检查用户是否为管理员"""
        user = self.get_user(username)
        return user["is_admin"] if user else False

    def disable_user(self, username: str, disabled: bool = True):
        """禁用/启用用户"""
        encrypted_username = self._username_to_encrypted.get(username)
        if not encrypted_username:
            logger.warning(f"禁用用户失败: 用户不存在 - {username}")
            return

        with self._get_connection() as conn:
            conn.execute(
                "UPDATE users SET is_disabled = ? WHERE username = ?",
                (1 if disabled else 0, encrypted_username)
            )
            conn.commit()
            action = "禁用" if disabled else "启用"
            logger.warning(f"用户已{action}: {username}")
            # 更新缓存
            self._update_cache(username)

    def delete_user(self, username: str):
        """删除用户"""
        encrypted_username = self._username_to_encrypted.get(username)
        if not encrypted_username:
            logger.warning(f"删除用户失败: 用户不存在 - {username}")
            return

        with self._get_connection() as conn:
            conn.execute("DELETE FROM users WHERE username = ?", (encrypted_username,))
            conn.commit()
            logger.warning(f"用户已删除: {username}")
            # 更新缓存
            if username in self._user_cache:
                del self._user_cache[username]
            if username in self._username_to_encrypted:
                del self._username_to_encrypted[username]

    def change_password(self, username: str, new_hashed_password: str):
        """修改密码（带密码历史检查）"""
        # 检查密码历史
        if self.is_password_in_history(username, new_hashed_password):
            logger.warning(f"用户尝试使用历史密码: {username}")
            raise ValueError("不能使用最近使用过的密码")

        encrypted_username = self._username_to_encrypted.get(username)
        if not encrypted_username:
            logger.warning(f"修改密码失败: 用户不存在 - {username}")
            return

        # 加密新密码
        encrypted_password = self.encryptor.encrypt(new_hashed_password)

        with self._get_connection() as conn:
            # 先添加旧密码到历史记录
            user = self.get_user(username)
            if user:
                old_password = user["hashed_password"]
                encrypted_old_password = self.encryptor.encrypt(old_password)
                conn.execute(
                    "INSERT INTO password_history (username, hashed_password, created_at) VALUES (?, ?, ?)",
                    (encrypted_username, encrypted_old_password, datetime.now().isoformat())
                )

                # 更新用户密码
                conn.execute(
                    "UPDATE users SET hashed_password = ? WHERE username = ?",
                    (encrypted_password, encrypted_username)
                )

                # 清理过期的密码历史（保留最近的 N 个）
                self._cleanup_password_history(username)

                conn.commit()
                logger.info(f"用户修改密码: {username}")
                # 更新缓存
                self._update_cache(username)

    def is_password_in_history(self, username: str, new_hashed_password: str) -> bool:
        """检查新密码是否在历史记录中"""
        with self._get_connection() as conn:
            # 加密新密码用于比较
            encrypted_new_password = self.encryptor.encrypt(new_hashed_password)

            # 获取该用户最近的密码历史
            rows = conn.execute("""
                SELECT hashed_password FROM password_history
                ORDER BY created_at DESC LIMIT ?
            """, (settings.password_history_count,)).fetchall()

            for row in rows:
                try:
                    # 解密历史密码
                    old_password = self.encryptor.decrypt(row["hashed_password"])
                    # 比较密码哈希（bcrypt 是通过 verify 来比较的）
                    if PasswordHasher.verify_password(new_hashed_password, old_password):
                        return True
                except Exception as e:
                    logger.debug(f"检查密码历史时解密失败: {e}")
                    continue

            return False

    def _cleanup_password_history(self, username: str):
        """清理过期的密码历史记录"""
        with self._get_connection() as conn:
            # 加密用户名用于查询
            encrypted_username = self.encryptor.encrypt(username)

            # 获取所有历史记录
            rows = conn.execute("""
                SELECT id, username FROM password_history
                ORDER BY created_at DESC
            """).fetchall()

            # 找到该用户的历史记录并清理
            user_history_ids = []
            for row in rows:
                try:
                    decrypted_username = self.encryptor.decrypt(row["username"])
                    if decrypted_username == username:
                        user_history_ids.append(row["id"])
                except Exception:
                    continue

            # 保留最近的 N 个，删除其余的
            if len(user_history_ids) > settings.password_history_count:
                ids_to_delete = user_history_ids[settings.password_history_count:]
                for history_id in ids_to_delete:
                    conn.execute("DELETE FROM password_history WHERE id = ?", (history_id,))
                logger.debug(f"清理密码历史: {username}, 删除 {len(ids_to_delete)} 条记录")

    def save_refresh_token(self, username: str, token: str) -> str:
        """保存 refresh token 到数据库（带会话数量限制）"""
        # 检查活跃会话数
        active_sessions = self._count_active_refresh_tokens(username)
        if active_sessions >= settings.max_active_sessions:
            # 撤销最旧的 token
            self._revoke_oldest_refresh_token(username)
            logger.warning(f"达到最大会话数限制，撤销最旧的会话: {username}")

        encrypted_username = self.encryptor.encrypt(username)
        encrypted_token = self.encryptor.encrypt(token)
        expires_at = datetime.now() + timedelta(days=settings.refresh_token_expire_days)

        with self._get_connection() as conn:
            conn.execute(
                "INSERT INTO refresh_tokens (username, token, expires_at, created_at) VALUES (?, ?, ?, ?)",
                (encrypted_username, encrypted_token, expires_at.isoformat(), datetime.now().isoformat())
            )
            conn.commit()
            logger.debug(f"保存 refresh token: {username}, 活跃会话数: {active_sessions + 1}")
            return token

    def _count_active_refresh_tokens(self, username: str) -> int:
        """统计用户的活跃 refresh tokens 数量"""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT username FROM refresh_tokens WHERE is_revoked = 0").fetchall()
            count = 0
            for row in rows:
                try:
                    decrypted_username = self.encryptor.decrypt(row["username"])
                    if decrypted_username == username:
                        count += 1
                except Exception:
                    continue
            return count

    def _revoke_oldest_refresh_token(self, username: str):
        """撤销用户最旧的 refresh token"""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT id, username FROM refresh_tokens
                WHERE is_revoked = 0
                ORDER BY created_at ASC
                LIMIT 1
            """).fetchall()

            for row in rows:
                try:
                    decrypted_username = self.encryptor.decrypt(row["username"])
                    if decrypted_username == username:
                        conn.execute("UPDATE refresh_tokens SET is_revoked = 1 WHERE id = ?", (row["id"],))
                        conn.commit()
                        logger.debug(f"撤销最旧的 refresh token: {username}")
                        return
                except Exception:
                    continue

    def get_refresh_token(self, token: str) -> Optional[dict]:
        """验证并获取 refresh token 信息"""
        encrypted_token = self.encryptor.encrypt(token)

        with self._get_connection() as conn:
            row = conn.execute("SELECT * FROM refresh_tokens WHERE token = ?", (encrypted_token,)).fetchone()
            if not row:
                return None

            try:
                decrypted_username = self.encryptor.decrypt(row["username"])
                decrypted_token = self.encryptor.decrypt(row["token"])

                # 检查是否已撤销
                if row["is_revoked"]:
                    logger.warning(f"Refresh token 已被撤销: {decrypted_username}")
                    return None

                # 检查是否过期
                expires_at = datetime.fromisoformat(row["expires_at"])
                if datetime.now() > expires_at:
                    logger.warning(f"Refresh token 已过期: {decrypted_username}")
                    # 删除过期的 token
                    conn.execute("DELETE FROM refresh_tokens WHERE id = ?", (row["id"],))
                    conn.commit()
                    return None

                return {
                    "username": decrypted_username,
                    "token": decrypted_token,
                    "expires_at": expires_at
                }
            except Exception as e:
                logger.warning(f"解密 refresh token 失败: {e}")
                return None

    def revoke_refresh_token(self, token: str):
        """撤销 refresh token"""
        encrypted_token = self.encryptor.encrypt(token)

        with self._get_connection() as conn:
            conn.execute("UPDATE refresh_tokens SET is_revoked = 1 WHERE token = ?", (encrypted_token,))
            conn.commit()
            logger.debug(f"撤销 refresh token")

    def revoke_all_refresh_tokens(self, username: str):
        """撤销用户的所有 refresh tokens"""
        encrypted_username = self.encryptor.encrypt(username)

        with self._get_connection() as conn:
            # 找到该用户的所有 refresh tokens
            rows = conn.execute("SELECT id, username FROM refresh_tokens").fetchall()
            for row in rows:
                try:
                    decrypted_username = self.encryptor.decrypt(row["username"])
                    if decrypted_username == username:
                        conn.execute("UPDATE refresh_tokens SET is_revoked = 1 WHERE id = ?", (row["id"],))
                except Exception:
                    continue
            conn.commit()
            logger.info(f"撤销用户的所有 refresh tokens: {username}")

    def cleanup_expired_refresh_tokens(self):
        """清理过期的 refresh tokens"""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT id, expires_at FROM refresh_tokens WHERE is_revoked = 0").fetchall()
            now = datetime.now()
            for row in rows:
                expires_at = datetime.fromisoformat(row["expires_at"])
                if now > expires_at:
                    conn.execute("DELETE FROM refresh_tokens WHERE id = ?", (row["id"],))
            conn.commit()
            logger.debug("清理过期的 refresh tokens")

    def get_all_users(self) -> List[dict]:
        """获取所有用户（解密敏感字段）"""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
            users = []
            for row in rows:
                try:
                    users.append({
                        "username": self.encryptor.decrypt(row["username"]),
                        "hashed_password": self.encryptor.decrypt(row["hashed_password"]),
                        "is_admin": bool(row["is_admin"]),
                        "is_disabled": bool(row["is_disabled"]),
                        "created_at": row["created_at"]
                    })
                except Exception as e:
                    logger.warning(f"获取用户列表时解密失败: {str(e)}")
                    continue
            return users

    def get_all_usernames(self) -> List[str]:
        """获取所有用户名（解密）"""
        with self._get_connection() as conn:
            rows = conn.execute("SELECT username FROM users").fetchall()
            usernames = []
            for row in rows:
                try:
                    usernames.append(self.encryptor.decrypt(row["username"]))
                except Exception as e:
                    logger.warning(f"获取用户名列表时解密失败: {str(e)}")
                    continue
            return usernames

    def user_count(self) -> int:
        """获取用户总数"""
        with self._get_connection() as conn:
            result = conn.execute("SELECT COUNT(*) as count FROM users").fetchone()
            return result["count"]

    def get_created_at(self, username: str) -> Optional[datetime]:
        """获取用户创建时间"""
        user = self.get_user(username)
        return user["created_at"] if user else None


# 初始化用户数据库（持久化存储）
user_db = UserDB()

# ==================== WebSocket 客户端管理 ====================
clients: List[dict] = []  # 存储客户端信息
# ⚠️ 重要：聊天消息不持久化存储在服务器，仅实时广播给在线用户
# 所有用户断开后，聊天记录自动从内存清除，不留任何痕迹

# 消息存储（用于撤回和已读状态）
messages: Dict[str, dict] = {}  # {message_id: {sender, content, time, type, is_read}}

# 统计信息
stats = {
    "total_messages_sent": 0,
    "total_logins": 0,
    "total_registrations": 0
}

# 登录跟踪器
login_tracker = LoginAttemptTracker()
ip_rate_limiter = IPRateLimiter()
ws_connection_rate_limiter = WSConnectionRateLimiter()

# ==================== JWT Token 管理 ====================
ALGORITHM = "HS256"


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """创建 JWT access token"""
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)

    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict) -> str:
    """创建 JWT refresh token（更长的有效期）"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)
    to_encode.update({"exp": expire, "type": "refresh", "jti": str(uuid.uuid4())})
    encoded_jwt = jwt.encode(to_encode, settings.secret_key, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """从 JWT token 获取当前用户"""
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="无效的认证凭据",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except jwt.ExpiredSignatureError:
        logger.warning("JWT Token签名过期")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="认证已过期，请重新登录",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        logger.warning("JWT Token无效")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证凭据",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except JWTError as e:
        logger.warning(f"JWT Token验证失败: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证凭据",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = user_db.get_user(username)
    if user is None:
        logger.warning(f"用户不存在: {username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证凭据",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 记录用户权限信息（调试）
    logger.debug(f"用户 {username} 登录 - is_admin: {user.get('is_admin')}, is_disabled: {user.get('is_disabled')}")

    # 检查用户是否被禁用
    if user_db.is_disabled(username):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="账户已被禁用"
        )

    # 返回用户信息，包含 is_admin
    return {
        "username": user["username"],
        "hashed_password": user["hashed_password"],
        "is_admin": user["is_admin"],
        "is_disabled": user["is_disabled"],
        "created_at": user["created_at"]
    }


# ==================== 健康检查和监控 ====================
@app.get("/health")
async def health_check():
    """健康检查接口"""
    return {
        "status": "healthy",
        "app_name": settings.app_name,
        "version": settings.app_version,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api/stats", response_model=StatsResponse)
async def get_stats(current_user: dict = Depends(get_current_user)):
    """获取统计信息（管理员）"""
    # 只有管理员可以查看统计信息
    if not current_user["is_admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="权限不足"
        )

    return StatsResponse(
        online_users=len(clients),
        total_messages_sent=stats["total_messages_sent"],
        total_users=user_db.user_count()
    )


@app.get("/api/public-key")
async def get_public_key():
    """获取 RSA 公钥（用于密钥交换）"""
    return {
        "public_key": public_key_pem.decode('utf-8'),
        "key_size": settings.rsa_key_size,
        "encryption_details": {
            "aes": "AES-256-CBC",
            "rsa": f"RSA-{settings.rsa_key_size}",
            "password_hash": "bcrypt"
        }
    }


# ==================== 用户认证 ====================
@app.get("/", response_class=HTMLResponse)
async def get_chat_page():
    """获取聊天页面"""
    index_file = os.path.join(frontend_dir, "index.html")
    with open(index_file, "r", encoding="utf-8") as f:
        return f.read()


@app.post("/register", response_model=dict)
@limiter.limit("5/minute")
async def register(user_data: UserRegister, request: Request):
    """
    用户注册
    - 密码强度检查
    - IP 频率限制
    - 用户名重复检查
    """
    logger.info(f"注册请求 - 用户名: {user_data.username}, IP: {get_remote_address(request)}")

    # 检查 IP 频率限制
    allowed, wait_time = ip_rate_limiter.check_rate_limit(get_remote_address(request))
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"请求过于频繁，请 {wait_time} 秒后重试"
        )

    # 检查用户名是否已存在
    if user_db.get_user(user_data.username):
        logger.warning(f"注册失败 - 用户名已存在: {user_data.username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="用户名已被注册"
        )

    # 密码强度验证
    is_valid, error_msg = PasswordValidator.validate(user_data.password, settings)
    if not is_valid:
        logger.warning(f"注册失败 - 密码强度不足: {user_data.username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg
        )

    # 哈希密码（使用 bcrypt）
    hashed_password = PasswordHasher.hash_password(user_data.password)

    # 添加用户
    user_db.add_user(user_data.username, hashed_password)

    stats["total_registrations"] += 1
    logger.info(f"注册成功: {user_data.username}")

    return {
        "username": user_data.username,
        "message": f"用户 '{user_data.username}' 注册成功"
    }


@app.post("/token", response_model=TokenResponse)
@limiter.limit("30/minute")
async def login(request: Request):
    """
    用户登录
    - 登录失败次数限制
    - IP 频率限制
    - 支持 JSON 和表单数据两种格式
    - 支持密码加密传输（RSA 加密）
    """
    ip = get_remote_address(request)
    
    # 根据请求头解析数据
    content_type = request.headers.get("content-type", "")
    
    if "application/json" in content_type:
        # JSON 格式
        try:
            body = await request.json()
            username = body.get("username", "")
            password = body.get("password", "")
            encrypted_password = body.get("encrypted_password", "")
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid JSON data"
            )
    else:
        # 表单数据格式
        try:
            form_data = await request.form()
            username = form_data.get("username", "")
            password = form_data.get("password", "")
            encrypted_password = form_data.get("encrypted_password", "")
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Invalid form data"
            )
    
    # 如果提供了加密密码，则解密
    if encrypted_password:
        try:
            password = RSAEncryptor.decrypt(encrypted_password, private_key_pem.decode('utf-8'))
            logger.debug(f"使用加密密码登录 - 用户名: {username}")
            logger.debug(f"解密后的密码长度: {len(password)}")
        except Exception as e:
            logger.warning(f"密码解密失败: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="密码解密失败，请刷新页面重试"
            )
    
    # 验证数据
    if not username or not password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="用户名和密码不能为空"
        )

    logger.info(f"登录请求 - 用户名: {username}, IP: {ip}")

    # 检查IP锁定状态
    if login_tracker.is_ip_locked(ip):
        logger.warning(f"登录失败 - IP已锁定: {ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="您的IP已被暂时锁定，请稍后再试"
        )

    # 检查账户锁定状态（在密码验证之前检查，确保锁定后立即返回）
    is_locked, remaining = login_tracker.is_locked(username)
    if is_locked:
        logger.warning(f"登录失败 - 账户已锁定: {username}, 剩余时间: {remaining}分钟")
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"账户已被锁定，请 {remaining} 分钟后重试"
        )

    # 检查用户是否存在
    user = user_db.get_user(username)
    if not user:
        logger.warning(f"登录失败 - 用户不存在: {username}")
        login_tracker.record_attempt(username, ip, False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误"
        )

    # 检查用户是否被禁用
    if user_db.is_disabled(username):
        logger.warning(f"登录失败 - 用户已禁用: {username}")
        # 明确告知用户账户状态，不透露其他信息
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="账户已被禁用"
        )

    # 验证密码（使用 bcrypt）
    logger.debug(f"准备验证密码 - 用户名: {username}, 密码长度: {len(password)}")
    logger.debug(f"数据库中的哈希密码: {user['hashed_password'][:50]}...")
    if not PasswordHasher.verify_password(password, user["hashed_password"]):
        logger.warning(f"登录失败 - 密码错误: {username}")

        # 检查是否需要锁定账户（在记录失败尝试之前检查）
        can_login, lock_msg = login_tracker.check_and_lock(username, ip)

        # 记录失败尝试（必须在check_and_lock之后调用，否则会重复计算）
        login_tracker.record_attempt(username, ip, False)

        if not can_login:
            # 如果是首次锁定，需要重新获取剩余时间
            is_locked, remaining = login_tracker.is_locked(username)
            if is_locked and remaining:
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail=f"账户已被锁定，请 {remaining} 分钟后重试"
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail=lock_msg
                )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误"
        )

    # 登录成功
    login_tracker.record_attempt(username, ip, True)
    stats["total_logins"] += 1
    logger.info(f"登录成功: {username}")

    # 创建 tokens
    access_token = create_access_token(
        data={"sub": username}
    )
    refresh_token = create_refresh_token(
        data={"sub": username}
    )

    # 保存 refresh token 到数据库
    user_db.save_refresh_token(username, refresh_token)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        username=username
    )


@app.post("/api/auth/refresh", response_model=TokenResponse)
@limiter.limit("10/minute")
async def refresh_token(request: Request, refresh_request: RefreshTokenRequest):
    """
    刷新 access token
    使用 refresh token 获取新的 access token
    """
    ip = get_remote_address(request)
    logger.debug(f"刷新 token 请求 - IP: {ip}")

    # 验证 refresh token
    token_info = user_db.get_refresh_token(refresh_request.refresh_token)
    if not token_info:
        logger.warning(f"刷新 token 失败 - refresh token 无效或已过期: {ip}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的 refresh token"
        )

    username = token_info["username"]

    # 验证 JWT refresh token
    try:
        payload = jwt.decode(
            refresh_request.refresh_token,
            settings.secret_key,
            algorithms=[ALGORITHM]
        )
        if payload.get("type") != "refresh":
            logger.warning(f"刷新 token 失败 - token 类型错误: {username}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="无效的 refresh token"
            )
    except jwt.ExpiredSignatureError:
        logger.warning(f"刷新 token 失败 - refresh token 已过期: {username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="refresh token 已过期，请重新登录"
        )
    except jwt.InvalidTokenError:
        logger.warning(f"刷新 token 失败 - refresh token 无效: {username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的 refresh token"
        )

    # 检查用户是否被禁用
    if user_db.is_disabled(username):
        logger.warning(f"刷新 token 失败 - 用户已被禁用: {username}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="账户已被禁用"
        )

    # 创建新的 access token
    new_access_token = create_access_token(
        data={"sub": username}
    )

    # 可选：创建新的 refresh token（轮换 refresh token）
    # 撤销旧的 refresh token
    user_db.revoke_refresh_token(refresh_request.refresh_token)
    # 创建新的 refresh token
    new_refresh_token = create_refresh_token(
        data={"sub": username}
    )
    user_db.save_refresh_token(username, new_refresh_token)

    logger.info(f"刷新 token 成功: {username}")

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        username=username
    )


# ==================== 用户管理 API ====================
@app.get("/api/user/info", response_model=UserInfo)
async def get_user_info(current_user: dict = Depends(get_current_user)):
    """获取当前用户信息"""
    return UserInfo(
        username=current_user["username"],
        is_admin=current_user["is_admin"],
        created_at=current_user["created_at"].isoformat() if current_user["created_at"] else None
    )


@app.post("/api/user/change-password")
async def change_password(
    password_data: UserChangePassword,
    current_user: dict = Depends(get_current_user)
):
    """修改密码"""
    username = current_user["username"]

    # 验证旧密码
    if not PasswordHasher.verify_password(password_data.old_password, current_user["hashed_password"]):
        logger.warning(f"修改密码失败 - 旧密码错误: {username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="旧密码错误"
        )

    # 验证新密码强度
    is_valid, error_msg = PasswordValidator.validate(password_data.new_password, settings)
    if not is_valid:
        logger.warning(f"修改密码失败 - 新密码强度不足: {username}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg
        )

    # 哈希新密码
    new_hashed_password = PasswordHasher.hash_password(password_data.new_password)

    # 更新密码
    user_db.change_password(username, new_hashed_password)

    logger.info(f"密码修改成功: {username}")
    return {"message": "密码修改成功"}


# ==================== 管理员 API ====================
@app.get("/api/admin/users")
async def list_users(current_user: dict = Depends(get_current_user)):
    """获取所有用户列表（管理员）"""
    logger.info(f"获取用户列表请求 - 用户: {current_user['username']}, is_admin: {current_user['is_admin']}")
    if not current_user["is_admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="权限不足"
        )

    users = user_db.get_all_users()
    return {"users": users}


@app.post("/api/admin/disable-user/{username}")
async def disable_user(username: str, current_user: dict = Depends(get_current_user)):
    """禁用用户（管理员）"""
    if not current_user["is_admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="权限不足"
        )

    if not user_db.get_user(username):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    # 不能禁用自己
    if username == current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="不能禁用自己"
        )

    # 禁用用户
    user_db.disable_user(username, True)

    # 踢出该用户（如果在线）
    kicked = False
    for client in clients[:]:
        if client["username"] == username:
            try:
                await client["ws"].close(code=status.WS_1008_POLICY_VIOLATION, reason="账户已被管理员禁用")
                clients.remove(client)
                kicked = True
            except Exception as e:
                logger.debug(f"关闭WebSocket连接失败: {e}")
                pass

    if kicked:
        logger.warning(f"用户 {username} 已被禁用并踢出")
    else:
        logger.warning(f"用户 {username} 已被禁用")

    return {"message": f"用户 '{username}' 已被禁用"}


@app.post("/api/admin/enable-user/{username}")
async def enable_user(username: str, current_user: dict = Depends(get_current_user)):
    """启用用户（管理员）"""
    if not current_user["is_admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="权限不足"
        )

    if not user_db.get_user(username):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    user_db.disable_user(username, False)
    return {"message": f"用户 '{username}' 已被启用"}


@app.delete("/api/admin/user/{username}")
async def delete_user(username: str, current_user: dict = Depends(get_current_user)):
    """删除用户（管理员）"""
    if not current_user["is_admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="权限不足"
        )

    if not user_db.get_user(username):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不存在"
        )

    # 不能删除自己
    if username == current_user["username"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="不能删除自己"
        )

    user_db.delete_user(username)

    # 踢出该用户（如果在线）
    for client in clients[:]:
        if client["username"] == username:
            try:
                await client["ws"].close(code=status.WS_1008_POLICY_VIOLATION, reason="账户已被删除")
                clients.remove(client)
            except Exception as e:
                logger.debug(f"删除用户时断开连接失败: {str(e)}")

    return {"message": f"用户 '{username}' 已被删除"}


@app.post("/api/admin/kick/{username}")
async def kick_user(username: str, current_user: dict = Depends(get_current_user)):
    """踢出在线用户（管理员）"""
    if not current_user["is_admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="权限不足"
        )

    # 踢出该用户（如果在线）
    kicked = False
    for client in clients[:]:
        if client["username"] == username:
            try:
                await client["ws"].close(code=status.WS_1008_POLICY_VIOLATION, reason="已被管理员踢出")
                clients.remove(client)
                kicked = True
            except Exception as e:
                logger.debug(f"踢出用户时断开连接失败: {str(e)}")

    if not kicked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="用户不在线"
        )

    logger.warning(f"管理员踢出用户: {username} by {current_user['username']}")
    return {"message": f"用户 '{username}' 已被踢出"}


@app.post("/api/admin/announcement")
async def send_announcement(
    announcement: SystemAnnouncement,
    current_user: dict = Depends(get_current_user)
):
    """发送系统公告（管理员）"""
    logger.info(f"发送公告请求 - 用户: {current_user['username']}, is_admin: {current_user['is_admin']}, 公告: {announcement.message}")
    if not current_user["is_admin"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="权限不足"
        )

    # 广播系统公告
    for client in clients:
        try:
            encrypted_msg = AESEncryptor.encrypt(announcement.message, client["encryption_key"])
            await client["ws"].send_json({
                "type": "announcement",
                "message": encrypted_msg,
                "time": int(time.time()),
                "sender": "管理员"
            })
        except Exception as e:
            logger.debug(f"踢出用户时出错: {str(e)}")

    logger.info(f"系统公告发送: {announcement.message}")
    return {"message": "系统公告已发送"}


# ==================== WebSocket 聊天端点 ====================
@app.websocket("/ws")
async def chat(ws: WebSocket):
    """
    WebSocket 聊天端点
    - JWT 认证
    - Origin 验证
    - 消息加密
    - 消息撤回
    - 在线用户列表
    - 心跳检测
    """
    # 验证 Origin 头部
    origin = ws.headers.get("origin")
    if origin and "*" not in settings.ws_allowed_origins:
        if origin not in settings.ws_allowed_origins:
            logger.warning(f"WebSocket连接被拒绝 - Origin验证失败: {origin}")
            await ws.close(code=status.WS_1008_POLICY_VIOLATION, reason="Origin not allowed")
            return

    await ws.accept()

    client_info = None
    username = None

    try:
        # 第一步：接收认证信息
        auth_data = await ws.receive_json()
        token = auth_data.get("token")
        encryption_key = auth_data.get("encryption_key", settings.default_encryption_key)

        # 检查连接频率
        client_ip = ws.client.host
        if not ws_connection_rate_limiter.check_rate_limit(client_ip):
            await ws.close(code=status.WS_1008_POLICY_VIOLATION, reason="连接频率过高，请稍后再试")
            return

        # 验证 JWT token
        try:
            payload = jwt.decode(token, settings.secret_key, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if not username or not user_db.get_user(username):
                await ws.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid token")
                return
        except JWTError:
            await ws.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid token")
            return

        # 获取用户信息
        user = user_db.get_user(username)
        if not user:
            await ws.close(code=status.WS_1008_POLICY_VIOLATION, reason="用户不存在")
            return

        # 检查用户是否被禁用
        if user["is_disabled"]:
            await ws.close(code=status.WS_1008_POLICY_VIOLATION, reason="账户已被禁用")
            return

        # 检查账户是否被锁定
        is_locked, remaining = login_tracker.is_locked(username)
        if is_locked:
            logger.warning(f"WebSocket连接被拒绝 - 账户已锁定: {username}, 剩余: {remaining}分钟")
            await ws.close(code=status.WS_1008_POLICY_VIOLATION, reason=f"账户已被锁定，请{remaining}分钟后重试")
            return

        # 创建客户端信息
        client_id = f"{username}_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        client_info = {
            "ws": ws,
            "username": username,
            "client_id": client_id,
            "encryption_key": encryption_key,
            "connected_at": int(time.time())
        }
        clients.append(client_info)

        logger.info(f"用户连接: {username} (客户端ID: {client_id})")

        # 发送连接成功消息
        await ws.send_json({
            "type": "connected",
            "message": f"欢迎 {username}！",
            "time": int(time.time()),
            "is_admin": user["is_admin"]
        })

        # 通知其他用户
        system_msg = f"用户 {username} 已加入聊天"
        encrypted_system_msg = AESEncryptor.encrypt(system_msg, encryption_key)
        for client in clients:
            if client["ws"] != ws:
                try:
                    await client["ws"].send_json({
                        "type": "system",
                        "message": encrypted_system_msg,
                        "time": int(time.time()),
                        "sender": "系统"
                    })
                except Exception as e:
                    logger.debug(f"发送系统消息失败: {e}")
                    pass

        # 发送在线用户列表
        await broadcast_online_users()

        # 消息处理循环
        while True:
            data = await ws.receive_json()

            # 心跳检测
            if data.get("type") == "heartbeat":
                await ws.send_json({"type": "heartbeat", "time": int(time.time())})
                continue

            # 消息撤回
            if data.get("type") == "recall":
                message_id = data.get("message_id")
                if message_id in messages:
                    # 检查是否是发送者
                    if messages[message_id]["sender"] != username:
                        await ws.send_json({
                            "type": "error",
                            "message": "只能撤回自己的消息"
                        })
                        continue

                    # 检查是否在撤回时间限制内
                    message_time = messages[message_id]["time"]
                    if time.time() - message_time > settings.message_recall_minutes * 60:
                        await ws.send_json({
                            "type": "error",
                            "message": f"消息发送超过 {settings.message_recall_minutes} 分钟，无法撤回"
                        })
                        continue

                    # 撤回消息
                    messages[message_id]["type"] = "recall"
                    messages[message_id]["content"] = "[消息已撤回]"

                    # 广播撤回通知
                    for client in clients:
                        try:
                            await client["ws"].send_json({
                                "type": "recall",
                                "message_id": message_id,
                                "time": int(time.time())
                            })
                        except Exception as e:
                            logger.debug(f"发送撤回通知失败: {e}")
                            pass

                    logger.info(f"消息撤回: {message_id} by {username}")
                continue

            # 处理聊天消息
            message_content = data.get("message", "")

            # 解密消息
            try:
                decrypted_msg = AESEncryptor.decrypt(message_content, encryption_key)
            except Exception as e:
                await ws.send_json({
                    "type": "error",
                    "message": "消息解密失败，请检查加密密钥"
                })
                continue

            # 检查消息长度
            if len(decrypted_msg) > settings.max_message_length:
                await ws.send_json({
                    "type": "error",
                    "message": f"消息长度不能超过 {settings.max_message_length} 个字符"
                })
                continue

            # 生成消息ID
            message_id = f"{username}_{int(time.time())}_{uuid.uuid4().hex[:8]}"

            # 存储消息
            messages[message_id] = {
                "id": message_id,
                "sender": username,
                "content": decrypted_msg,
                "time": int(time.time()),
                "type": "message",
                "is_read": False
            }

            # 加密消息（使用 CBC 模式与前端兼容）
            encrypted_msg = AESEncryptor.encrypt(decrypted_msg, encryption_key)

            # 广播消息
            user = user_db.get_user(username)
            is_user_admin = user["is_admin"] if user else False
            for client in clients:
                try:
                    is_sender = client["username"] == username
                    await client["ws"].send_json({
                        "type": "message",
                        "message_id": message_id,
                        "message": encrypted_msg,
                        "sender": username,
                        "time": int(time.time()),
                        "is_sender": is_sender,
                        "is_admin": is_user_admin
                    })
                except Exception as e:
                    # 如果发送失败，移除该客户端
                    if client in clients:
                        clients.remove(client)

            stats["total_messages_sent"] += 1
            logger.debug(f"消息发送: {username} -> {len(clients)} 个客户端")

    except WebSocketDisconnect:
        logger.info(f"用户断开连接: {username}")
    except Exception as e:
        logger.error(f"WebSocket 错误: {username} - {str(e)}")
    finally:
        # 清理客户端
        if client_info and client_info in clients:
            clients.remove(client_info)

        # 通知其他用户
        if username:
            system_msg = f"用户 {username} 已离开聊天"
            for client in clients:
                try:
                    # 使用每个用户自己的加密密钥来加密系统消息（CBC 模式）
                    encrypted_system_msg = AESEncryptor.encrypt(system_msg, client["encryption_key"])
                    await client["ws"].send_json({
                        "type": "system",
                        "message": encrypted_system_msg,
                        "time": int(time.time()),
                        "sender": "系统"
                    })
                except Exception as e:
                    logger.debug(f"发送断开连接通知失败: {e}")
                    pass

            # 发送在线用户列表
            await broadcast_online_users()

            # 如果所有用户都已离开，清空消息和统计
            if not clients:
                messages.clear()
                logger.info("所有用户已离开，消息已清除")


async def broadcast_online_users():
    """广播在线用户列表"""
    online_users = []
    for client in clients:
        user = user_db.get_user(client["username"])
        if user:
            online_users.append({
                "username": client["username"],
                "is_admin": user["is_admin"],
                "connected_at": client["connected_at"]
            })

    for client in clients:
        try:
            await client["ws"].send_json({
                "type": "online_users",
                "users": online_users,
                "count": len(online_users)
            })
        except Exception as e:
            logger.debug(f"踢出用户时出错: {str(e)}")


# ==================== 启动事件 ====================
@app.on_event("startup")
async def startup_event():
    """应用启动时的初始化"""
    logger.info("=" * 50)
    logger.info(f"{settings.app_name} {settings.app_version} 启动成功")
    logger.info(f"环境: {settings.environment}")
    logger.info(f"监听地址: {settings.host}:{settings.port}")
    logger.info(f"RSA 密钥: {settings.rsa_key_size} 位")
    logger.info(f"密码强度要求: 最小 {settings.min_password_length} 位，必须包含大小写字母、数字、特殊字符")
    logger.info(f"登录限制: {settings.max_login_attempts} 次失败后锁定 {settings.login_lock_minutes} 分钟")
    logger.info(f"消息撤回: {settings.message_recall_minutes} 分钟内可撤回")
    logger.info("=" * 50)


@app.on_event("shutdown")
async def shutdown_event():
    """应用关闭时的清理"""
    logger.info("应用正在关闭...")
    # 关闭所有 WebSocket 连接
    for client in clients[:]:
        try:
            await client["ws"].close()
        except Exception as e:
            logger.debug(f"踢出用户时出错: {str(e)}")
    logger.info("应用已关闭")
