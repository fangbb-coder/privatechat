"""
加密工具模块
提供 AES、RSA 加密解密功能

安全说明：
- 消息加密 (AESEncryptor)：AES-256-CBC，与前端 CryptoJS 兼容，KDF 使用 SHA-256（前端约定）
- 数据库字段加密 (DatabaseEncryptor)：AES-256-GCM，使用独立的 DB_ENCRYPTION_KEY（H2 密钥分离），
  KDF 使用 PBKDF2-SHA256（H1 强 KDF）
- RSA 解密 (RSAEncryptor)：统一错误路径与恒定时间处理，降低填充预言风险（H6）
"""
import base64
import hashlib
import hmac
import os
from typing import Tuple, Optional

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, PKCS1_v1_5
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from utils.logger import get_logger

logger = get_logger()

# 绝不向日志输出密钥/IV/明文（L1）
# 历史版本在 debug 日志中打印了 key.hex() / 明文，已全部移除。


class AESEncryptor:
    """AES-256-CBC 加密器（与前端 CryptoJS 兼容）。

    注意：为保持与前端 CryptoJS 的兼容性，密钥派生沿用 SHA-256(password)。
    这是前端约定，若需更强 KDF 需前后端同步迁移到 PBKDF2/scrypt。
    此处对消息加密保留该约定，但对数据库字段加密使用独立的强 KDF（见 DatabaseEncryptor）。
    """

    NONCE_SIZE = 12  # GCM 模式使用的 nonce 大小（保留以兼容）
    CBC_IV_SIZE = 16  # CBC 模式使用的 IV 大小
    GCM_TAG_SIZE = 16  # GCM 模式的认证标签大小

    @staticmethod
    def get_key(password: str) -> bytes:
        """从密码生成32字节的AES-256密钥（前端 CryptoJS 兼容）"""
        return hashlib.sha256(password.encode('utf-8')).digest()

    @staticmethod
    def encrypt(plaintext: str, password: str) -> str:
        """使用AES-256-CBC加密消息（与前端 CryptoJS 完全兼容）"""
        if not isinstance(plaintext, str):
            raise TypeError("plaintext 必须为 str")
        key = AESEncryptor.get_key(password)
        iv = get_random_bytes(AESEncryptor.CBC_IV_SIZE)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded)

        # 组合: IV + ciphertext
        combined = iv + ciphertext
        return base64.b64encode(combined).decode('utf-8')

    @staticmethod
    def decrypt(ciphertext: str, password: str) -> str:
        """使用AES-256-CBC解密消息（与前端 CryptoJS 完全兼容）"""
        if not isinstance(ciphertext, str) or not ciphertext:
            raise ValueError("ciphertext 不能为空")

        data = base64.b64decode(ciphertext.encode('utf-8'))
        if len(data) < AESEncryptor.CBC_IV_SIZE + AES.block_size:
            raise ValueError("密文长度不合法")

        key = AESEncryptor.get_key(password)
        # 前端 CBC 格式: IV(16字节) + ciphertext
        iv = data[:AESEncryptor.CBC_IV_SIZE]
        encrypted = data[AESEncryptor.CBC_IV_SIZE:]

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        unpadded = unpad(decrypted, AES.block_size)
        return unpadded.decode('utf-8')


class RSAKeyManager:
    """RSA 密钥管理器 - 支持密钥持久化"""

    def __init__(self, keys_dir: str = "./keys", key_size: int = 2048):
        self.keys_dir = keys_dir
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
        os.makedirs(keys_dir, exist_ok=True)

    def generate_keys(self) -> Tuple[bytes, bytes]:
        """生成 RSA 密钥对"""
        private_key = RSA.generate(self.key_size)
        public_key = private_key.publickey()
        return (
            private_key.export_key(),
            public_key.export_key()
        )

    def save_keys(self, private_key: bytes, public_key: bytes):
        """保存密钥对到文件"""
        private_path = os.path.join(self.keys_dir, "private.pem")
        public_path = os.path.join(self.keys_dir, "public.pem")

        # 私钥文件设置 0600 权限
        fd = os.open(private_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(private_key)

        with open(public_path, "wb") as f:
            f.write(public_key)

    def load_keys(self) -> Tuple[bytes, bytes]:
        """从文件加载密钥对"""
        private_path = os.path.join(self.keys_dir, "private.pem")
        public_path = os.path.join(self.keys_dir, "public.pem")

        with open(private_path, "rb") as f:
            private_key = f.read()

        with open(public_path, "rb") as f:
            public_key = f.read()

        return private_key, public_key

    def load_or_generate(self) -> Tuple[bytes, bytes]:
        """加载或生成密钥对"""
        private_path = os.path.join(self.keys_dir, "private.pem")

        if os.path.exists(private_path):
            private_key, public_key = self.load_keys()
        else:
            private_key, public_key = self.generate_keys()
            self.save_keys(private_key, public_key)

        self.private_key = RSA.import_key(private_key)
        self.public_key = self.private_key.publickey()

        return private_key, public_key

    def get_public_key_pem(self) -> str:
        """获取公钥 PEM 字符串"""
        if self.public_key:
            return self.public_key.export_key().decode('utf-8')
        return ""


class PasswordHasher:
    """密码哈希器（使用 bcrypt）"""

    @staticmethod
    def hash_password(password: str) -> str:
        """哈希密码"""
        import bcrypt
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed.decode('utf-8')

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """验证密码（恒定时间比较，避免时序泄露）"""
        import bcrypt
        if not plain_password or not hashed_password:
            return False
        try:
            return bcrypt.checkpw(
                plain_password.encode('utf-8'),
                hashed_password.encode('utf-8')
            )
        except (ValueError, TypeError) as e:
            # 仅记录类型，不记录密码
            logger.warning(f"密码验证失败: {type(e).__name__}")
            return False
        except Exception as e:
            logger.warning(f"密码验证异常: {type(e).__name__}")
            return False


class PasswordValidator:
    """密码强度验证器"""

    @staticmethod
    def validate(password: str, settings) -> Tuple[bool, str]:
        """
        验证密码强度

        返回: (是否通过, 错误信息)
        """
        if not password:
            return False, "密码不能为空"

        # 检查长度
        if len(password) < settings.min_password_length:
            return False, f"密码长度不能少于 {settings.min_password_length} 个字符"

        if len(password) > settings.max_password_length:
            return False, f"密码长度不能超过 {settings.max_password_length} 个字符"

        # 检查大写字母
        if settings.password_require_uppercase:
            if not any(c.isupper() for c in password):
                return False, "密码必须包含至少一个大写字母"

        # 检查小写字母
        if settings.password_require_lowercase:
            if not any(c.islower() for c in password):
                return False, "密码必须包含至少一个小写字母"

        # 检查数字
        if settings.password_require_digits:
            if not any(c.isdigit() for c in password):
                return False, "密码必须包含至少一个数字"

        # 检查特殊字符
        if settings.password_require_special:
            special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
            if not any(c in special_chars for c in password):
                return False, "密码必须包含至少一个特殊字符 (!@#$%^&*()_+-=[]{}|;:,.<>?)"

        return True, ""


class RSAEncryptor:
    """RSA 加密器 - 用于加密敏感数据（如登录密码）

    安全说明（H6）：
    - 解密统一返回 ValueError，不区分"填充错误/格式错误/解码错误"，
      降低 Bleichenbacher 填充预言攻击的可区分性。
    - PKCS1_v1_5 解密使用随机 sentinel 而非固定值，避免通过 sentinel 判断成败。
    """

    @staticmethod
    def encrypt(plaintext: str, public_key_pem: str) -> str:
        """
        使用 RSA 公钥加密数据（OAEP）
        """
        if not isinstance(plaintext, str):
            raise TypeError("plaintext 必须为 str")
        public_key = RSA.import_key(public_key_pem)
        cipher = PKCS1_OAEP.new(public_key)
        encrypted = cipher.encrypt(plaintext.encode('utf-8'))
        return base64.b64encode(encrypted).decode('utf-8')

    @staticmethod
    def decrypt(ciphertext: str, private_key_pem: str) -> str:
        """
        使用 RSA 私钥解密数据（支持 PKCS#1 v1.5 和 OAEP 两种格式）

        统一在失败时抛出 ValueError（不泄露具体失败阶段），降低填充预言风险。
        """
        if not isinstance(ciphertext, str) or not ciphertext:
            raise ValueError("RSA 解密失败: 输入为空")

        try:
            private_key = RSA.import_key(private_key_pem)
            encrypted_data = base64.b64decode(ciphertext.encode('utf-8'))
        except Exception:
            # 统一错误，不区分 base64 解码失败 / 密钥导入失败
            raise ValueError("RSA 解密失败")

        # 先尝试 PKCS#1 v1.5（JSEncrypt 默认格式），使用随机 sentinel
        try:
            sentinel = get_random_bytes(32)  # 随机 sentinel，避免固定值被探测
            cipher = PKCS1_v1_5.new(private_key)
            decrypted = cipher.decrypt(encrypted_data, sentinel)
            # 若返回 sentinel，说明解密失败 -> 统一走错误路径
            if decrypted is not sentinel and len(decrypted) > 0:
                # 尝试 utf-8 解码
                try:
                    return decrypted.decode('utf-8')
                except UnicodeDecodeError:
                    pass  # 继续尝试 OAEP
        except Exception:
            pass  # 静默，统一错误

        # 回退 OAEP
        try:
            cipher = PKCS1_OAEP.new(private_key)
            decrypted = cipher.decrypt(encrypted_data)
            return decrypted.decode('utf-8')
        except Exception:
            raise ValueError("RSA 解密失败")


class DatabaseEncryptor:
    """数据库字段加密器 - 使用 AES-256-GCM 加密敏感字段

    安全增强（H1 + H2）：
    - 使用独立的 DB_ENCRYPTION_KEY（与 JWT secret_key 分离）
    - 密钥派生使用 PBKDF2-SHA256（高迭代次数 + 固定盐），而非裸 SHA-256
    - 额外存储 HMAC 哈希列用于等值查询（M3 缓解方案在 UserDB 中使用）
    """

    # PBKDF2 参数
    _PBKDF2_ITERATIONS = 200_000
    _SALT = b"private_chat_db_field_v1"  # 固定盐（用于派生稳定的 DB 密钥，便于查询一致性）
    _NONCE_SIZE = 12
    _TAG_SIZE = 16

    def __init__(self, encryption_key: str = None):
        """
        初始化加密器

        Args:
            encryption_key: 加密密钥，如果为 None 则使用配置中的 DB_ENCRYPTION_KEY
        """
        from utils.config import settings
        # H2: 使用独立的 db_encryption_key，而非 JWT 的 secret_key
        self.key = encryption_key or settings.db_encryption_key
        # H1: PBKDF2 派生固定长度的 AES 密钥（固定盐保证同一密钥派生结果一致，
        # 从而加密/解密可逆；盐本身无需保密，仅防止预计算彩虹表跨应用复用）
        self.aes_key = hashlib.pbkdf2_hmac(
            'sha256',
            self.key.encode('utf-8'),
            self._SALT,
            self._PBKDF2_ITERATIONS,
            dklen=32,
        )

    def encrypt(self, plaintext: str) -> str:
        """加密明文，返回 base64 字符串"""
        if plaintext is None:
            return None
        if not isinstance(plaintext, str):
            plaintext = str(plaintext)

        # 生成随机 nonce
        nonce = get_random_bytes(self._NONCE_SIZE)

        # 创建 AES-GCM 加密器
        cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=nonce)

        # 加密数据
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))

        # 组合: nonce + tag + ciphertext
        combined = nonce + tag + ciphertext

        # Base64 编码
        return base64.b64encode(combined).decode('utf-8')

    def decrypt(self, ciphertext: str) -> str:
        """解密密文，失败抛出 ValueError"""
        if ciphertext is None:
            return None
        if not isinstance(ciphertext, str) or not ciphertext:
            raise ValueError("解密失败: 输入为空")

        try:
            # Base64 解码
            data = base64.b64decode(ciphertext.encode('utf-8'))

            if len(data) < self._NONCE_SIZE + self._TAG_SIZE:
                raise ValueError("解密失败: 数据长度不合法")

            # 提取 nonce、tag、ciphertext
            nonce = data[:self._NONCE_SIZE]
            tag = data[self._NONCE_SIZE:self._NONCE_SIZE + self._TAG_SIZE]
            encrypted_data = data[self._NONCE_SIZE + self._TAG_SIZE:]

            # 创建 AES-GCM 解密器
            cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=nonce)

            # 解密数据（解密失败会抛出 ValueError/MAC 校验失败）
            decrypted = cipher.decrypt_and_verify(encrypted_data, tag)

            return decrypted.decode('utf-8')

        except ValueError:
            raise
        except Exception as e:
            # 统一错误信息，不暴露内部细节
            raise ValueError(f"解密失败")

    @staticmethod
    def username_hmac(username: str) -> str:
        """生成用户名的 HMAC 哈希，用于数据库等值查询（M3 缓解）

        返回 hex 字符串。同一密钥下结果稳定，不可逆推原用户名。
        """
        from utils.config import settings
        return hmac.new(
            settings.db_encryption_key.encode('utf-8'),
            username.encode('utf-8'),
            hashlib.sha256,
        ).hexdigest()
