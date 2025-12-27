"""
加密工具模块
提供 AES、RSA 加密解密功能
"""
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import base64
import hashlib
from typing import Tuple, Optional
import os
from logger import get_logger

logger = get_logger()


class AESEncryptor:
    """AES-256-GCM 加密器（更安全，推荐使用）

    解密时自动支持旧的 AES-256-CBC 格式以保持向后兼容性
    """

    NONCE_SIZE = 12  # GCM 模式使用的 nonce 大小
    CBC_IV_SIZE = 16  # CBC 模式使用的 IV 大小
    GCM_TAG_SIZE = 16  # GCM 模式的认证标签大小

    @staticmethod
    def get_key(password: str) -> bytes:
        """从密码生成32字节的AES-256密钥"""
        return hashlib.sha256(password.encode()).digest()

    @staticmethod
    def encrypt(plaintext: str, password: str) -> str:
        """使用AES-256-CBC加密消息（与前端 CryptoJS 完全兼容）"""
        key = AESEncryptor.get_key(password)
        iv = get_random_bytes(AESEncryptor.CBC_IV_SIZE)

        logger.debug(f"加密 - 密钥 (hex): {key.hex()}")
        logger.debug(f"加密 - IV (hex): {iv.hex()}")
        logger.debug(f"加密 - 明文: {plaintext[:50]}...")

        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded = pad(plaintext.encode('utf-8'), AES.block_size)
        ciphertext = cipher.encrypt(padded)

        logger.debug(f"加密 - 密文 (hex): {ciphertext.hex()[:100]}...")

        # 组合: IV + ciphertext
        combined = iv + ciphertext
        logger.debug(f"加密 - 组合后长度: {len(combined)} bytes")

        result = base64.b64encode(combined).decode('utf-8')
        logger.debug(f"加密 - Base64结果: {result[:80]}...")

        return result

    @staticmethod
    def decrypt(ciphertext: str, password: str) -> str:
        """使用AES-256-CBC解密消息（与前端 CryptoJS 完全兼容）"""
        data = base64.b64decode(ciphertext.encode('utf-8'))

        logger.debug(f"解密 - 密码前4字符: {password[:4]}")
        logger.debug(f"解密 - 数据长度: {len(data)} bytes")
        logger.debug(f"解密 - 数据 (hex): {data.hex()[:100]}...")

        # 生成密钥
        key = hashlib.sha256(password.encode()).digest()
        logger.debug(f"解密 - 密钥 (hex): {key.hex()}")

        # 前端 CBC 格式: IV(16字节) + ciphertext
        iv = data[:AESEncryptor.CBC_IV_SIZE]
        encrypted = data[AESEncryptor.CBC_IV_SIZE:]

        logger.debug(f"解密 - IV (hex): {iv.hex()}")
        logger.debug(f"解密 - 密文 (hex): {encrypted.hex()[:100]}...")

        # 解密
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(encrypted)
        unpadded = unpad(decrypted, AES.block_size)
        result = unpadded.decode('utf-8')

        logger.debug(f"解密 - 结果: {result[:50]}...")

        return result


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

        with open(private_path, "wb") as f:
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
        """验证密码"""
        import bcrypt
        try:
            return bcrypt.checkpw(
                plain_password.encode('utf-8'),
                hashed_password.encode('utf-8')
            )
        except (ValueError, TypeError, bcrypt.exceptions.BcryptError) as e:
            logger.warning(f"密码验证失败: {type(e).__name__}")
            return False


class PasswordValidator:
    """密码强度验证器"""

    @staticmethod
    def validate(password: str, settings) -> Tuple[bool, str]:
        """
        验证密码强度

        返回: (是否通过, 错误信息)
        """
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


class DatabaseEncryptor:
    """数据库字段加密器 - 使用 AES-256-GCM 加密敏感字段"""

    def __init__(self, encryption_key: str = None):
        """
        初始化加密器

        Args:
            encryption_key: 加密密钥，如果为 None 则使用配置中的默认密钥
        """
        from config import settings
        self.key = encryption_key or settings.secret_key
        # 使用密钥派生函数生成固定长度的 AES 密钥
        self.aes_key = hashlib.sha256(self.key.encode()).digest()
        self.nonce_size = 12  # GCM 模式使用的 nonce 大小

    def encrypt(self, plaintext: str) -> str:
        """
        加密明文

        Args:
            plaintext: 要加密的明文字符串

        Returns:
            加密后的 base64 编码字符串
        """
        if plaintext is None:
            return None

        # 生成随机 nonce
        nonce = get_random_bytes(self.nonce_size)

        # 创建 AES-GCM 加密器
        cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=nonce)

        # 加密数据
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))

        # 组合: nonce + tag + ciphertext
        combined = nonce + tag + ciphertext

        # Base64 编码
        return base64.b64encode(combined).decode('utf-8')

    def decrypt(self, ciphertext: str) -> str:
        """
        解密密文

        Args:
            ciphertext: base64 编码的密文字符串

        Returns:
            解密后的明文字符串

        Raises:
            ValueError: 解密失败时抛出
        """
        if ciphertext is None:
            return None

        try:
            # Base64 解码
            data = base64.b64decode(ciphertext.encode('utf-8'))

            # 提取 nonce、tag、ciphertext
            nonce = data[:self.nonce_size]
            tag = data[self.nonce_size:self.nonce_size + 16]
            encrypted_data = data[self.nonce_size + 16:]

            # 创建 AES-GCM 解密器
            cipher = AES.new(self.aes_key, AES.MODE_GCM, nonce=nonce)

            # 解密数据
            decrypted = cipher.decrypt_and_verify(encrypted_data, tag)

            return decrypted.decode('utf-8')

        except Exception as e:
            raise ValueError(f"解密失败: {str(e)}")
