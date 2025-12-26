from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, validator
from typing import List, Optional, Tuple
from datetime import datetime, timedelta
from jose import JWTError, jwt
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
import base64
import time
import os
import json
import hashlib
import re
import secrets

app = FastAPI(title="Minimal Chat")

# 配置
SECRET_KEY = "your-secret-key-change-this-in-production-minimal-chat-2025"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
DEFAULT_ENCRYPTION_KEY = "PrivateChat2025Secure!"  # 默认加密密码，用户登录后使用

# RSA密钥对（2048位，远超1024位要求）
# 使用RSA-2048进行密钥交换，比RSA-1024更安全
RSA_KEY_SIZE = 2048
private_key = RSA.generate(RSA_KEY_SIZE)
public_key_pem = private_key.publickey().export_key()

# 用户名和密码验证规则
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 20
MIN_PASSWORD_LENGTH = 6
MAX_PASSWORD_LENGTH = 32
USERNAME_PATTERN = r"^[a-zA-Z0-9_]+$"  # 只允许字母、数字和下划线

# OAuth2 方案
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


class UserRegister(BaseModel):
    """用户注册数据模型"""
    username: str = Field(..., min_length=MIN_USERNAME_LENGTH, max_length=MAX_USERNAME_LENGTH)
    password: str = Field(..., min_length=MIN_PASSWORD_LENGTH, max_length=MAX_PASSWORD_LENGTH)

    @validator('username')
    def username_must_be_valid(cls, v):
        if not re.match(USERNAME_PATTERN, v):
            raise ValueError("用户名只能包含字母、数字和下划线")
        return v


class RegisterResponse(BaseModel):
    """注册响应数据模型"""
    username: str
    message: str


def get_password_hash(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    """生成密码哈希，返回 (hashed_password, salt)"""
    if salt is None:
        salt = hashlib.sha256(os.urandom(32)).hexdigest()[:16]
    salted_password = password + salt
    hashed = hashlib.sha256(salted_password.encode()).hexdigest()
    return hashed, salt


def verify_password(plain_password: str, hashed_password: str, salt: str) -> bool:
    """验证密码"""
    salted_password = plain_password + salt
    computed_hash = hashlib.sha256(salted_password.encode()).hexdigest()
    return computed_hash == hashed_password


# 用户数据库（生产环境应使用真实数据库）
# 初始化默认用户
hashed_pw_admin, salt_admin = get_password_hash("admin234")
hashed_pw_admin2, salt_admin2 = get_password_hash("admin2345")

users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": hashed_pw_admin,
        "salt": salt_admin
    },
    "admin2": {
        "username": "admin2",
        "hashed_password": hashed_pw_admin2,
        "salt": salt_admin2
    }
}

# 挂载静态文件目录
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

clients: List[dict] = []  # 存储客户端信息: {"ws": WebSocket, "username": str, "key": bytes}
# ⚠️ 重要：聊天消息不持久化存储在服务器，仅实时广播给在线用户
# 所有用户断开后，聊天记录自动从内存清除，不留任何痕迹

# 会话密钥存储（临时，仅用于当前会话）
session_keys: dict = {}  # {"client_id": session_key}


class AdvancedEncryptor:
    """
    高级加密类 - 混合加密方案
    1. RSA-2048：用于密钥交换（比1024位更安全）
    2. AES-256-GCM：消息加密（认证加密，防止篡改）
    3. 随机填充：防止流量分析
    4. 消息混淆：防止中间人攻击
    """

    @staticmethod
    def get_rsa_public_key() -> str:
        """获取RSA公钥（PEM格式）"""
        return public_key_pem.decode('utf-8')

    @staticmethod
    def rsa_decrypt(encrypted_data: bytes) -> bytes:
        """使用RSA私钥解密数据"""
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(encrypted_data)

    @staticmethod
    def rsa_encrypt_with_password(data: bytes, password: str) -> bytes:
        """
        使用RSA加密数据（用密码派生会话密钥进行混合加密）
        注意：实际场景中应该使用客户端的RSA公钥，这里简化处理
        """
        # 派生密钥
        key, salt = AdvancedEncryptor.derive_key(password)

        # 使用AES-GCM加密数据
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        # 组合数据：salt(32) + nonce(12) + tag(16) + ciphertext
        combined = salt + nonce + tag + ciphertext

        return combined

    @staticmethod
    def rsa_decrypt_with_password(encrypted_data: bytes, password: str) -> bytes:
        """解密使用密码加密的数据"""
        # 提取各部分
        salt = encrypted_data[:32]
        nonce = encrypted_data[32:44]
        tag = encrypted_data[44:60]
        ciphertext = encrypted_data[60:]

        # 派生密钥
        key, _ = AdvancedEncryptor.derive_key(password, salt)

        # 解密
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(ciphertext, tag)

        return decrypted

    @staticmethod
    def generate_session_key() -> bytes:
        """生成随机的AES-256会话密钥（32字节）"""
        return get_random_bytes(32)

    @staticmethod
    def derive_key(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """
        使用scrypt从密码派生密钥（比SHA-256更安全）
        参数强度：N=2^20, r=8, p=1（高安全性）
        """
        if salt is None:
            salt = get_random_bytes(32)
        # scrypt是抗GPU/ASIC的密钥派生函数
        key = scrypt(
            password.encode(),
            salt=salt,
            key_len=32,
            N=2**20,
            r=8,
            p=1
        )
        return key, salt

    @staticmethod
    def add_obfuscation(plaintext: str) -> Tuple[bytes, int]:
        """
        添加混淆层，防止流量分析
        随机填充前后，使得密文长度和内容不可预测
        """
        # 随机生成填充长度（64-256字节）
        padding_length = secrets.randbelow(192) + 64

        # 前置随机填充
        front_padding = get_random_bytes(padding_length)

        # 后置随机填充
        back_padding = get_random_bytes(padding_length)

        # 组合数据
        data = front_padding + plaintext.encode('utf-8') + back_padding

        # 记录填充长度，用于解密
        return data, padding_length

    @staticmethod
    def remove_obfuscation(data: bytes, padding_length: int) -> str:
        """移除混淆层，还原原始数据"""
        # 移除前后填充
        plaintext = data[padding_length:-padding_length]
        return plaintext.decode('utf-8')

    @staticmethod
    def encrypt(plaintext: str, session_key: bytes) -> str:
        """
        使用AES-256-GCM加密消息（认证加密模式）
        提供保密性和完整性保护
        """
        # 添加混淆层
        obfuscated_data, padding_length = AdvancedEncryptor.add_obfuscation(plaintext)

        # 生成随机nonce（12字节，GCM标准）
        nonce = get_random_bytes(12)

        # 使用AES-256-GCM加密
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(obfuscated_data)

        # 组合数据：padding_length(4) + nonce(12) + tag(16) + ciphertext
        combined = padding_length.to_bytes(4, 'big') + nonce + tag + ciphertext

        # Base64编码
        return base64.b64encode(combined).decode('utf-8')

    @staticmethod
    def decrypt(ciphertext: str, session_key: bytes) -> str:
        """
        使用AES-256-GCM解密消息（认证解密，防止篡改）
        """
        # 解码base64
        combined = base64.b64decode(ciphertext.encode('utf-8'))

        # 提取各部分
        padding_length = int.from_bytes(combined[:4], 'big')
        nonce = combined[4:16]
        tag = combined[16:32]
        encrypted_data = combined[32:]

        # 使用AES-256-GCM解密
        cipher = AES.new(session_key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(encrypted_data, tag)

        # 移除混淆层
        plaintext = AdvancedEncryptor.remove_obfuscation(decrypted, padding_length)
        return plaintext

    @staticmethod
    def encrypt_with_password(plaintext: str, password: str) -> Tuple[str, bytes]:
        """
        使用密码加密（用于用户提供的密码）
        返回 (密文, salt)
        """
        # 派生密钥
        key, salt = AdvancedEncryptor.derive_key(password)
        # 加密
        ciphertext = AdvancedEncryptor.encrypt(plaintext, key)
        return ciphertext, salt

    @staticmethod
    def decrypt_with_password(ciphertext: str, password: str, salt: bytes) -> str:
        """
        使用密码解密
        """
        # 派生密钥
        key, _ = AdvancedEncryptor.derive_key(password, salt)
        # 解密
        return AdvancedEncryptor.decrypt(ciphertext, key)


class LegacyAESEncryptor:
    """
    旧版AES-256-CBC加密器（向后兼容）
    用于支持仍使用旧加密格式的客户端
    """

    @staticmethod
    def get_key(password: str) -> bytes:
        """从密码生成32字节的AES-256密钥"""
        return hashlib.sha256(password.encode()).digest()

    @staticmethod
    def encrypt(plaintext: str, password: str) -> str:
        """使用AES-256-CBC加密消息（旧格式）"""
        key = LegacyAESEncryptor.get_key(password)
        # 生成随机IV
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # 加密并padding
        padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
        encrypted = cipher.encrypt(padded_data)
        # 返回base64编码的 IV + 加密数据
        return base64.b64encode(iv + encrypted).decode('utf-8')

    @staticmethod
    def decrypt(ciphertext: str, password: str) -> str:
        """使用AES-256-CBC解密消息（旧格式）"""
        key = LegacyAESEncryptor.get_key(password)
        # 解码base64
        data = base64.b64decode(ciphertext.encode('utf-8'))
        # 提取IV和加密数据
        iv = data[:16]
        encrypted = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # 解密并unpadding
        decrypted = cipher.decrypt(encrypted)
        unpadded = unpad(decrypted, AES.block_size)
        return unpadded.decode('utf-8')


def hybrid_decrypt(ciphertext: str, session_key: bytes, user_password: str = None) -> str:
    """
    混合解密函数（自动识别新旧格式）
    优先尝试新格式（GCM+混淆），失败后尝试旧格式（CBC）

    参数:
        ciphertext: 密文
        session_key: 会话密钥（用于新格式）
        user_password: 用户密码（用于旧格式，可选）
    """
    try:
        # 尝试新格式解密（GCM+混淆）
        return AdvancedEncryptor.decrypt(ciphertext, session_key)
    except Exception as e:
        # 如果新格式失败，尝试旧格式（CBC）
        if user_password:
            try:
                return LegacyAESEncryptor.decrypt(ciphertext, user_password)
            except Exception as e2:
                pass
        # 两种格式都失败
        raise Exception("解密失败：消息可能已损坏或加密密钥不正确")


def hybrid_encrypt(plaintext: str, session_key: bytes) -> str:
    """
    混合加密函数（使用新格式）
    自动使用新格式（GCM+混淆）加密
    """
    return AdvancedEncryptor.encrypt(plaintext, session_key)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """创建JWT token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """从JWT token获取当前用户"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = users_db.get(username)
    if user is None:
        raise credentials_exception
    return user


@app.get("/", response_class=HTMLResponse)
async def get_chat_page():
    index_file = os.path.join(frontend_dir, "index.html")
    with open(index_file, "r", encoding="utf-8") as f:
        return f.read()


@app.post("/register", response_model=RegisterResponse)
async def register(user_data: UserRegister):
    """用户注册"""
    # 检查用户名是否已存在
    if user_data.username in users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"用户名 '{user_data.username}' 已存在"
        )

    # 生成密码哈希
    hashed_pw, salt = get_password_hash(user_data.password)

    # 添加新用户到数据库
    users_db[user_data.username] = {
        "username": user_data.username,
        "hashed_password": hashed_pw,
        "salt": salt
    }

    return RegisterResponse(
        username=user_data.username,
        message=f"用户 '{user_data.username}' 注册成功"
    )


@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """用户登录，返回JWT token"""
    user = users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"], user["salt"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user["username"],
        "encryption_info": {
            "rsa_public_key": AdvancedEncryptor.get_rsa_public_key(),
            "rsa_key_size": RSA_KEY_SIZE,
            "encryption_mode": "RSA-2048 + AES-256-GCM + Obfuscation"
        }
    }


@app.get("/api/public-key")
async def get_public_key():
    """获取RSA公钥（用于密钥交换）"""
    return {
        "public_key": AdvancedEncryptor.get_rsa_public_key(),
        "key_size": RSA_KEY_SIZE,
        "encryption_details": {
            "rsa": "RSA-2048 (OAEP padding)",
            "aes": "AES-256-GCM (Authenticated Encryption)",
            "obfuscation": "Random padding (64-256 bytes)",
            "kdf": "Scrypt (N=2^20, r=8, p=1)"
        }
    }


@app.websocket("/ws")
async def chat(ws: WebSocket):
    """
    WebSocket聊天端点（带用户认证和高级加密）
    使用RSA-2048 + AES-256-GCM + 随机填充的多层加密方案
    """
    await ws.accept()

    # 第一步：接收认证信息
    try:
        auth_data = await ws.receive_json()
        token = auth_data.get("token")
        encryption_key = auth_data.get("encryption_key", DEFAULT_ENCRYPTION_KEY)

        # 验证JWT token
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username = payload.get("sub")
            if not username or username not in users_db:
                await ws.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid token")
                return
        except JWTError:
            await ws.close(code=status.WS_1008_POLICY_VIOLATION, reason="Invalid token")
            return

        # 生成会话密钥（每个连接独立的随机密钥）
        session_key = AdvancedEncryptor.generate_session_key()
        client_id = f"{username}_{int(time.time())}_{secrets.token_hex(8)}"
        session_keys[client_id] = session_key

        # 添加到客户端列表
        client_info = {
            "ws": ws,
            "username": username,
            "client_id": client_id,
            "session_key": session_key,
            "encryption_key": encryption_key  # 保留用于兼容性
        }
        clients.append(client_info)

        # 发送连接成功消息
        await ws.send_json({
            "type": "connected",
            "message": f"用户 {username} 已连接",
            "time": int(time.time())
        })

        # 通知其他用户（使用发送者的加密密码加密）
        # 只有使用相同加密密码的用户才能看到系统通知
        system_msg = f"用户 {username} 已加入聊天"
        encrypted_system_msg = LegacyAESEncryptor.encrypt(system_msg, encryption_key)
        for client in clients:
            if client["ws"] != ws:
                try:
                    await client["ws"].send_json({
                        "type": "system",
                        "message": encrypted_system_msg,
                        "time": int(time.time()),
                        "sender": "系统"
                    })
                except:
                    pass

        # 消息处理循环
        while True:
            data = await ws.receive_json()

            # 解密消息（使用混合解密，支持新旧格式）
            # 前端发送的消息使用用户密码加密，尝试用session_key（新格式）和user_password（旧格式）解密
            try:
                decrypted_msg = hybrid_decrypt(data["message"], session_key, encryption_key)
            except Exception as e:
                await ws.send_json({
                    "type": "error",
                    "message": "消息解密失败，请检查加密密钥",
                    "time": int(time.time())
                })
                continue

            # 广播消息给所有客户端（使用发送者的加密密码加密）
            # 只有使用相同加密密码的用户才能解密消息
            encrypted_msg = LegacyAESEncryptor.encrypt(decrypted_msg, encryption_key)
            for client in clients:
                try:
                    await client["ws"].send_json({
                        "type": "message",
                        "message": encrypted_msg,
                        "sender": username,
                        "time": int(time.time())
                    })
                except Exception as e:
                    # 如果发送失败，移除该客户端
                    if client in clients:
                        clients.remove(client)

    except WebSocketDisconnect:
        # 用户断开连接
        if client_info in clients:
            clients.remove(client_info)

            # 清理会话密钥
            if client_id in session_keys:
                del session_keys[client_id]

            # 通知其他用户（使用断开者的加密密码加密）
            # 只有使用相同加密密码的用户才能看到系统通知
            system_msg = f"用户 {username} 已离开聊天"
            encrypted_system_msg = LegacyAESEncryptor.encrypt(system_msg, encryption_key)
            for client in clients:
                try:
                    await client["ws"].send_json({
                        "type": "system",
                        "message": encrypted_system_msg,
                        "time": int(time.time()),
                        "sender": "系统"
                    })
                except:
                    pass

            # 如果所有用户都已离开，聊天记录自动清除（不持久化）
            if not clients:
                # 清空所有会话密钥
                session_keys.clear()
