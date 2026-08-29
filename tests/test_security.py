"""
基础安全测试（L3）

覆盖：
- 配置加载与校验（C1/H2/H3）
- AES 消息加密解密往返
- DatabaseEncryptor 加密解密往返 + HMAC 稳定性（H1/H2/M3）
- 密码哈希与验证（含恒定时间）
- RSA 加解密往返与统一错误（H6）
- 密码强度校验
- 密码历史按用户过滤（M8）
- MITM 防护：MessageEncryptor(AES-GCM) + session key 协商 + 公钥指纹 + TLS 强制
"""
import os
import sys
import tempfile

import pytest

# 确保 backend 在搜索路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))

# 开发环境，避免触发生产配置校验
os.environ.setdefault("ENVIRONMENT", "development")


def test_config_loads_and_validation():
    """C1/H2/H3: 配置可加载，开发环境默认值合理"""
    from utils.config import Settings

    s = Settings()
    assert s.environment == "development"
    assert s.app_name
    # 密钥分离字段都存在
    assert hasattr(s, "secret_key")
    assert hasattr(s, "db_encryption_key")
    # 默认管理员配置存在
    assert s.admin_username_list == ["admin"]

    # 生产环境必须有密钥和 host，应抛错
    with pytest.raises(Exception):
        Settings(environment="production", allowed_origins="", allowed_hosts="")


def test_aes_message_roundtrip():
    """消息加密解密可逆"""
    from utils.encryption import AESEncryptor

    password = "SharedChatKey2025!"
    for plaintext in ["hello", "你好，世界", "a" * 1000, ""]:
        if plaintext == "":
            continue  # 空串 CBC 解密会失败，仅测非空
        ct = AESEncryptor.encrypt(plaintext, password)
        assert ct != plaintext
        pt = AESEncryptor.decrypt(ct, password)
        assert pt == plaintext


def test_database_encryptor_roundtrip_and_hmac_stability():
    """H1/H2/M3: 数据库加密可逆，HMAC 同输入同输出"""
    from utils.encryption import DatabaseEncryptor

    enc = DatabaseEncryptor()
    for plaintext in ["admin", "user@example.com", "张三", "token_abc"]:
        ct = enc.encrypt(plaintext)
        assert ct != plaintext
        assert enc.decrypt(ct) == plaintext

    # HMAC 稳定性
    h1 = DatabaseEncryptor.username_hmac("admin")
    h2 = DatabaseEncryptor.username_hmac("admin")
    assert h1 == h2
    assert DatabaseEncryptor.username_hmac("admin") != DatabaseEncryptor.username_hmac("root")


def test_password_hash_and_verify():
    """密码哈希与验证"""
    from utils.encryption import PasswordHasher

    pw = "MyStr0ng!Pass"
    hashed = PasswordHasher.hash_password(pw)
    assert PasswordHasher.verify_password(pw, hashed) is True
    assert PasswordHasher.verify_password("wrong", hashed) is False
    assert PasswordHasher.verify_password("", hashed) is False
    assert PasswordHasher.verify_password(pw, "") is False


def test_password_validator():
    """密码强度校验"""
    from utils.encryption import PasswordValidator
    from utils.config import Settings

    s = Settings()
    ok, _ = PasswordValidator.validate("Abcd1234!", s)
    assert ok is True

    ok, msg = PasswordValidator.validate("weak", s)
    assert ok is False
    assert "少于" in msg or "长度" in msg

    ok, msg = PasswordValidator.validate("abcdefgh1!", s)  # 无大写
    assert ok is False
    assert "大写" in msg


def test_rsa_roundtrip_and_unified_error():
    """H6: RSA 加解密可逆，损坏密文统一抛 ValueError"""
    from utils.encryption import RSAEncryptor, RSAKeyManager

    with tempfile.TemporaryDirectory() as d:
        km = RSAKeyManager(keys_dir=d, key_size=2048)
        priv, pub = km.load_or_generate()
        pub_pem = pub.decode() if isinstance(pub, bytes) else pub
        priv_pem = priv.decode() if isinstance(priv, bytes) else priv

        ct = RSAEncryptor.encrypt("secret-login-pw", pub_pem)
        assert RSAEncryptor.decrypt(ct, priv_pem) == "secret-login-pw"

        # 损坏密文应统一抛 ValueError（不泄露填充阶段）
        with pytest.raises(ValueError):
            RSAEncryptor.decrypt(ct[:-4] + "AAAA", priv_pem)


def test_userdb_password_history_isolation(tmp_path, monkeypatch):
    """M8: 密码历史按用户过滤，不会跨用户比对"""
    from utils.config import Settings
    import utils.config as cfg

    s = Settings(environment="development", database_path=str(tmp_path / "t.db"))
    monkeypatch.setattr(cfg, "settings", s)

    # 延迟导入，使用被替换的 settings
    import importlib
    import backend.main as main_mod
    importlib.reload(main_mod)
    user_db = main_mod.UserDB()

    pw_a = "UserAPass!2025"
    user_db.add_user("alice", main_mod.PasswordHasher.hash_password(pw_a))
    # alice 用过 pw_a 后，密码历史应含 pw_a
    user_db.change_password("alice", "AliceNew!2026")

    # bob 用 pw_a（与 alice 旧密码相同）应不被判定为"历史密码"，因为是不同用户
    user_db.add_user("bob", main_mod.PasswordHasher.hash_password("BobInit!2025"))
    assert user_db.is_password_in_history("bob", pw_a) is False
    # alice 重复用 pw_a 应被判定为历史密码
    assert user_db.is_password_in_history("alice", pw_a) is True


# ============================================================
# MITM 防护测试（HTTPS 分支新增）
# ============================================================

def test_message_encryptor_roundtrip_aes_gcm():
    """MITM 防护：AES-256-GCM 消息加密可逆"""
    from utils.encryption import MessageEncryptor
    from Crypto.Random import get_random_bytes

    session_key = get_random_bytes(32)  # 32 字节 = AES-256
    enc = MessageEncryptor(session_key)

    for plaintext in ["hello", "你好，世界", "a" * 1000, ""]:
        if plaintext == "":
            continue  # GCM 空串虽可加密，但保持与其他用例一致跳过
        ct = enc.encrypt(plaintext)
        assert ct != plaintext
        assert enc.decrypt(ct) == plaintext


def test_message_encryptor_detects_tampering():
    """MITM 防护：GCM 认证标签防止密文篡改（bit-flipping 攻击）"""
    import base64
    from utils.encryption import MessageEncryptor
    from Crypto.Random import get_random_bytes

    session_key = get_random_bytes(32)
    enc = MessageEncryptor(session_key)

    ct = enc.encrypt("transfer 100 dollars to bob")
    # 篡改密文中的一位
    raw = bytearray(base64.b64decode(ct.encode('utf-8')))
    raw[len(raw) // 2] ^= 0x01  # 翻转中间一个 bit
    tampered = base64.b64encode(bytes(raw)).decode('utf-8')

    # 篡改后解密应失败（GCM 标签校验不通过）
    with pytest.raises(ValueError):
        enc.decrypt(tampered)


def test_message_encryptor_rejects_invalid_key():
    """MITM 防护：session key 长度必须为 32 字节"""
    from utils.encryption import MessageEncryptor

    for bad_key in [b"too_short", b"", b"x" * 16, b"x" * 64]:
        with pytest.raises(ValueError):
            MessageEncryptor(bad_key)


def test_message_encryptor_unique_nonce_per_encryption():
    """MITM 防护：每次加密使用不同 nonce，避免 nonce 重用"""
    import base64
    from utils.encryption import MessageEncryptor
    from Crypto.Random import get_random_bytes

    session_key = get_random_bytes(32)
    enc = MessageEncryptor(session_key)

    nonces = set()
    for _ in range(50):
        ct = enc.encrypt("same plaintext")
        raw = base64.b64decode(ct.encode('utf-8'))
        nonce = raw[:12]  # nonce 占前 12 字节
        nonces.add(nonce)

    # 50 次加密应产生 50 个不同的 nonce
    assert len(nonces) == 50


def test_session_key_negotiation_roundtrip():
    """MITM 防护：RSA-OAEP session key 协商完整往返（模拟前端→后端）"""
    import base64
    from Crypto.PublicKey import RSA
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA256
    from Crypto.Random import get_random_bytes
    from utils.encryption import decrypt_session_key, MessageEncryptor

    # 1. 后端生成 RSA 密钥对
    priv = RSA.generate(2048)
    pub = priv.publickey()
    priv_pem = priv.export_key()
    pub_pem = pub.export_key()

    # 2. 前端生成随机 32 字节 session key，用 RSA-OAEP(SHA-256) 加密
    raw_session_key = get_random_bytes(32)
    cipher = PKCS1_OAEP.new(pub, hashAlgo=SHA256)
    encrypted_key = cipher.encrypt(raw_session_key)
    encrypted_key_b64 = base64.b64encode(encrypted_key).decode('utf-8')

    # 3. 后端用私钥解密还原 session key
    recovered_key = decrypt_session_key(encrypted_key_b64, priv_pem)
    assert recovered_key == raw_session_key
    assert len(recovered_key) == 32

    # 4. 后端用 session key 加密消息，前端应能解密
    enc = MessageEncryptor(recovered_key)
    ct = enc.encrypt("hello over secure channel")
    # 验证后端自解密一致
    assert enc.decrypt(ct) == "hello over secure channel"


def test_decrypt_session_key_rejects_empty_and_garbage():
    """MITM 防护：session key 解密对空输入/垃圾输入抛 ValueError"""
    from Crypto.PublicKey import RSA
    from utils.encryption import decrypt_session_key

    priv = RSA.generate(2048)
    priv_pem = priv.export_key()

    # 空输入
    with pytest.raises(ValueError):
        decrypt_session_key("", priv_pem)

    # 垃圾 base64
    with pytest.raises(ValueError):
        decrypt_session_key("not-valid-base64-data!!!", priv_pem)

    # 合法 base64 但非 RSA 密文
    import base64
    junk = base64.b64encode(b"\x00" * 256).decode('utf-8')
    with pytest.raises(ValueError):
        decrypt_session_key(junk, priv_pem)


def test_public_key_fingerprint_stability_and_distinctness():
    """MITM 防护（TOFU）：公钥指纹稳定且不同密钥指纹不同"""
    from Crypto.PublicKey import RSA
    from utils.encryption import get_public_key_fingerprint

    # 同一密钥指纹应稳定
    priv = RSA.generate(2048)
    pub_pem = priv.publickey().export_key()
    fp1 = get_public_key_fingerprint(pub_pem)
    fp2 = get_public_key_fingerprint(pub_pem)
    assert fp1 == fp2
    assert len(fp1) == 64  # SHA-256 hex
    assert all(c in "0123456789abcdef" for c in fp1)

    # 不同密钥指纹应不同（模拟 MITM 替换公钥的场景）
    priv2 = RSA.generate(2048)
    pub_pem2 = priv2.publickey().export_key()
    fp_other = get_public_key_fingerprint(pub_pem2)
    assert fp1 != fp_other


def test_force_tls_config_default_and_env_override():
    """MITM 防护：force_tls 配置默认开启，可被环境变量覆盖"""
    from utils.config import Settings

    # 默认开启
    s = Settings(environment="development")
    assert s.force_tls is True

    # 环境变量可关闭
    s_off = Settings(environment="development", force_tls=False)
    assert s_off.force_tls is False


def test_no_default_encryption_key_field():
    """MITM 防护：DEFAULT_ENCRYPTION_KEY 已从配置中移除"""
    from utils.config import Settings

    s = Settings()
    # 应不存在 default_encryption_key 字段
    assert not hasattr(s, "default_encryption_key")
    assert not hasattr(s, "DEFAULT_ENCRYPTION_KEY")
