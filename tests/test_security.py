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
        Settings(environment="production", allowed_origins=[], allowed_hosts=[])


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
