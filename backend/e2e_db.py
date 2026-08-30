"""
端到端加密（E2E）存储层

设计原则（满足零知识 + 离线消息 + 多人聊天 + 前向保密）：
- 服务端只存储：加密消息密文、per-recipient 的加密消息密钥（enc_key）、ratchet 协商头。
  服务端不持有任何客户端私钥，因此无法解密 enc_key，也就无法解密消息正文。
- 离线消息：消息持久化在 e2e_messages 表，用户上线后按 recipient_hmac 拉取自己的 enc_key + 密文，
  客户端本地用私钥 + ratchet 状态解密。客户端不存储消息明文。
- 多人聊天：每条消息为每个接收方各存一份 enc_key（信封加密），服务端只做转发/存储。
- 前向保密由客户端 Double Ratchet 链推进 + 一次性预密钥（OPK）保证。

表结构（与 chat.db 同库，独立表，互不干扰现有用户数据）：
- e2e_user_keys:   用户身份公钥目录（X25519/ECDH 公钥 + 指纹）
- e2e_prekeys:      一次性预密钥池（离线首次握手用，用一次即标记 used）
- e2e_messages:     加密消息密文（仅密文，服务端无法解密）
- e2e_message_keys: 每个接收方一份的 enc_key + ratchet_header
"""
import sqlite3
from datetime import datetime
from typing import List, Dict, Optional

from utils.config import settings
from utils.logger import get_logger
from utils.encryption import DatabaseEncryptor

logger = get_logger()


class E2EDatabase:
    """端到端加密消息的存储与转发层（服务端零知识）"""

    def __init__(self, db_path: str = None, encryptor: DatabaseEncryptor = None):
        self.db_path = db_path or settings.database_path
        self.encryptor = encryptor or DatabaseEncryptor()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self):
        with self._get_conn() as conn:
            # 身份公钥目录：username 加密存储 + username_hmac 等值查询
            conn.execute("""
                CREATE TABLE IF NOT EXISTS e2e_user_keys (
                    username_hmac   TEXT PRIMARY KEY,
                    username        TEXT NOT NULL,
                    identity_pubkey TEXT NOT NULL,
                    fingerprint     TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                )
            """)
            # 一次性预密钥池：离线用户首次握手时被消耗
            conn.execute("""
                CREATE TABLE IF NOT EXISTS e2e_prekeys (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    prekey_id     TEXT NOT NULL UNIQUE,
                    username_hmac TEXT NOT NULL,
                    pubkey        TEXT NOT NULL,
                    used          INTEGER DEFAULT 0
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_prekeys_user ON e2e_prekeys(username_hmac, used)"
            )
            # 加密消息密文：服务端无法解密
            conn.execute("""
                CREATE TABLE IF NOT EXISTS e2e_messages (
                    message_id TEXT PRIMARY KEY,
                    sender     TEXT NOT NULL,
                    ciphertext TEXT NOT NULL,
                    room       TEXT NOT NULL DEFAULT 'public',
                    created_at TEXT NOT NULL
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_e2e_msg_time ON e2e_messages(created_at)"
            )
            # 每个接收方一份 enc_key + ratchet_header
            conn.execute("""
                CREATE TABLE IF NOT EXISTS e2e_message_keys (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id     TEXT NOT NULL,
                    recipient_hmac TEXT NOT NULL,
                    enc_key        TEXT NOT NULL,
                    ratchet_header TEXT NOT NULL,
                    read           INTEGER DEFAULT 0,
                    FOREIGN KEY(message_id) REFERENCES e2e_messages(message_id)
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_e2e_mk_recipient ON e2e_message_keys(recipient_hmac, read)"
            )
            conn.commit()
        logger.info("E2E 数据库初始化完成（零知识：服务端不持有任何客户端私钥）")

    # ---------- 公钥目录 ----------

    def upsert_keys(self, username: str, identity_pubkey: str,
                    fingerprint: str, prekeys: List[Dict]):
        """上传/更新身份公钥 + 一批一次性预密钥"""
        uh = DatabaseEncryptor.username_hmac(username)
        enc_user = self.encryptor.encrypt(username)
        now = datetime.utcnow().isoformat()
        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO e2e_user_keys(username_hmac, username, identity_pubkey, fingerprint, updated_at)
                   VALUES(?,?,?,?,?)
                   ON CONFLICT(username_hmac) DO UPDATE SET
                       username=excluded.username,
                       identity_pubkey=excluded.identity_pubkey,
                       fingerprint=excluded.fingerprint,
                       updated_at=excluded.updated_at""",
                (uh, enc_user, identity_pubkey, fingerprint, now),
            )
            # 重新上传时清掉旧的未用预密钥，避免与新一轮混淆
            if prekeys:
                conn.execute(
                    "DELETE FROM e2e_prekeys WHERE username_hmac=? AND used=0", (uh,)
                )
                for pk in prekeys:
                    conn.execute(
                        """INSERT OR IGNORE INTO e2e_prekeys(prekey_id, username_hmac, pubkey, used)
                           VALUES(?,?,?,0)""",
                        (pk["id"], uh, pk["pubkey"]),
                    )
            conn.commit()
        logger.info(f"E2E 公钥已上传: {username}（预密钥 {len(prekeys)} 个）")

    def add_prekeys(self, username: str, prekeys: List[Dict]):
        """补充一次性预密钥"""
        uh = DatabaseEncryptor.username_hmac(username)
        with self._get_conn() as conn:
            for pk in prekeys:
                conn.execute(
                    """INSERT OR IGNORE INTO e2e_prekeys(prekey_id, username_hmac, pubkey, used)
                       VALUES(?,?,?,0)""",
                    (pk["id"], uh, pk["pubkey"]),
                )
            conn.commit()

    def get_all_keys(self) -> List[Dict]:
        """返回公钥目录（明文用户名，供前端按用户名加密）"""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT username, identity_pubkey, fingerprint FROM e2e_user_keys"
            ).fetchall()
            return [
                {
                    "username": self.encryptor.decrypt(r["username"]),
                    "identity_pubkey": r["identity_pubkey"],
                    "fingerprint": r["fingerprint"],
                }
                for r in rows
            ]

    def get_pubkey(self, username: str) -> Optional[Dict]:
        uh = DatabaseEncryptor.username_hmac(username)
        with self._get_conn() as conn:
            r = conn.execute(
                "SELECT identity_pubkey, fingerprint FROM e2e_user_keys WHERE username_hmac=?",
                (uh,),
            ).fetchone()
            return dict(r) if r else None

    def get_member_list(self) -> List[str]:
        """返回所有已上传公钥的用户名（发消息时拉取成员列表）"""
        with self._get_conn() as conn:
            rows = conn.execute("SELECT username FROM e2e_user_keys").fetchall()
            return [self.encryptor.decrypt(r["username"]) for r in rows]

    def get_prekey_count(self, username: str) -> int:
        uh = DatabaseEncryptor.username_hmac(username)
        with self._get_conn() as conn:
            r = conn.execute(
                "SELECT COUNT(*) AS c FROM e2e_prekeys WHERE username_hmac=? AND used=0",
                (uh,),
            ).fetchone()
            return r["c"]

    def consume_prekey(self, username: str) -> Optional[Dict]:
        """原子消耗一个未用预密钥（用于 X3DH 离线首次握手）。
        消耗后该预密钥不可再用，提供前向保密。"""
        uh = DatabaseEncryptor.username_hmac(username)
        with self._get_conn() as conn:
            try:
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute(
                    """SELECT id, prekey_id, pubkey FROM e2e_prekeys
                       WHERE username_hmac=? AND used=0 ORDER BY id LIMIT 1""",
                    (uh,),
                ).fetchone()
                if not row:
                    conn.execute("ROLLBACK")
                    return None
                conn.execute("UPDATE e2e_prekeys SET used=1 WHERE id=?", (row["id"],))
                conn.execute("COMMIT")
                return {"prekey_id": row["prekey_id"], "pubkey": row["pubkey"]}
            except Exception as e:
                conn.execute("ROLLBACK")
                logger.warning(f"消耗预密钥失败: {type(e).__name__}")
                return None

    # ---------- 消息存储与拉取 ----------

    def store_message(self, message_id: str, sender: str,
                     ciphertext: str, room: str,
                     recipients: List[Dict]) -> List[str]:
        """存储加密消息 + per-recipient enc_key。
        recipients: [{username, enc_key, ratchet_header}]
        返回在线客户端需要实时推送的 recipient 用户名列表。
        """
        enc_sender = self.encryptor.encrypt(sender)
        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO e2e_messages(message_id, sender, ciphertext, room, created_at)
                   VALUES(?,?,?,?,?)""",
                (message_id, enc_sender, ciphertext, room,
                 datetime.utcnow().isoformat()),
            )
            for rcpt in recipients:
                rh = DatabaseEncryptor.username_hmac(rcpt["username"])
                conn.execute(
                    """INSERT INTO e2e_message_keys(message_id, recipient_hmac, enc_key, ratchet_header, read)
                       VALUES(?,?,?,?,0)""",
                    (message_id, rh, rcpt["enc_key"], rcpt["ratchet_header"]),
                )
            conn.commit()
        return [r["username"] for r in recipients]

    def get_user_messages(self, username: str, unread_only: bool = True) -> List[Dict]:
        """拉取发给该用户的消息（离线消息补偿）。
        客户端不存消息，每次上线/需要时拉取密文，本地解密后渲染（不持久化）。
        """
        rh = DatabaseEncryptor.username_hmac(username)
        with self._get_conn() as conn:
            if unread_only:
                rows = conn.execute(
                    """SELECT mk.id AS key_id, mk.message_id, mk.enc_key, mk.ratchet_header, mk.read,
                       m.sender, m.ciphertext, m.created_at, m.room
                       FROM e2e_message_keys mk
                       JOIN e2e_messages m ON mk.message_id = m.message_id
                       WHERE mk.recipient_hmac=? AND mk.read=0
                       ORDER BY mk.id""",
                    (rh,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT mk.id AS key_id, mk.message_id, mk.enc_key, mk.ratchet_header, mk.read,
                       m.sender, m.ciphertext, m.created_at, m.room
                       FROM e2e_message_keys mk
                       JOIN e2e_messages m ON mk.message_id = m.message_id
                       WHERE mk.recipient_hmac=?
                       ORDER BY mk.id DESC LIMIT 200""",
                    (rh,),
                ).fetchall()
            return [
                {
                    "key_id": r["key_id"],
                    "message_id": r["message_id"],
                    "sender": self.encryptor.decrypt(r["sender"]),
                    "ciphertext": r["ciphertext"],
                    "enc_key": r["enc_key"],
                    "ratchet_header": r["ratchet_header"],
                    "created_at": r["created_at"],
                    "room": r["room"],
                    "read": r["read"],
                }
                for r in rows
            ]

    def mark_read(self, username: str, message_id: str):
        rh = DatabaseEncryptor.username_hmac(username)
        with self._get_conn() as conn:
            conn.execute(
                "UPDATE e2e_message_keys SET read=1 WHERE message_id=? AND recipient_hmac=?",
                (message_id, rh),
            )
            conn.commit()
