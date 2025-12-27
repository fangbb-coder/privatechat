"""
安全工具模块
提供登录限制、IP 限制等安全功能
"""
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
from config import settings
from logger import get_logger

logger = get_logger()


class LoginAttemptTracker:
    """登录尝试跟踪器 - 防止暴力破解"""

    def __init__(self):
        # 存储登录失败记录: {username: [(datetime, ip), ...]}
        self.attempts: Dict[str, list] = defaultdict(list)
        # 存储锁定时间: {username: unlock_time}
        self.locked_until: Dict[str, datetime] = {}
        # IP级别的锁定（防止同一IP暴力破解多个账户）
        self.ip_locks: Dict[str, datetime] = {}

    def record_attempt(self, username: str, ip: str, success: bool):
        """记录登录尝试"""
        if success:
            # 登录成功，清除该用户的失败记录
            if username in self.attempts:
                del self.attempts[username]
            if username in self.locked_until:
                del self.locked_until[username]
        else:
            # 登录失败，记录尝试
            self.attempts[username].append((datetime.now(), ip))
            logger.warning(f"登录失败 - 用户: {username}, IP: {ip}, 总失败次数: {len(self.attempts[username])}")

            # 检查该IP是否有大量失败尝试（可能是暴力破解）
            self._check_ip_lock(ip)

    def _check_ip_lock(self, ip: str):
        """检查IP级别的锁定"""
        # 清理过期的IP锁定
        now = datetime.now()
        self.ip_locks = {
            ip_addr: lock_time
            for ip_addr, lock_time in self.ip_locks.items()
            if now < lock_time
        }

        # 检查该IP是否已被锁定
        if ip in self.ip_locks:
            return

        # 统计该IP的失败次数（跨所有用户）
        all_failures = [
            attempt
            for attempts in self.attempts.values()
            for attempt in attempts
            if attempt[1] == ip and now - attempt[0] < timedelta(minutes=10)
        ]

        # 如果同一IP失败次数过多，锁定该IP
        if len(all_failures) >= settings.ip_lock_threshold:
            lock_until = now + timedelta(minutes=settings.ip_lock_minutes)
            self.ip_locks[ip] = lock_until
            logger.warning(f"IP锁定 - IP: {ip}, 锁定时间: {settings.ip_lock_minutes}分钟")

    def is_ip_locked(self, ip: str) -> bool:
        """检查IP是否被锁定"""
        if ip not in self.ip_locks:
            return False
        if datetime.now() > self.ip_locks[ip]:
            del self.ip_locks[ip]
            return False
        return True

    def is_locked(self, username: str) -> Tuple[bool, Optional[int]]:
        """
        检查账户是否被锁定

        返回: (是否锁定, 剩余锁定分钟数)
        """
        if username not in self.locked_until:
            return False, None

        now = datetime.now()
        lock_time = self.locked_until[username]

        if now > lock_time:
            # 锁定已过期
            del self.locked_until[username]
            return False, None

        # 计算剩余锁定时间（分钟），至少显示1分钟
        remaining_seconds = (lock_time - now).total_seconds()
        remaining = int(remaining_seconds / 60)
        if remaining == 0:
            remaining = 1  # 如果不满1分钟，至少显示1分钟

        logger.info(f"账户已锁定: {username}, 剩余 {remaining} 分钟")
        return True, remaining

    def check_and_lock(self, username: str, ip: str) -> Tuple[bool, str]:
        """
        检查并锁定账户

        返回: (是否允许登录, 错误信息)
        """
        # 首先检查IP是否被锁定
        if self.is_ip_locked(ip):
            return False, "您的IP已被暂时锁定，请稍后再试"

        # 检查账户是否已被锁定
        is_locked, remaining = self.is_locked(username)
        if is_locked:
            return False, f"账户已被锁定，请 {remaining} 分钟后重试"

        # 检查最近的失败尝试
        recent_attempts = [
            attempt for attempt in self.attempts.get(username, [])
            if datetime.now() - attempt[0] < timedelta(minutes=15)
        ]

        if len(recent_attempts) >= settings.max_login_attempts:
            # 锁定账户
            lock_until = datetime.now() + timedelta(minutes=settings.login_lock_minutes)
            self.locked_until[username] = lock_until
            logger.warning(f"账户锁定 - 用户: {username}, 锁定时间: {settings.login_lock_minutes}分钟")
            return False, "登录尝试次数过多，账户已锁定"

        return True, ""


class IPRateLimiter:
    """IP 频率限制器（带内存保护）"""

    def __init__(self):
        # 存储请求记录: {ip: [datetime, ...]}
        self.requests: Dict[str, list] = defaultdict(list)
        self.max_ips = settings.rate_limit_max_ips  # 限制最大 IP 数量，防止内存泄漏

    def check_rate_limit(self, ip: str) -> Tuple[bool, Optional[int]]:
        """
        检查 IP 是否超过频率限制

        返回: (是否允许访问, 剩余等待秒数)
        """
        now = datetime.now()

        # 定期清理（每1000次请求执行一次完整清理）
        if len(self.requests) > self.max_ips:
            self._cleanup_expired_ips(now)

        # 清理超过 1 分钟的旧记录
        self.requests[ip] = [
            req_time for req_time in self.requests[ip]
            if now - req_time < timedelta(minutes=1)
        ]

        # 如果没有记录了，删除该 IP 键
        if not self.requests[ip]:
            del self.requests[ip]

        # 检查请求次数
        if len(self.requests[ip]) >= settings.rate_limit_per_minute:
            # 计算剩余等待时间（秒）
            oldest_req = self.requests[ip][0]
            wait_seconds = int((oldest_req + timedelta(minutes=1) - now).total_seconds())
            return False, wait_seconds

        # 记录本次请求
        self.requests[ip].append(now)

        return True, None

    def _cleanup_expired_ips(self, now: datetime):
        """清理所有过期的 IP 记录"""
        expired_ips = []
        for ip, timestamps in self.requests.items():
            # 清理过期的记录
            valid_timestamps = [
                req_time for req_time in timestamps
                if now - req_time < timedelta(minutes=1)
            ]
            if valid_timestamps:
                self.requests[ip] = valid_timestamps
            else:
                expired_ips.append(ip)

        # 删除过期的 IP 键
        for ip in expired_ips:
            if ip in self.requests:
                del self.requests[ip]

        logger.debug(f"速率限制器清理完成，剩余 IP 数量: {len(self.requests)}")


class WSConnectionRateLimiter:
    """WebSocket 连接频率限制器（带内存保护）"""

    def __init__(self):
        # 存储连接记录: {ip: [datetime, ...]}
        self.connections: Dict[str, list] = defaultdict(list)
        self.max_ips = settings.rate_limit_max_ips  # 限制最大 IP 数量，防止内存泄漏

    def check_rate_limit(self, ip: str) -> bool:
        """
        检查 IP 是否超过连接频率限制

        返回: (是否允许连接)
        """
        now = datetime.now()

        # 定期清理（每1000次连接执行一次完整清理）
        if len(self.connections) > self.max_ips:
            self._cleanup_expired_ips(now)

        # 清理超过 1 分钟的旧记录
        self.connections[ip] = [
            conn_time for conn_time in self.connections[ip]
            if now - conn_time < timedelta(minutes=1)
        ]

        # 如果没有记录了，删除该 IP 键
        if not self.connections[ip]:
            del self.connections[ip]

        # 检查连接次数
        if len(self.connections[ip]) >= settings.ws_connections_per_minute:
            return False

        # 记录本次连接
        self.connections[ip].append(now)

        return True

    def _cleanup_expired_ips(self, now: datetime):
        """清理所有过期的 IP 记录"""
        expired_ips = []
        for ip, timestamps in self.connections.items():
            # 清理过期的记录
            valid_timestamps = [
                conn_time for conn_time in timestamps
                if now - conn_time < timedelta(minutes=1)
            ]
            if valid_timestamps:
                self.connections[ip] = valid_timestamps
            else:
                expired_ips.append(ip)

        # 删除过期的 IP 键
        for ip in expired_ips:
            if ip in self.connections:
                del self.connections[ip]

        logger.debug(f"WebSocket 速率限制器清理完成，剩余 IP 数量: {len(self.connections)}")


# 创建全局实例
login_tracker = LoginAttemptTracker()
ip_rate_limiter = IPRateLimiter()
ws_connection_rate_limiter = WSConnectionRateLimiter()
