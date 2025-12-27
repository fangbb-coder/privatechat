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
            logger.warning(f"登录失败 - 用户: {username}, IP: {ip}")

    def is_locked(self, username: str) -> Tuple[bool, Optional[int]]:
        """
        检查账户是否被锁定

        返回: (是否锁定, 剩余锁定分钟数)
        """
        if username not in self.locked_until:
            return False, None

        if datetime.now() > self.locked_until[username]:
            # 锁定已过期
            del self.locked_until[username]
            return False, None

        # 计算剩余锁定时间（分钟）
        remaining = int((self.locked_until[username] - datetime.now()).total_seconds() / 60)
        return True, remaining

    def check_and_lock(self, username: str, ip: str) -> Tuple[bool, str]:
        """
        检查并锁定账户

        返回: (是否允许登录, 错误信息)
        """
        # 检查是否已被锁定
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
            return False, f"登录失败次数过多，账户已被锁定 {settings.login_lock_minutes} 分钟"

        return True, ""


class IPRateLimiter:
    """IP 频率限制器"""

    def __init__(self):
        # 存储请求记录: {ip: [datetime, ...]}
        self.requests: Dict[str, list] = defaultdict(list)

    def check_rate_limit(self, ip: str) -> Tuple[bool, Optional[int]]:
        """
        检查 IP 是否超过频率限制

        返回: (是否允许访问, 剩余等待秒数)
        """
        now = datetime.now()

        # 清理超过 1 分钟的旧记录
        self.requests[ip] = [
            req_time for req_time in self.requests[ip]
            if now - req_time < timedelta(minutes=1)
        ]

        # 检查请求次数
        if len(self.requests[ip]) >= settings.rate_limit_per_minute:
            # 计算剩余等待时间（秒）
            oldest_req = self.requests[ip][0]
            wait_seconds = int((oldest_req + timedelta(minutes=1) - now).total_seconds())
            return False, wait_seconds

        # 记录本次请求
        self.requests[ip].append(now)

        return True, None


# 创建全局实例
login_tracker = LoginAttemptTracker()
ip_rate_limiter = IPRateLimiter()


def get_login_tracker() -> LoginAttemptTracker:
    """获取登录跟踪器实例"""
    return login_tracker


def get_ip_rate_limiter() -> IPRateLimiter:
    """获取 IP 限制器实例"""
    return ip_rate_limiter
