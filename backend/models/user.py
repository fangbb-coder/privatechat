"""
用户数据模型
"""
from pydantic import BaseModel, Field, validator
from typing import Optional
import re


class UserRegister(BaseModel):
    """用户注册数据模型"""
    username: str = Field(..., min_length=3, max_length=20, description="用户名")
    password: str = Field(..., min_length=8, max_length=64, description="密码")

    @validator('username')
    def username_must_be_valid(cls, v):
        if not re.match(r"^[a-zA-Z0-9_]+$", v):
            raise ValueError("用户名只能包含字母、数字和下划线")
        return v


class UserLogin(BaseModel):
    """用户登录数据模型"""
    username: str
    password: str
    remember_me: bool = False


class UserChangePassword(BaseModel):
    """修改密码数据模型"""
    old_password: str = Field(..., min_length=1, description="旧密码")
    new_password: str = Field(..., min_length=8, max_length=64, description="新密码")


class UserInfo(BaseModel):
    """用户信息模型"""
    username: str
    is_admin: bool
    created_at: Optional[str] = None


class TokenResponse(BaseModel):
    """Token 响应模型"""
    access_token: str
    token_type: str = "bearer"
    username: str
    remember_me: Optional[bool] = False


class Message(BaseModel):
    """消息模型"""
    id: str
    sender: str
    content: str
    time: int
    type: str  # message, system, recall
    is_read: bool = False
    is_sender: bool = False


class MessageRecall(BaseModel):
    """消息撤回模型"""
    message_id: str


class OnlineUser(BaseModel):
    """在线用户模型"""
    username: str
    status: str  # online, busy
    connected_at: int


class SystemAnnouncement(BaseModel):
    """系统公告模型"""
    message: str
    type: str = "announcement"


class StatsResponse(BaseModel):
    """统计信息响应"""
    online_users: int
    total_messages_sent: int
    total_users: int
