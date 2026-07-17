"""Pydantic 请求/响应模型"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field, field_validator


# ─── 认证相关 ────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=32, description="用户名")
    password: str = Field(min_length=1, max_length=128, description="密码")

    @field_validator("username")
    @classmethod
    def strip_username(cls, v: str) -> str:
        return v.strip()


class RegisterRequest(BaseModel):
    username: str = Field(min_length=2, max_length=32, description="用户名")
    password: str = Field(min_length=6, max_length=128, description="密码")
    confirm_password: str = Field(min_length=6, max_length=128, description="确认密码")

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("用户名只能包含字母、数字、下划线和连字符")
        return v

    @field_validator("confirm_password")
    @classmethod
    def passwords_match(cls, v: str, info) -> str:
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("两次输入的密码不一致")
        return v


class ChangePasswordRequest(BaseModel):
    old_password: str = Field(min_length=1, max_length=128, description="原密码")
    new_password: str = Field(min_length=8, max_length=128, description="新密码")


class LoginResponse(BaseModel):
    token: str
    username: str
    session_timeout: int
    password_changed: bool
    role: str


class AuthStatusResponse(BaseModel):
    authenticated: bool
    username: Optional[str] = None
    role: Optional[str] = None
    password_changed: Optional[bool] = None


# ─── 用户管理 ────────────────────────────────────────────

class UserCreateRequest(BaseModel):
    username: str = Field(min_length=2, max_length=32, description="用户名")
    password: str = Field(min_length=8, max_length=128, description="密码")
    role: str = Field(default="user", pattern="^(admin|user)$", description="角色")

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        v = v.strip()
        if not v.replace("_", "").replace("-", "").isalnum():
            raise ValueError("用户名只能包含字母、数字、下划线和连字符")
        return v


class UserUpdateRequest(BaseModel):
    role: Optional[str] = Field(default=None, pattern="^(admin|user)$", description="角色")
    password: Optional[str] = Field(default=None, min_length=8, max_length=128, description="新密码")


class UserInfo(BaseModel):
    username: str
    role: str
    created: str
    password_changed: bool


class UsersResponse(BaseModel):
    users: list[UserInfo]


# ─── 日记相关 ────────────────────────────────────────────

class DiarySaveRequest(BaseModel):
    content: str = Field(min_length=1, max_length=50000, description="日记内容")


class DiaryEntry(BaseModel):
    date: str
    title: str = ""
    preview: str = ""
    tags: list[str] = []
    word_count: int = 0


class DiariesResponse(BaseModel):
    entries: list[DiaryEntry]
    total: int


class DiaryDetail(BaseModel):
    date: str
    content: str
    tags: list[str] = []


# ─── 搜索/统计 ───────────────────────────────────────────

class SearchResult(BaseModel):
    date: str
    preview: str
    tags: list[str] = []


class SearchResponse(BaseModel):
    results: list[SearchResult]
    total: int


class StatsResponse(BaseModel):
    total_entries: int
    total_words: int
    first_date: Optional[str] = None
    last_date: Optional[str] = None
    streak: int
    tags: dict[str, int] = {}
    encrypted: bool


class CalendarDay(BaseModel):
    day: int
    has_entry: bool


class CalendarResponse(BaseModel):
    dates: list[CalendarDay]


# ─── 审计日志 ────────────────────────────────────────────

class AuditEntry(BaseModel):
    timestamp: str
    user: str
    action: str
    detail: str
    ip: str


class AuditResponse(BaseModel):
    entries: list[str]
    total: int


# ─── 备份/恢复 ───────────────────────────────────────────

class DecryptBackupRequest(BaseModel):
    password: str = Field(min_length=1, max_length=128, description="密码")


class RestoreResponse(BaseModel):
    status: str
    restored: int
    skipped: int
    errors: list[str] = []


# ─── 设置/健康检查 ────────────────────────────────────────

class SettingsResponse(BaseModel):
    encryption_enabled: bool
    session_timeout: int
    max_login_attempts: int
    has_master_key: bool
    bcrypt_rounds: int


class HealthResponse(BaseModel):
    status: str
    timestamp: str
    version: str
    encryption: bool
    disk: Optional[dict] = None
    crypto: Optional[str] = None


# ─── 错误响应 ────────────────────────────────────────────

class ErrorResponse(BaseModel):
    error: str