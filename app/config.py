"""配置管理模块 — 基于 Pydantic Settings"""

import os
import sys
import logging
from pathlib import Path
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("diary")

BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ─── 基础路径 ──────────────────────────────────────────
    diary_dir: Path = Field(default=BASE_DIR / "data", validation_alias="DIARY_DIR")
    config_dir: Path = Field(default=BASE_DIR / "config", validation_alias="CONFIG_DIR")

    # ─── 安全配置 ──────────────────────────────────────────
    secret_key: str = Field(default="", validation_alias="DIARY_SECRET_KEY")
    session_timeout: int = Field(default=3600, validation_alias="DIARY_SESSION_TIMEOUT", ge=60, le=86400)
    max_login_attempts: int = Field(default=5, validation_alias="DIARY_MAX_LOGIN_ATTEMPTS", ge=1, le=20)
    login_lockout_seconds: int = Field(default=300, validation_alias="DIARY_LOGIN_LOCKOUT", ge=60, le=3600)
    rate_limit_window: int = Field(default=60, validation_alias="DIARY_RATE_LIMIT_WINDOW", ge=10, le=3600)
    rate_limit_max: int = Field(default=100, validation_alias="DIARY_RATE_LIMIT_MAX", ge=10, le=1000)
    encryption_enabled: bool = Field(default=True, validation_alias="DIARY_ENCRYPT")
    bcrypt_rounds: int = Field(default=10, validation_alias="DIARY_BCRYPT_ROUNDS", ge=4, le=16)
    pbkdf2_iterations: int = Field(default=600000, validation_alias="DIARY_PBKDF2_ITERATIONS", ge=50000, le=2000000)
    default_password: str = Field(default="admin123", validation_alias="DIARY_DEFAULT_PASSWORD")

    # ─── 服务配置 ──────────────────────────────────────────
    port: int = Field(default=9000, validation_alias="DIARY_PORT", ge=1024, le=65535)
    proxy_connect_addr: str = Field(default="127.0.0.1", validation_alias="DIARY_PROXY_CONNECT_ADDR")

    # ─── 运行时路径 ────────────────────────────────────────
    users_file: Path | None = Field(default=None, init=False)
    audit_file: Path | None = Field(default=None, init=False)
    sessions_file: Path | None = Field(default=None, init=False)
    rate_limit_file: Path | None = Field(default=None, init=False)
    master_key_file: Path | None = Field(default=None, init=False)
    search_db_file: Path | None = Field(default=None, init=False)

    def model_post_init(self, __context) -> None:
        self._ensure_dirs()
        self._setup_runtime_paths()

    def _ensure_dirs(self) -> None:
        for d in [self.config_dir, self.diary_dir]:
            d.mkdir(parents=True, exist_ok=True)
            self._safe_chmod(d, 0o700)

    def _setup_runtime_paths(self) -> None:
        self.users_file = self.config_dir / "users.json"
        self.audit_file = self.config_dir / "audit.log"
        self.sessions_file = self.config_dir / "sessions.enc.json"
        self.rate_limit_file = self.config_dir / "rate_limits.json"
        self.master_key_file = self.config_dir / "master.key"
        # tmpfs 优先（Pi SD 卡保护），fallback 到 config 目录
        tmpfs_db = Path("/tmp/diary_search.db")
        self.search_db_file = tmpfs_db if (tmpfs_db.parent.exists() and os.name != "nt") else (self.config_dir / "search.db")

    @staticmethod
    def _safe_chmod(path: Path, mode: int) -> None:
        if sys.platform != "win32":
            try:
                path.chmod(mode)
            except OSError:
                pass

    @field_validator("default_password", mode="after")
    @classmethod
    def _warn_default_password(cls, v: str) -> str:
        if v == "admin123":
            logger.warning("⚠️ 使用默认密码 'admin123'，请通过 DIARY_DEFAULT_PASSWORD 环境变量修改")
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()

# ─── 导出常量 (兼容旧代码) ─────────────────────────────────
DIARY_DIR = settings.diary_dir
CONFIG_DIR = settings.config_dir
SECRET_KEY = settings.secret_key
SESSION_TIMEOUT = settings.session_timeout
MAX_LOGIN_ATTEMPTS = settings.max_login_attempts
LOGIN_LOCKOUT_SECONDS = settings.login_lockout_seconds
RATE_LIMIT_WINDOW = settings.rate_limit_window
RATE_LIMIT_MAX = settings.rate_limit_max
ENCRYPTION_ENABLED = settings.encryption_enabled
BCRYPT_ROUNDS = settings.bcrypt_rounds
PBKDF2_ITERATIONS = settings.pbkdf2_iterations
DEFAULT_PASSWORD = settings.default_password
PORT = settings.port
PROXY_CONNECT_ADDR = settings.proxy_connect_addr

USERS_FILE = settings.users_file
AUDIT_FILE = settings.audit_file
SESSIONS_FILE = settings.sessions_file
RATE_LIMIT_FILE = settings.rate_limit_file
MASTER_KEY_FILE = settings.master_key_file
SEARCH_DB_FILE = settings.search_db_file

safe_chmod = Settings._safe_chmod
ensure_dirs = settings._ensure_dirs