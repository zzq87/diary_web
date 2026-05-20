"""认证模块：密码、用户、Session、速率限制"""

import os
import time
import hmac
import hashlib
import base64
import secrets
import logging
import threading
from datetime import datetime
from typing import Optional

from .config import (
    USERS_FILE,
    SESSIONS_FILE,
    RATE_LIMIT_FILE,
    SESSION_TIMEOUT,
    MAX_LOGIN_ATTEMPTS,
    LOGIN_LOCKOUT_SECONDS,
    RATE_LIMIT_WINDOW,
    RATE_LIMIT_MAX,
    PBKDF2_ITERATIONS,
    safe_chmod,
)

logger = logging.getLogger("diary.auth")

# ─── 密码 ──────────────────────────────────────────────


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return base64.b64encode(salt + pwd_hash).decode()


def verify_password(password: str, hashed: str) -> bool:
    try:
        raw = base64.b64decode(hashed)
        salt, stored_hash = raw[:16], raw[16:]
        # 尝试当前迭代次数
        pwd_hash = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt, PBKDF2_ITERATIONS
        )
        if hmac.compare_digest(pwd_hash, stored_hash):
            return True
        # 兼容旧迭代次数（100000），用于平滑迁移
        if PBKDF2_ITERATIONS != 100000:
            pwd_hash_old = hashlib.pbkdf2_hmac(
                "sha256", password.encode(), salt, 100000
            )
            if hmac.compare_digest(pwd_hash_old, stored_hash):
                return True
        return False
    except Exception:
        return False


# ─── 文件锁 ────────────────────────────────────────────

_file_locks: dict[str, threading.Lock] = {}
_file_locks_lock = threading.Lock()
_LOCK_TTL = 3600  # 锁对象 TTL 1小时
_lock_last_used: dict[str, float] = {}


def _get_lock(name: str) -> threading.Lock:
    with _file_locks_lock:
        now = time.time()
        # 清理过期锁
        expired = [k for k, v in _lock_last_used.items() if now - v > _LOCK_TTL]
        for k in expired:
            _file_locks.pop(k, None)
            _lock_last_used.pop(k, None)

        if name not in _file_locks:
            _file_locks[name] = threading.Lock()
        _lock_last_used[name] = now
        return _file_locks[name]


# ─── 用户管理 ──────────────────────────────────────────


def load_users() -> dict:
    lock = _get_lock("users")
    with lock:
        if USERS_FILE.exists():
            return _load_json(USERS_FILE)
        default_users = {
            "admin": {
                "password_hash": hash_password(_get_default_password()),
                "created": datetime.now().isoformat(),
                "password_changed": False,
            }
        }
        _save_json(USERS_FILE, default_users)
        return default_users


def _get_default_password() -> str:
    from .config import DEFAULT_PASSWORD

    return DEFAULT_PASSWORD


def save_users(users: dict) -> None:
    lock = _get_lock("users")
    with lock:
        _save_json(USERS_FILE, users)


def create_user(username: str, password: str) -> bool:
    lock = _get_lock("users")
    with lock:
        users = _load_json(USERS_FILE) if USERS_FILE.exists() else {}
        if username in users:
            return False
        users[username] = {
            "password_hash": hash_password(password),
            "created": datetime.now().isoformat(),
            "password_changed": True,
        }
        _save_json(USERS_FILE, users, locked=True)
    return True


# ─── Session 管理 ──────────────────────────────────────


def load_sessions() -> dict:
    lock = _get_lock("sessions")
    with lock:
        return _load_json(SESSIONS_FILE) if SESSIONS_FILE.exists() else {}


def save_sessions(sessions: dict) -> None:
    lock = _get_lock("sessions")
    with lock:
        _save_json(SESSIONS_FILE, sessions)


def create_session(username: str, ip: str = "unknown") -> str:
    token = secrets.token_urlsafe(32)
    lock = _get_lock("sessions")
    with lock:
        sessions = _load_json(SESSIONS_FILE) if SESSIONS_FILE.exists() else {}
        now = time.time()
        sessions[token] = {
            "username": username,
            "created": now,
            "last_activity": now,
            "ip": ip,
        }
        _save_json(SESSIONS_FILE, sessions, locked=True)
    return token


def validate_session(token: str) -> Optional[str]:
    if not token:
        return None
    lock = _get_lock("sessions")
    with lock:
        sessions = _load_json(SESSIONS_FILE) if SESSIONS_FILE.exists() else {}
        session = sessions.get(token)
        if not session:
            return None
        if time.time() - session["last_activity"] > SESSION_TIMEOUT:
            del sessions[token]
            _save_json(SESSIONS_FILE, sessions, locked=True)
            return None
        session["last_activity"] = time.time()
        _save_json(SESSIONS_FILE, sessions, locked=True)
        return session["username"]


def invalidate_session(token: str) -> None:
    lock = _get_lock("sessions")
    with lock:
        sessions = _load_json(SESSIONS_FILE) if SESSIONS_FILE.exists() else {}
        sessions.pop(token, None)
        _save_json(SESSIONS_FILE, sessions, locked=True)


# ─── JSON 辅助 ─────────────────────────────────────────


def _load_json(path) -> dict:
    import json

    return json.loads(path.read_text(encoding="utf-8"))


def _save_json(path, data: dict, locked: bool = False) -> None:
    import json

    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    if not locked:
        safe_chmod(path, 0o600)


# ─── 速率限制（内存化 + 定时刷盘）───────────────────────

_rate_limit_mem: dict = {}
_rate_limit_lock = threading.Lock()
_rate_limit_flush_interval = 10
_rate_limit_last_flush = 0.0


def _load_rate_limits() -> None:
    global _rate_limit_mem
    try:
        if RATE_LIMIT_FILE.exists():
            _rate_limit_mem = _load_json(RATE_LIMIT_FILE)
    except Exception:
        _rate_limit_mem = {}


def _flush_rate_limits() -> None:
    global _rate_limit_last_flush
    now = time.time()
    if now - _rate_limit_last_flush < _rate_limit_flush_interval:
        return
    _rate_limit_last_flush = now
    try:
        import json

        RATE_LIMIT_FILE.write_text(json.dumps(_rate_limit_mem), encoding="utf-8")
    except Exception:
        pass


def _cleanup_expired(now: float, window: float) -> None:
    expired = [
        k for k, v in _rate_limit_mem.items() if now - v.get("start", 0) > window
    ]
    for k in expired:
        del _rate_limit_mem[k]


def check_rate_limit(client_ip: str, endpoint: str = "api") -> bool:
    key = f"{client_ip}:{endpoint}"
    now = time.time()
    with _rate_limit_lock:
        _cleanup_expired(now, RATE_LIMIT_WINDOW)
        if key not in _rate_limit_mem:
            _rate_limit_mem[key] = {"count": 1, "start": now}
        else:
            _rate_limit_mem[key]["count"] += 1
            if _rate_limit_mem[key]["count"] > RATE_LIMIT_MAX:
                _flush_rate_limits()
                return False
    _flush_rate_limits()
    return True


def check_login_limit(client_ip: str) -> bool:
    key = f"login:{client_ip}"
    now = time.time()
    with _rate_limit_lock:
        _cleanup_expired(now, LOGIN_LOCKOUT_SECONDS)
        if key in _rate_limit_mem:
            if _rate_limit_mem[key]["count"] >= MAX_LOGIN_ATTEMPTS:
                _flush_rate_limits()
                return False
            _rate_limit_mem[key]["count"] += 1
        else:
            _rate_limit_mem[key] = {"count": 1, "start": now}
    _flush_rate_limits()
    return True


# ─── 审计日志 ──────────────────────────────────────────

from .config import AUDIT_FILE

_audit_lock = threading.Lock()


def _sanitize_log_field(value: str) -> str:
    if not value:
        return ""
    return value.replace("\n", " ").replace("\r", " ").replace("\t", " ")


def audit_log(action: str, username: str, detail: str = "", ip: str = "") -> None:
    timestamp = datetime.now().isoformat()
    username = _sanitize_log_field(username)
    detail = _sanitize_log_field(detail)
    ip = _sanitize_log_field(ip)
    # 使用 | 分隔符替代空格，避免 detail 含空格时解析错乱
    log_entry = (
        f"[{timestamp}]|user={username}|action={action}|detail={detail}|ip={ip}\n"
    )
    with _audit_lock:
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)
