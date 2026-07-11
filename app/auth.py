"""认证模块：密码、用户、Session 加密存储、速率限制、审计日志"""

import json
import base64
import os
import time
import hmac
import hashlib
import threading
from datetime import datetime
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import logging

from app.crypto import get_or_create_master_key
from app.config import (
    SESSION_TIMEOUT,
    MAX_LOGIN_ATTEMPTS,
    LOGIN_LOCKOUT_SECONDS,
    RATE_LIMIT_WINDOW,
    RATE_LIMIT_MAX,
    PBKDF2_ITERATIONS,
    USERS_FILE,
    AUDIT_FILE,
    RATE_LIMIT_FILE,
    SESSIONS_FILE,
    DEFAULT_PASSWORD,
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
        pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
        if hmac.compare_digest(pwd_hash, stored_hash):
            return True
        if PBKDF2_ITERATIONS != 100000:
            pwd_hash_old = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
            if hmac.compare_digest(pwd_hash_old, stored_hash):
                return True
        return False
    except Exception:
        return False


# ─── JSON 辅助 ─────────────────────────────────────────


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _save_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    safe_chmod(path, 0o600)


# ─── 文件锁 ────────────────────────────────────────────

_file_locks: dict[str, threading.Lock] = {}
_file_locks_lock = threading.Lock()


def _get_lock(name: str) -> threading.Lock:
    with _file_locks_lock:
        if name not in _file_locks:
            _file_locks[name] = threading.Lock()
        return _file_locks[name]


# ─── 用户管理 ──────────────────────────────────────────


def load_users() -> dict:
    lock = _get_lock("users")
    with lock:
        if USERS_FILE.exists():
            users = _load_json(USERS_FILE)
            migrated = False
            for uname, udata in users.items():
                if "role" not in udata:
                    udata["role"] = "admin" if uname == "admin" else "user"
                    migrated = True
            if migrated:
                _save_json(USERS_FILE, users)
            return users
        default_users = {
            "admin": {
                "password_hash": hash_password(DEFAULT_PASSWORD),
                "created": datetime.now().isoformat(),
                "password_changed": False,
                "role": "admin",
            }
        }
        _save_json(USERS_FILE, default_users)
        return default_users


def save_users(users: dict) -> None:
    lock = _get_lock("users")
    with lock:
        _save_json(USERS_FILE, users)


def create_user(username: str, password: str, role: str = "user") -> bool:
    if not username or len(username) < 2:
        return False
    if not password or len(password) < 6:
        return False
    if role not in ("admin", "user"):
        return False
    lock = _get_lock("users")
    with lock:
        users = _load_json(USERS_FILE) if USERS_FILE.exists() else {}
        if username in users:
            return False
        users[username] = {
            "password_hash": hash_password(password),
            "created": datetime.now().isoformat(),
            "password_changed": True,
            "role": role,
        }
        _save_json(USERS_FILE, users)
    return True


def delete_user(username: str) -> bool:
    if username == "admin":
        return False
    lock = _get_lock("users")
    with lock:
        users = _load_json(USERS_FILE) if USERS_FILE.exists() else {}
        if username not in users:
            return False
        del users[username]
        _save_json(USERS_FILE, users)
    return True


def update_user(username: str, **kwargs) -> bool:
    if username == "admin" and "role" in kwargs:
        return False
    allowed = {"password_hash", "password_changed", "role"}
    updates = {k: v for k, v in kwargs.items() if k in allowed}
    if not updates:
        return False
    lock = _get_lock("users")
    with lock:
        users = _load_json(USERS_FILE) if USERS_FILE.exists() else {}
        if username not in users:
            return False
        users[username].update(updates)
        _save_json(USERS_FILE, users)
    return True


def list_users() -> list[dict]:
    users = load_users()
    return [
        {
            "username": uname,
            "role": udata.get("role", "user"),
            "created": udata.get("created", ""),
            "password_changed": udata.get("password_changed", False),
        }
        for uname, udata in users.items()
    ]


def is_admin(username: str) -> bool:
    users = load_users()
    user = users.get(username)
    return user is not None and user.get("role") == "admin"


# ─── 会话加密和解密辅助 ────────────────────────────────────────

from .config import MASTER_KEY_FILE

_session_key: bytes | None = None
_session_key_mtime: float = 0.0


def _derive_session_key() -> bytes:
    global _session_key, _session_key_mtime
    mtime = MASTER_KEY_FILE.stat().st_mtime if MASTER_KEY_FILE.exists() else 0.0
    if _session_key is None or mtime != _session_key_mtime:
        master_key = get_or_create_master_key()
        _session_key = hmac.new(master_key, b"diary-session-v1", hashlib.sha256).digest()
        _session_key_mtime = mtime
    return _session_key


def _encrypt_session(session_data: dict, session_key: bytes) -> str:
    """加密会话数据"""
    aesgcm = AESGCM(session_key)
    nonce = os.urandom(12)
    data = json.dumps(session_data, ensure_ascii=False).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return base64.b64encode(nonce + ciphertext).decode()


def _decrypt_session(encrypted: str, session_key: bytes) -> dict:
    """解密会话数据"""
    try:
        raw = base64.b64decode(encrypted)
        if len(raw) < 28:
            raise ValueError("密文过短")
        nonce, ciphertext = raw[:12], raw[12:]
        aesgcm = AESGCM(session_key)
        data = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(data.decode("utf-8"))
    except Exception as e:
        logger.warning(f"会话解密失败: {e}")
        return {}


# ─── 文件锁 ────────────────────────────────────────────

_session_locks: dict[str, threading.RLock] = {}
_session_locks_lock = threading.Lock()


def _get_session_lock(name: str) -> threading.RLock:
    with _session_locks_lock:
        if name not in _session_locks:
            _session_locks[name] = threading.RLock()
        return _session_locks[name]


def _load_sessions_data() -> dict:
    if not _session_file.exists():
        return {}
    try:
        encrypted_data = _session_file.read_text(encoding="utf-8")
        session_key = _derive_session_key()
        return _decrypt_session(encrypted_data, session_key)
    except Exception as e:
        logger.warning(f"加载加密会话失败: {e}")
        return {}


def _save_sessions_data(sessions: dict) -> None:
    try:
        session_key = _derive_session_key()
        encrypted = _encrypt_session(sessions, session_key)
        _session_file.write_text(encrypted, encoding="utf-8")
        if os.name != "nt":
            _session_file.chmod(0o600)
    except Exception as e:
        logger.error(f"保存加密会话失败: {e}")
        raise


# ─── 会话存储 ─────────────────────────────────────────────────

_session_file = SESSIONS_FILE


def _load_sessions() -> dict:
    lock = _get_session_lock("sessions")
    with lock:
        return _load_sessions_data()


def _save_sessions(sessions: dict) -> None:
    lock = _get_session_lock("sessions")
    with lock:
        _save_sessions_data(sessions)


def create_session(username: str, ip: str = "unknown") -> str:
    """创建新会话"""
    lock = _get_session_lock("sessions")
    with lock:
        sessions = _load_sessions_data()
        token = os.urandom(32).hex()
        now = time.time()
        sessions[token] = {
            "username": username,
            "created": now,
            "last_activity": now,
            "ip": ip,
        }
        _save_sessions_data(sessions)
    return token


def validate_session(token: str) -> str | None:
    """验证会话，返回用户名或 None（不触发磁盘写入）"""
    if not token:
        return None
    lock = _get_session_lock("sessions")
    with lock:
        sessions = _load_sessions_data()
        session = sessions.get(token)
        if not session:
            return None
        if time.time() - session["last_activity"] > SESSION_TIMEOUT:
            del sessions[token]
            _save_sessions_data(sessions)
            return None
        session["last_activity"] = time.time()
        return session["username"]


def peek_session(token: str) -> str | None:
    """只读验证会话，不更新 last_activity，不落盘"""
    if not token:
        return None
    lock = _get_session_lock("sessions")
    with lock:
        sessions = _load_sessions_data()
        session = sessions.get(token)
        if not session:
            return None
        if time.time() - session["last_activity"] > SESSION_TIMEOUT:
            return None
        return session["username"]


def invalidate_session(token: str) -> None:
    """使会话失效"""
    lock = _get_session_lock("sessions")
    with lock:
        sessions = _load_sessions_data()
        sessions.pop(token, None)
        _save_sessions_data(sessions)


def cleanup_expired_sessions() -> None:
    """清理过期会话"""
    lock = _get_session_lock("sessions")
    with lock:
        sessions = _load_sessions_data()
        now = time.time()
        expired_tokens = [
            token for token, session in sessions.items()
            if now - session["last_activity"] > SESSION_TIMEOUT
        ]
        for token in expired_tokens:
            del sessions[token]
        if expired_tokens:
            _save_sessions_data(sessions)
            logger.info(f"清理了 {len(expired_tokens)} 个过期会话")

# ─── 速率限制（内存化 + 定时刷盘）───────────────────────

_rate_limit_mem: dict = {}
_rate_limit_lock = threading.Lock()
_rate_limit_flush_interval = 10
_rate_limit_last_flush = 0.0


def _load_rate_limits() -> None:
    global _rate_limit_mem
    _rate_limit_mem = {}
    try:
        if RATE_LIMIT_FILE.exists():
            _rate_limit_mem.update(_load_json(RATE_LIMIT_FILE))
    except Exception:
        pass


def _flush_rate_limits() -> None:
    global _rate_limit_last_flush
    now = time.time()
    if now - _rate_limit_last_flush < _rate_limit_flush_interval:
        return
    _rate_limit_last_flush = now
    try:
        RATE_LIMIT_FILE.write_text(json.dumps(_rate_limit_mem), encoding="utf-8")
    except Exception:
        pass


def _cleanup_expired(now: float, window: float) -> None:
    expired = [k for k, v in _rate_limit_mem.items() if now - v.get("start", 0) > window]
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
    log_entry = json.dumps({
        "timestamp": timestamp,
        "user": username,
        "action": action,
        "detail": detail,
        "ip": ip,
    }, ensure_ascii=False) + "\n"
    with _audit_lock:
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)


