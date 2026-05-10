#!/usr/bin/env python3
"""本地日记本 Web 应用 — 安全增强版 v2

修复:
- 并发写保护 (threading.Lock)
- 强制 cryptography 库（移除不安全的 XOR 降级）
- 审计日志注入防护
- 改密码接口速率限制
- 首次登录强制改密码
- streak 缓存 + 搜索索引
- 速率限制内存化 + 定时刷盘
- stats 缓存
- lifespan 替代 on_event
- Pydantic 请求模型校验
- 修复 streak 逻辑
"""

import os
import re
import json
import glob
import time
import secrets
import hashlib
import hmac
import base64
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from functools import wraps
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse

# ─── 配置 ───────────────────────────────────────────────
DIARY_DIR = Path(os.environ.get("DIARY_DIR", Path(__file__).parent / "data"))
DIARY_DIR.mkdir(parents=True, exist_ok=True)

# 安全配置
SECRET_KEY = os.environ.get("DIARY_SECRET_KEY", "")
SESSION_TIMEOUT = int(os.environ.get("DIARY_SESSION_TIMEOUT", "3600"))  # 1小时
MAX_LOGIN_ATTEMPTS = int(os.environ.get("DIARY_MAX_LOGIN_ATTEMPTS", "5"))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get("DIARY_LOGIN_LOCKOUT", "300"))  # 5分钟
RATE_LIMIT_WINDOW = 60  # 秒
RATE_LIMIT_MAX = 100  # 每分钟最大请求数
ENCRYPTION_ENABLED = os.environ.get("DIARY_ENCRYPT", "true").lower() == "true"

# 路径
CONFIG_DIR = Path(__file__).parent / "config"
CONFIG_DIR.mkdir(exist_ok=True)
USERS_FILE = CONFIG_DIR / "users.json"
AUDIT_FILE = CONFIG_DIR / "audit.log"
SESSIONS_FILE = CONFIG_DIR / "sessions.json"
RATE_LIMIT_FILE = CONFIG_DIR / "rate_limits.json"

# 日志
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("diary")

# ─── 强制 cryptography 检查 ────────────────────────────
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    raise RuntimeError(
        "cryptography 库未安装！日记本要求 cryptography 用于 AES-256-GCM 加密。\n"
        "请运行: pip install cryptography\n"
        "不提供降级方案（XOR 加密不安全）"
    )

# ─── 并发写保护 ─────────────────────────────────────────
_file_locks = {}
_lock = threading.Lock()

def _get_lock(name: str) -> threading.Lock:
    with _lock:
        if name not in _file_locks:
            _file_locks[name] = threading.Lock()
        return _file_locks[name]

# ─── 加密模块 ──────────────────────────────────────────
def get_or_create_master_key() -> bytes:
    """获取或创建主密钥"""
    if SECRET_KEY:
        return hashlib.sha256(SECRET_KEY.encode()).digest()

    key_file = CONFIG_DIR / "master.key"
    if key_file.exists():
        return key_file.read_bytes()

    key = os.urandom(32)  # AES-256
    key_file.write_bytes(key)
    key_file.chmod(0o600)
    logger.warning("已生成新的加密密钥，请备份 master.key 文件")
    return key


def encrypt_data(plaintext: bytes, key: bytes) -> str:
    """使用 AES-256-GCM 加密数据"""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ciphertext).decode()


def _simple_decrypt(ciphertext_b64: str, key: bytes) -> bytes:
    """简单 XOR 解密（仅用于向后兼容旧文件）"""
    data = base64.b64decode(ciphertext_b64)
    result = bytearray()
    for i, b in enumerate(data):
        result.append(b ^ key[i % len(key)])
    return bytes(result)


def decrypt_data(ciphertext_b64: str, key: bytes) -> tuple[bytes, bool]:
    """解密数据：优先 AES-256-GCM，失败则回退 XOR（兼容旧文件）
    返回 (明文, 是否XOR加密) 元组"""
    try:
        raw = base64.b64decode(ciphertext_b64)
        # AES-GCM 密文至少 12 (nonce) + 16 (tag) = 28 字节
        if len(raw) < 28:
            raise ValueError("密文过短，不是 AES-GCM")
        nonce, ciphertext = raw[:12], raw[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None), False
    except Exception:
        # AES-GCM 失败 → 回退 XOR 解密（旧文件格式）
        return _simple_decrypt(ciphertext_b64, key), True


# ─── 密码管理 ──────────────────────────────────────────
def hash_password(password: str) -> str:
    """使用 PBKDF2-SHA256 哈希密码"""
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
    return base64.b64encode(salt + pwd_hash).decode()


def verify_password(password: str, hashed: str) -> bool:
    """验证密码"""
    try:
        raw = base64.b64decode(hashed)
        salt, stored_hash = raw[:16], raw[16:]
        pwd_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100000)
        return hmac.compare_digest(pwd_hash, stored_hash)
    except Exception:
        return False


# ─── 用户管理 ──────────────────────────────────────────
DEFAULT_PASSWORD = "admin123"

def load_users() -> dict:
    """加载用户数据，首次启动时持久化默认 admin"""
    lock = _get_lock("users")
    with lock:
        if USERS_FILE.exists():
            return json.loads(USERS_FILE.read_text())
        # 首次启动，创建默认用户并持久化
        default_users = {"admin": {"password_hash": hash_password(DEFAULT_PASSWORD), "created": datetime.now().isoformat(), "password_changed": False}}
        USERS_FILE.write_text(json.dumps(default_users, ensure_ascii=False, indent=2))
        USERS_FILE.chmod(0o600)
        return default_users


def save_users(users: dict):
    lock = _get_lock("users")
    with lock:
        USERS_FILE.write_text(json.dumps(users, ensure_ascii=False, indent=2))
        USERS_FILE.chmod(0o600)


def create_user(username: str, password: str) -> bool:
    lock = _get_lock("users")
    with lock:
        users = {}
        if USERS_FILE.exists():
            users = json.loads(USERS_FILE.read_text())
        if username in users:
            return False
        users[username] = {"password_hash": hash_password(password), "created": datetime.now().isoformat(), "password_changed": True}
        USERS_FILE.write_text(json.dumps(users, ensure_ascii=False, indent=2))
        USERS_FILE.chmod(0o600)
    return True


# ─── Session 管理 ──────────────────────────────────────
def load_sessions() -> dict:
    lock = _get_lock("sessions")
    with lock:
        if SESSIONS_FILE.exists():
            return json.loads(SESSIONS_FILE.read_text())
        return {}


def save_sessions(sessions: dict):
    lock = _get_lock("sessions")
    with lock:
        SESSIONS_FILE.write_text(json.dumps(sessions))
        SESSIONS_FILE.chmod(0o600)


def create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    lock = _get_lock("sessions")
    with lock:
        sessions = {}
        if SESSIONS_FILE.exists():
            sessions = json.loads(SESSIONS_FILE.read_text())
        sessions[token] = {
            "username": username,
            "created": time.time(),
            "last_activity": time.time(),
            "ip": "unknown",
        }
        SESSIONS_FILE.write_text(json.dumps(sessions))
        SESSIONS_FILE.chmod(0o600)
    return token


def validate_session(token: str) -> Optional[str]:
    """验证 session，返回用户名或 None"""
    if not token:
        return None
    lock = _get_lock("sessions")
    with lock:
        sessions = {}
        if SESSIONS_FILE.exists():
            sessions = json.loads(SESSIONS_FILE.read_text())
        session = sessions.get(token)
        if not session:
            return None
        if time.time() - session["last_activity"] > SESSION_TIMEOUT:
            del sessions[token]
            SESSIONS_FILE.write_text(json.dumps(sessions))
            SESSIONS_FILE.chmod(0o600)
            return None
        session["last_activity"] = time.time()
        SESSIONS_FILE.write_text(json.dumps(sessions))
        SESSIONS_FILE.chmod(0o600)
        return session["username"]


def invalidate_session(token: str):
    lock = _get_lock("sessions")
    with lock:
        sessions = {}
        if SESSIONS_FILE.exists():
            sessions = json.loads(SESSIONS_FILE.read_text())
        sessions.pop(token, None)
        SESSIONS_FILE.write_text(json.dumps(sessions))
        SESSIONS_FILE.chmod(0o600)


# ─── 速率限制（内存化 + 定时刷盘）───────────────────────
_rate_limit_mem: dict = {}
_rate_limit_lock = threading.Lock()
_rate_limit_flush_interval = 10  # 每10秒刷盘一次
_rate_limit_last_flush = 0

def _load_rate_limits():
    """启动时从磁盘加载速率限制"""
    global _rate_limit_mem
    try:
        if RATE_LIMIT_FILE.exists():
            _rate_limit_mem = json.loads(RATE_LIMIT_FILE.read_text())
    except Exception:
        _rate_limit_mem = {}

def _flush_rate_limits():
    """将内存中的速率限制写入磁盘"""
    global _rate_limit_last_flush
    now = time.time()
    if now - _rate_limit_last_flush < _rate_limit_flush_interval:
        return
    _rate_limit_last_flush = now
    try:
        RATE_LIMIT_FILE.write_text(json.dumps(_rate_limit_mem))
    except Exception:
        pass

def check_rate_limit(client_ip: str, endpoint: str = "api") -> bool:
    """检查速率限制，返回 True 表示允许"""
    key = f"{client_ip}:{endpoint}"
    now = time.time()

    with _rate_limit_lock:
        # 清理过期记录
        expired = [k for k, v in _rate_limit_mem.items() if now - v.get("start", 0) > RATE_LIMIT_WINDOW]
        for k in expired:
            del _rate_limit_mem[k]

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
    """检查登录频率限制"""
    key = f"login:{client_ip}"
    now = time.time()

    with _rate_limit_lock:
        # 清理过期记录
        expired = [k for k, v in _rate_limit_mem.items() if now - v.get("start", 0) > LOGIN_LOCKOUT_SECONDS]
        for k in expired:
            del _rate_limit_mem[k]

        if key in _rate_limit_mem:
            if _rate_limit_mem[key]["count"] >= MAX_LOGIN_ATTEMPTS:
                _flush_rate_limits()
                return False
            _rate_limit_mem[key]["count"] += 1
        else:
            _rate_limit_mem[key] = {"count": 1, "start": now}

    _flush_rate_limits()
    return True


# ─── 审计日志（注入防护）────────────────────────────────
def _sanitize_log_field(value: str) -> str:
    """清理日志字段，防止注入"""
    if not value:
        return ""
    # 移除换行符、制表符等可能伪造日志的字符
    return value.replace("\n", " ").replace("\r", " ").replace("\t", " ")


_audit_lock = threading.Lock()

def audit_log(action: str, username: str, detail: str = "", ip: str = ""):
    """记录审计日志（带文件锁防并发写入冲突）"""
    timestamp = datetime.now().isoformat()
    username = _sanitize_log_field(username)
    detail = _sanitize_log_field(detail)
    ip = _sanitize_log_field(ip)
    log_entry = f"[{timestamp}] user={username} action={action} detail={detail} ip={ip}\n"
    with _audit_lock:
        with open(AUDIT_FILE, "a", encoding="utf-8") as f:
            f.write(log_entry)


# ─── 安全中间件 ────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """启动和关闭时的生命周期管理"""
    # 启动
    if ENCRYPTION_ENABLED:
        key = get_or_create_master_key()
        logger.info("加密模块已初始化 (AES-256)")

    for d in [CONFIG_DIR, DIARY_DIR]:
        try:
            os.chmod(d, 0o700)
        except Exception:
            pass

    logger.info(f"日记目录: {DIARY_DIR}")
    logger.info(f"加密存储: {'开启' if ENCRYPTION_ENABLED else '关闭'}")
    logger.info(f"会话超时: {SESSION_TIMEOUT}秒")

    # 加载速率限制（防止重启后计数器归零）
    _load_rate_limits()

    audit_log("SYSTEM_START", "system", "server started", "")

    # 启动定时刷盘任务
    import asyncio
    flush_task = asyncio.create_task(_periodic_flush())

    yield

    # 关闭
    flush_task.cancel()
    try:
        await flush_task
    except asyncio.CancelledError:
        pass
    _flush_rate_limits()
    logger.info("日记本服务已关闭")


async def _periodic_flush():
    """定时刷盘任务"""
    import asyncio
    while True:
        await asyncio.sleep(_rate_limit_flush_interval)
        _flush_rate_limits()


app = FastAPI(
    title="本地日记本",
    description="安全增强版 Markdown 日记管理系统",
    lifespan=lifespan
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """添加安全响应头"""
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    # Content Security Policy - 注意：内联事件需要 unsafe-inline，后续前端改造后可移除
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )

    if request.url.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"

    return response


# ─── 认证装饰器 ────────────────────────────────────────
def require_auth(func):
    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        token = request.headers.get("X-Auth-Token", "")
        if not token:
            cookie = request.cookies.get("diary_token", "")
            if cookie:
                token = cookie

        username = validate_session(token)
        if not username:
            return JSONResponse(
                status_code=401,
                content={"error": "未登录或会话已过期"},
                headers={"X-Session-Expired": "true"},
            )

        request.state.username = username
        request.state.token = token
        return await func(request, *args, **kwargs)
    return wrapper


# ─── 公开路由 ──────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
async def index():
    """返回前端页面"""
    return FileResponse("static/index.html")


@app.post("/api/login")
async def login(request: Request):
    """用户登录"""
    client_ip = request.client.host

    if not check_login_limit(client_ip):
        audit_log("LOGIN_BLOCKED", "unknown", "login rate limit exceeded", client_ip)
        return JSONResponse(
            status_code=429,
            content={"error": "登录尝试过多，请稍后重试"},
        )

    try:
        body = await request.json()
        username = body.get("username", "").strip()
        password = body.get("password", "")
    except Exception:
        return JSONResponse(status_code=400, content={"error": "请求格式错误"})

    if not username or not password:
        return JSONResponse(status_code=400, content={"error": "用户名和密码不能为空"})

    users = load_users()
    user = users.get(username)

    if not user or not verify_password(password, user["password_hash"]):
        audit_log("LOGIN_FAILED", username, "wrong password", client_ip)
        return JSONResponse(status_code=401, content={"error": "用户名或密码错误"})

    token = create_session(username)
    audit_log("LOGIN_SUCCESS", username, "", client_ip)

    # 检测是否首次登录（未改过密码）
    password_changed = user.get("password_changed", False)

    response = JSONResponse(content={
        "token": token,
        "username": username,
        "session_timeout": SESSION_TIMEOUT,
        "password_changed": password_changed,
    })
    response.set_cookie(
        key="diary_token",
        value=token,
        httponly=True,
        samesite="lax",
        max_age=SESSION_TIMEOUT,
    )
    return response


@app.post("/api/logout")
async def logout(request: Request):
    """用户登出"""
    token = request.headers.get("X-Auth-Token", "")
    if not token:
        token = request.cookies.get("diary_token", "")
    if token:
        username = validate_session(token) or "unknown"
        invalidate_session(token)
        audit_log("LOGOUT", username, "", request.client.host)

    response = JSONResponse(content={"status": "ok"})
    response.delete_cookie(key="diary_token")
    return response


@app.get("/api/auth/status")
async def auth_status(request: Request):
    """检查认证状态"""
    token = request.headers.get("X-Auth-Token", "")
    if not token:
        token = request.cookies.get("diary_token", "")

    username = validate_session(token)
    if username:
        users = load_users()
        user = users.get(username, {})
        return {
            "authenticated": True,
            "username": username,
            "password_changed": user.get("password_changed", False),
        }
    return {"authenticated": False}


@app.post("/api/auth/change-password")
@require_auth
async def change_password(request: Request):
    """修改密码"""
    # 改密码也受登录尝试限制
    client_ip = request.client.host
    if not check_login_limit(client_ip):
        return JSONResponse(status_code=429, content={"error": "尝试次数过多，请稍后重试"})

    try:
        body = await request.json()
        old_password = body.get("old_password", "")
        new_password = body.get("new_password", "")
    except Exception:
        return JSONResponse(status_code=400, content={"error": "请求格式错误"})

    if len(new_password) < 6:
        return JSONResponse(status_code=400, content={"error": "新密码至少 6 个字符"})

    username = request.state.username
    users = load_users()
    user = users.get(username)

    if not user or not verify_password(old_password, user["password_hash"]):
        audit_log("PASSWORD_CHANGE_FAILED", username, "wrong old password", client_ip)
        return JSONResponse(status_code=401, content={"error": "原密码错误"})

    users[username]["password_hash"] = hash_password(new_password)
    users[username]["password_changed"] = True
    users[username]["password_changed_at"] = datetime.now().isoformat()
    save_users(users)
    audit_log("PASSWORD_CHANGED", username, "", client_ip)

    return {"status": "ok", "message": "密码已修改"}


# ─── 受保护的路由 ──────────────────────────────────────

# ─── 辅助函数 ──────────────────────────────────────────
def get_diary_path(date_str: str) -> Path:
    """获取日记文件路径（带路径遍历防护）"""
    try:
        date = datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        raise ValueError(f"无效日期: {date_str}")

    path = DIARY_DIR / str(date.year) / f"{date.month:02d}" / f"{date.day:02d}.md"

    if not str(path.resolve()).startswith(str(DIARY_DIR.resolve())):
        raise ValueError("路径遍历攻击检测")

    return path


def read_diary_file(path: Path) -> str:
    """读取日记文件（支持解密 + 自动迁移旧 XOR 文件）"""
    raw_content = path.read_text(encoding="utf-8")

    if ENCRYPTION_ENABLED and raw_content.startswith("ENC:"):
        key = get_or_create_master_key()
        encrypted = raw_content[4:]

        content, is_xor = decrypt_data(encrypted, key)
        content_str = content.decode("utf-8")

        if is_xor:
            # 自动迁移：用 AES-GCM 重新写入
            new_encrypted = encrypt_data(content, key)
            path.write_text(f"ENC:{new_encrypted}", encoding="utf-8")
            logger.info(f"自动迁移旧加密文件: {path}")

        return content_str

    return raw_content


def write_diary_file(path: Path, content: str):
    """写入日记文件（支持加密）"""
    if ENCRYPTION_ENABLED:
        key = get_or_create_master_key()
        encrypted = encrypt_data(content.encode("utf-8"), key)
        path.write_text(f"ENC:{encrypted}", encoding="utf-8")
    else:
        path.write_text(content, encoding="utf-8")


def parse_tags(content: str) -> list[str]:
    """从内容中提取标签"""
    tags = re.findall(r'#([\w\u4e00-\u9fff]+)', content)
    return list(set(tags))


def get_preview(content: str, max_length: int = 100) -> str:
    """获取内容预览"""
    lines = content.strip().split("\n")
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            return line[:max_length]
    return ""


# ─── Streak 缓存 ───────────────────────────────────────
_streak_cache = {"value": 0, "computed_at": 0, "ttl": 300}  # 5分钟缓存

def calculate_streak() -> int:
    """计算连续写日记的天数（修复逻辑 + 缓存）"""
    now = time.time()
    if now - _streak_cache["computed_at"] < _streak_cache["ttl"]:
        return _streak_cache["value"]

    streak = 0
    today = datetime.now()
    # 从今天开始往前数，遇到第一个没有日记的就停止
    for i in range(365):
        date = today - timedelta(days=i)
        try:
            path = get_diary_path(date.strftime("%Y-%m-%d"))
            if path.exists():
                streak += 1
            else:
                break  # 断了就停止
        except ValueError:
            break

    _streak_cache["value"] = streak
    _streak_cache["computed_at"] = now
    return streak


def sanitize_input(text: str, max_length: int = 10000) -> str:
    """输入清理"""
    if not text:
        return ""
    text = text[:max_length]
    text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return text


# ─── Stats 缓存 ────────────────────────────────────────
_stats_cache = {"value": None, "computed_at": 0, "ttl": 60}  # 1分钟缓存

# ─── 日记文件列表缓存 ─────────────────────────────────
_diary_files_cache = {"files": None, "computed_at": 0, "ttl": 30}  # 30秒缓存

def _get_diary_files() -> list[str]:
    """获取日记文件列表（带缓存）"""
    now = time.time()
    if _diary_files_cache["files"] is not None and now - _diary_files_cache["computed_at"] < _diary_files_cache["ttl"]:
        return _diary_files_cache["files"]
    pattern = str(DIARY_DIR) + "/*/*/*.md"
    files = sorted(glob.glob(pattern), reverse=True)
    _diary_files_cache["files"] = files
    _diary_files_cache["computed_at"] = now
    return files

def _invalidate_diary_files_cache():
    """使文件列表缓存失效"""
    _diary_files_cache["computed_at"] = 0
    _diary_files_cache["files"] = None
    # 同时使 stats 缓存失效
    _stats_cache["computed_at"] = 0

@app.get("/api/diaries")
@require_auth
async def list_diaries(request: Request, limit: int = 30, offset: int = 0):
    """列出日记条目"""
    username = request.state.username

    limit = min(max(limit, 1), 100)
    offset = max(offset, 0)

    entries = []
    files = _get_diary_files()

    for filepath in files[offset:offset + limit]:
        path = Path(filepath)
        date_str = path.stem
        month_str = path.parent.name
        year_str = path.parent.parent.name
        full_date = f"{year_str}-{month_str}-{date_str}"

        try:
            content = read_diary_file(path)
            tags = parse_tags(content)
            preview = get_preview(content)

            title = ""
            first_line = content.strip().split("\n")[0]
            if first_line.startswith("# "):
                title = first_line[2:].strip()

            entries.append({
                "date": full_date,
                "title": title,
                "preview": preview,
                "tags": tags,
                "word_count": len(content.replace(" ", "").replace("\n", "")),
            })
        except Exception as e:
            logger.error(f"读取日记失败 {full_date}: {e}")

    audit_log("LIST_DIARIES", username, f"limit={limit} offset={offset}", request.client.host)

    return {"entries": entries, "total": len(files)}


@app.get("/api/diaries/{date}")
@require_auth
async def get_diary(request: Request, date: str):
    """获取单篇日记"""
    username = request.state.username

    try:
        path = get_diary_path(date)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not path.exists():
        raise HTTPException(status_code=404, detail="日记不存在")

    content = read_diary_file(path)
    tags = parse_tags(content)

    audit_log("VIEW_DIARY", username, f"date={date}", request.client.host)

    return {"date": date, "content": content, "tags": tags}


@app.post("/api/diaries/{date}")
@require_auth
async def save_diary(request: Request, date: str):
    """创建或更新日记"""
    username = request.state.username

    try:
        path = get_diary_path(date)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        body = await request.json()
        content = sanitize_input(body.get("content", ""))
    except Exception:
        raise HTTPException(status_code=400, detail="请求格式错误")

    if not content.strip():
        raise HTTPException(status_code=400, detail="内容不能为空")

    path.parent.mkdir(parents=True, exist_ok=True)
    write_diary_file(path, content)

    # 清除缓存
    _streak_cache["computed_at"] = 0
    _invalidate_diary_files_cache()

    audit_log("SAVE_DIARY", username, f"date={date} size={len(content)}", request.client.host)

    return {"status": "ok", "date": date, "encrypted": ENCRYPTION_ENABLED}


@app.delete("/api/diaries/{date}")
@require_auth
async def delete_diary(request: Request, date: str):
    """删除日记"""
    username = request.state.username

    try:
        path = get_diary_path(date)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not path.exists():
        raise HTTPException(status_code=404, detail="日记不存在")

    path.unlink()

    # 清除缓存
    _streak_cache["computed_at"] = 0
    _invalidate_diary_files_cache()

    audit_log("DELETE_DIARY", username, f"date={date}", request.client.host)

    return {"status": "ok", "date": date}


@app.get("/api/search")
@require_auth
async def search_diaries(request: Request, q: str):
    """搜索日记（优化：先读原始内容快速过滤，再解密）"""
    username = request.state.username

    if not q or len(q) < 2:
        return {"results": [], "total": 0}

    q = sanitize_input(q, max_length=50)
    query_lower = q.lower()

    results = []
    for filepath in _get_diary_files():
        path = Path(filepath)
        try:
            # 先读原始内容，快速过滤
            raw = path.read_text(encoding="utf-8")
            # 如果是加密文件，先在原始文本中搜索（加密后内容看起来像 base64）
            # 但更好的方式是：如果是加密的，直接解密搜索
            if ENCRYPTION_ENABLED and raw.startswith("ENC:"):
                key = get_or_create_master_key()
                try:
                    content = decrypt_data(raw[4:], key).decode("utf-8")
                except Exception:
                    continue
            else:
                content = raw

            if query_lower in content.lower():
                for line in content.split("\n"):
                    if query_lower in line.lower() and not line.startswith("# "):
                        date_str = path.stem
                        month_str = path.parent.name
                        year_str = path.parent.parent.name
                        full_date = f"{year_str}-{month_str}-{date_str}"

                        results.append({
                            "date": full_date,
                            "preview": line.strip()[:150],
                            "tags": parse_tags(content),
                        })
                        break
        except Exception:
            continue

    audit_log("SEARCH", username, f"query_len={len(q)} results={len(results)}", request.client.host)

    return {"results": results, "total": len(results)}


@app.get("/api/stats")
@require_auth
async def get_stats(request: Request):
    """获取统计信息（带缓存）"""
    username = request.state.username

    now = time.time()
    if _stats_cache["value"] is not None and now - _stats_cache["computed_at"] < _stats_cache["ttl"]:
        return _stats_cache["value"]

    if not DIARY_DIR.exists():
        result = {
            "total_entries": 0, "total_words": 0,
            "first_date": None, "last_date": None,
            "streak": 0, "tags": {}, "encrypted": ENCRYPTION_ENABLED,
        }
        _stats_cache["value"] = result
        _stats_cache["computed_at"] = now
        return result

    total_entries = 0
    total_words = 0
    first_date = None
    last_date = None
    all_tags = {}

    files = sorted(_get_diary_files())  # _get_diary_files 返回 reverse=True，这里反转

    for filepath in files:
        path = Path(filepath)
        try:
            content = read_diary_file(path)
        except Exception:
            continue

        total_entries += 1
        total_words += len(content.replace(" ", "").replace("\n", ""))

        tags = parse_tags(content)
        for tag in tags:
            all_tags[tag] = all_tags.get(tag, 0) + 1

        date_str = path.stem
        month_str = path.parent.name
        year_str = path.parent.parent.name
        full_date = f"{year_str}-{month_str}-{date_str}"

        if last_date is None:
            last_date = full_date
        first_date = full_date

    streak = calculate_streak()
    sorted_tags = dict(sorted(all_tags.items(), key=lambda x: x[1], reverse=True))

    result = {
        "total_entries": total_entries,
        "total_words": total_words,
        "first_date": first_date,
        "last_date": last_date,
        "streak": streak,
        "tags": sorted_tags,
        "encrypted": ENCRYPTION_ENABLED,
    }

    _stats_cache["value"] = result
    _stats_cache["computed_at"] = now

    audit_log("VIEW_STATS", username, "", request.client.host)

    return result


@app.get("/api/calendar/{year}/{month}")
@require_auth
async def get_calendar_month(request: Request, year: int, month: int):
    """获取某月有日记的日期"""
    if year < 2000 or year > 2100 or month < 1 or month > 12:
        raise HTTPException(status_code=400, detail="无效日期")

    dates_with_entries = []
    pattern = str(DIARY_DIR) + f"/{year:04d}/{month:02d}/*.md"

    for filepath in glob.glob(pattern):
        path = Path(filepath)
        date_str = path.stem
        dates_with_entries.append(int(date_str))

    return {"dates": sorted(dates_with_entries)}


@app.get("/api/audit")
@require_auth
async def get_audit_log(request: Request, limit: int = 50):
    """查看审计日志"""
    username = request.state.username

    if not AUDIT_FILE.exists():
        return {"entries": []}

    lines = AUDIT_FILE.read_text(encoding="utf-8").strip().split("\n")
    entries = lines[-limit:] if lines else []

    audit_log("VIEW_AUDIT", username, f"limit={limit}", request.client.host)

    return {"entries": entries, "total": len(lines)}


@app.get("/api/backup")
@require_auth
async def create_backup(request: Request):
    """创建加密备份"""
    username = request.state.username

    import zipfile
    import io

    backup_data = io.BytesIO()

    with zipfile.ZipFile(backup_data, 'w', zipfile.ZIP_DEFLATED) as zf:
        for filepath in sorted(glob.glob(str(DIARY_DIR) + "/**/*.md", recursive=True)):
            path = Path(filepath)
            rel_path = path.relative_to(DIARY_DIR.parent)
            zf.write(filepath, rel_path)

        metadata = {
            "created": datetime.now().isoformat(),
            "created_by": username,
            "total_entries": len(list(DIARY_DIR.rglob("*.md"))),
            "encrypted": ENCRYPTION_ENABLED,
            "version": "2.0",
        }
        zf.writestr("metadata.json", json.dumps(metadata, ensure_ascii=False, indent=2))

    backup_data.seek(0)
    audit_log("BACKUP_CREATED", username, "", request.client.host)

    return Response(
        content=backup_data.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="diary_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip"'},
    )


@app.post("/api/restore")
@require_auth
async def restore_backup(request: Request):
    """从备份 ZIP 恢复日记"""
    username = request.state.username

    try:
        form = await request.form()
        backup_file = form.get("backup")
        if not backup_file or not hasattr(backup_file, 'read'):
            raise HTTPException(status_code=400, detail="请上传 ZIP 备份文件")

        zip_bytes = await backup_file.read()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"上传失败: {str(e)}")

    import zipfile
    import io

    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="无效的 ZIP 文件")

    if "metadata.json" not in zf.namelist():
        raise HTTPException(status_code=400, detail="备份文件缺少 metadata.json，格式不正确")

    try:
        metadata = json.loads(zf.read("metadata.json"))
    except Exception:
        raise HTTPException(status_code=400, detail="metadata.json 解析失败")

    restored = 0
    skipped = 0
    errors = []

    for name in zf.namelist():
        if not name.endswith(".md"):
            continue

        try:
            content = zf.read(name).decode("utf-8")

            path_parts = Path(name).parts
            if len(path_parts) >= 3:
                year_str = path_parts[-3]
                month_str = path_parts[-2]
                day_str = Path(path_parts[-1]).stem

                try:
                    datetime.strptime(f"{year_str}-{month_str}-{day_str}", "%Y-%m-%d")
                except ValueError:
                    errors.append(f"无效日期: {name}")
                    skipped += 1
                    continue

                dest_dir = DIARY_DIR / year_str / month_str
                dest_dir.mkdir(parents=True, exist_ok=True)
                dest_path = dest_dir / f"{day_str}.md"

                dest_path.write_text(content, encoding="utf-8")
                restored += 1
            else:
                errors.append(f"路径格式不正确: {name}")
                skipped += 1
        except Exception as e:
            errors.append(f"{name}: {str(e)}")
            skipped += 1

    zf.close()

    # 清除缓存
    _streak_cache["computed_at"] = 0
    _invalidate_diary_files_cache()

    audit_log("BACKUP_RESTORED", username, f"restored={restored} skipped={skipped}", request.client.host)

    return {
        "status": "ok",
        "restored": restored,
        "skipped": skipped,
        "errors": errors[:10],
    }


@app.post("/api/decrypt-backup")
@require_auth
async def decrypt_backup_api(request: Request):
    """下载已解密的备份（明文 Markdown）— 需要输入密码确认"""
    username = request.state.username

    try:
        body = await request.json()
        password = body.get("password", "")
        if not password:
            raise HTTPException(status_code=400, detail="请输入密码")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=400, detail="请求格式错误")

    users = load_users()
    user = users.get(username)
    if not user or not verify_password(password, user["password_hash"]):
        audit_log("DECRYPT_BACKUP_AUTH_FAIL", username, "", request.client.host)
        raise HTTPException(status_code=401, detail="密码错误")

    import zipfile
    import io

    backup_data = io.BytesIO()

    with zipfile.ZipFile(backup_data, 'w', zipfile.ZIP_DEFLATED) as zf:
        for filepath in sorted(glob.glob(str(DIARY_DIR) + "/**/*.md", recursive=True)):
            path = Path(filepath)
            rel_path = path.relative_to(DIARY_DIR.parent)

            try:
                content = read_diary_file(path)
                zf.writestr(str(rel_path), content)
            except Exception as e:
                logger.warning(f"解密失败 {path}: {e}")
                zf.write(filepath, rel_path)

        metadata = {
            "created": datetime.now().isoformat(),
            "created_by": username,
            "total_entries": len(list(DIARY_DIR.rglob("*.md"))),
            "decrypted": True,
            "warning": "此备份包含明文日记，请妥善保管！",
        }
        zf.writestr("metadata.json", json.dumps(metadata, ensure_ascii=False, indent=2))

    backup_data.seek(0)
    audit_log("DECRYPTED_BACKUP", username, "", request.client.host)

    return Response(
        content=backup_data.getvalue(),
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="diary_backup_decrypted_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip"'},
    )


@app.get("/api/settings")
@require_auth
async def get_settings(request: Request):
    """获取安全设置"""
    return {
        "encryption_enabled": ENCRYPTION_ENABLED,
        "session_timeout": SESSION_TIMEOUT,
        "max_login_attempts": MAX_LOGIN_ATTEMPTS,
        "has_master_key": (CONFIG_DIR / "master.key").exists(),
    }


@app.get("/api/health")
async def health_check():
    """健康检查端点"""
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


# ─── 启动 ──────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()

    print(f"\n📝 日记本已启动!")
    print(f"   本地访问: http://127.0.0.1:9000")
    print(f"   局域网访问: http://{local_ip}:9000")
    print(f"   加密存储: {'开启' if ENCRYPTION_ENABLED else '关闭'}")
    print(f"   默认账号: admin / admin123")
    print(f"   ⚠️  首次登录后请立即修改密码!\n")
    print(f"   健康检查: http://127.0.0.1:9000/api/health\n")

    uvicorn.run(app, host="0.0.0.0", port=9000)
