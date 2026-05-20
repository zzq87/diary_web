"""配置管理模块"""

import os
import sys
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("diary")

BASE_DIR = Path(__file__).resolve().parent.parent

DIARY_DIR = Path(os.environ.get("DIARY_DIR", BASE_DIR / "data"))
DIARY_DIR.mkdir(parents=True, exist_ok=True)

SECRET_KEY = os.environ.get("DIARY_SECRET_KEY", "")
SESSION_TIMEOUT = int(os.environ.get("DIARY_SESSION_TIMEOUT", "3600"))
MAX_LOGIN_ATTEMPTS = int(os.environ.get("DIARY_MAX_LOGIN_ATTEMPTS", "5"))
LOGIN_LOCKOUT_SECONDS = int(os.environ.get("DIARY_LOGIN_LOCKOUT", "300"))
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 100
ENCRYPTION_ENABLED = os.environ.get("DIARY_ENCRYPT", "true").lower() == "true"

DEFAULT_PASSWORD = os.environ.get("DIARY_DEFAULT_PASSWORD", "")
if not DEFAULT_PASSWORD:
    DEFAULT_PASSWORD = os.environ.get("DIARY_ADMIN_PASSWORD", "admin123")
    if DEFAULT_PASSWORD == "admin123":
        logger.warning("⚠️ 使用默认密码 'admin123'，请通过 DIARY_DEFAULT_PASSWORD 环境变量修改")

CONFIG_DIR = BASE_DIR / "config"
CONFIG_DIR.mkdir(exist_ok=True)
USERS_FILE = CONFIG_DIR / "users.json"
AUDIT_FILE = CONFIG_DIR / "audit.log"
SESSIONS_FILE = CONFIG_DIR / "sessions.json"
RATE_LIMIT_FILE = CONFIG_DIR / "rate_limits.json"
MASTER_KEY_FILE = CONFIG_DIR / "master.key"

PBKDF2_ITERATIONS = int(os.environ.get("DIARY_PBKDF2_ITERATIONS", "600000"))

PORT = int(os.environ.get("DIARY_PORT", "9000"))
PROXY_CONNECT_ADDR = os.environ.get("DIARY_PROXY_CONNECT_ADDR", "192.168.1.2")


def safe_chmod(path: Path, mode: int) -> None:
    if sys.platform != "win32":
        try:
            path.chmod(mode)
        except OSError:
            pass


def ensure_dirs() -> None:
    for d in [CONFIG_DIR, DIARY_DIR]:
        d.mkdir(parents=True, exist_ok=True)
        safe_chmod(d, 0o700)
