#!/usr/bin/env python3
"""本地日记本 Web 应用入口"""

import socket
import logging

from app.config import PORT
from app.api import create_app

logger = logging.getLogger("diary")


def get_local_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def main():
    import uvicorn

    local_ip = get_local_ip()

    print(f"\n日记本已启动!")
    print(f"   本地访问: http://127.0.0.1:{PORT}")
    print(f"   局域网访问: http://{local_ip}:{PORT}")
    from app.config import ENCRYPTION_ENABLED, DEFAULT_PASSWORD

    print(f"   加密存储: {'开启' if ENCRYPTION_ENABLED else '关闭'}")
    print(f"   默认账号: admin / {DEFAULT_PASSWORD}")
    print(f"   首次登录后请立即修改密码!")
    print(f"   健康检查: http://127.0.0.1:{PORT}/api/health\n")

    uvicorn.run(create_app(), host="0.0.0.0", port=PORT)


if __name__ == "__main__":
    main()
