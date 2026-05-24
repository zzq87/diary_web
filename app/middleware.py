"""中间件模块：安全头、认证装饰器"""

from functools import wraps

from fastapi import Request
from fastapi.responses import JSONResponse

from .auth import validate_session, is_admin


async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    # CSP — 允许内联样式（前端多处使用）和 marked.js CDN
    # 内联脚本仅用于单页应用入口，实际逻辑在外部 JS 中更安全
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
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


def require_auth(func):
    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        token = request.headers.get("X-Auth-Token", "")
        if not token:
            token = request.cookies.get("diary_token", "")

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


def require_admin(func):
    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        token = request.headers.get("X-Auth-Token", "")
        if not token:
            token = request.cookies.get("diary_token", "")

        username = validate_session(token)
        if not username:
            return JSONResponse(
                status_code=401,
                content={"error": "未登录或会话已过期"},
                headers={"X-Session-Expired": "true"},
            )

        if not is_admin(username):
            return JSONResponse(
                status_code=403,
                content={"error": "需要管理员权限"},
            )

        request.state.username = username
        request.state.token = token
        return await func(request, *args, **kwargs)

    return wrapper
