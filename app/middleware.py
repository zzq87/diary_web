"""中间件模块：安全头、认证装饰器、速率限制"""

from functools import wraps
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse

from .auth import validate_session, is_admin, check_rate_limit


async def security_headers_middleware(request: Request, call_next):
    """安全响应头中间件"""
    response = await call_next(request)

    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
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


def _extract_token(request: Request) -> str:
    return request.headers.get("X-Auth-Token", "") or request.cookies.get("diary_token", "")


def _set_request_user(request: Request, username: str) -> None:
    request.state.username = username


def _auth_and_set_user(request: Request) -> str:
    """通用认证逻辑，返回 username，失败则返回 None。仅执行一次 load_users 并缓存 role。"""
    token = _extract_token(request)
    username = validate_session(token)
    if not username:
        return None
    _set_request_user(request, username)
    # 缓存角色到 request.state，避免 require_admin 二次 load_users
    if not hasattr(request.state, "role"):
        request.state.role = "admin" if is_admin(username) else "user"
    return username


def rate_limit(endpoint: str = "api"):
    """速率限制 FastAPI 依赖"""

    def dependency(request: Request):
        client_ip = request.client.host or "unknown"
        if not check_rate_limit(client_ip, endpoint):
            raise HTTPException(status_code=429, detail="请求过于频繁，请稍后重试")

    return dependency


def require_auth(func):
    """认证装饰器"""

    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        username = _auth_and_set_user(request)
        if not username:
            return JSONResponse(
                status_code=401,
                content={"error": "未登录或会话已过期"},
                headers={"X-Session-Expired": "true"},
            )
        return await func(*args, request=request, **kwargs)

    return wrapper


def require_admin(func):
    """管理员权限装饰器 — 复用 _auth_and_set_user 缓存"""

    @wraps(func)
    async def wrapper(request: Request, *args, **kwargs):
        username = _auth_and_set_user(request)
        if not username:
            return JSONResponse(
                status_code=401,
                content={"error": "未登录或会话已过期"},
                headers={"X-Session-Expired": "true"},
            )
        if request.state.role != "admin":
            return JSONResponse(
                status_code=403,
                content={"error": "需要管理员权限"},
            )
        return await func(*args, request=request, **kwargs)

    return wrapper
