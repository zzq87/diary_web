"""统一错误处理模块"""

from fastapi import Request, FastAPI
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from pydantic import ValidationError
import logging

logger = logging.getLogger("diary.errors")


class AppError(Exception):
    """应用基础异常"""

    def __init__(self, message: str, status_code: int = 400, error_code: str = "APP_ERROR"):
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        super().__init__(message)


class AuthError(AppError):
    """认证错误"""

    def __init__(self, message: str = "未授权"):
        super().__init__(message, status_code=401, error_code="AUTH_ERROR")


class NotFoundError(AppError):
    """资源未找到"""

    def __init__(self, message: str = "资源不存在"):
        super().__init__(message, status_code=404, error_code="NOT_FOUND")


class ForbiddenError(AppError):
    """权限不足"""

    def __init__(self, message: str = "权限不足"):
        super().__init__(message, status_code=403, error_code="FORBIDDEN")


class RateLimitError(AppError):
    """频率限制"""

    def __init__(self, message: str = "请求过于频繁，请稍后重试"):
        super().__init__(message, status_code=429, error_code="RATE_LIMIT")


class ValidationError(AppError):
    """参数校验错误"""

    def __init__(self, message: str = "参数校验失败"):
        super().__init__(message, status_code=400, error_code="VALIDATION_ERROR")


async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
    """应用异常处理器"""
    logger.warning(f"AppError: {exc.error_code} - {exc.message} (path={request.url.path})")
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": exc.message, "error_code": exc.error_code},
    )


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Pydantic 验证错误处理器"""
    errors = []
    for error in exc.errors():
        loc = " -> ".join(str(x) for x in error["loc"])
        errors.append(f"{loc}: {error['msg']}")
    error_msg = "; ".join(errors)
    logger.warning(f"ValidationError: {error_msg} (path={request.url.path})")
    return JSONResponse(
        status_code=422,
        content={"error": f"参数校验失败: {error_msg}", "error_code": "VALIDATION_ERROR"},
    )


async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """通用异常处理器"""
    logger.exception(f"Unhandled error: {type(exc).__name__} (path={request.url.path})")
    return JSONResponse(
        status_code=500,
        content={"error": "服务器内部错误", "error_code": "INTERNAL_ERROR"},
    )


def register_exception_handlers(app: FastAPI) -> None:
    """注册异常处理器"""
    app.add_exception_handler(AppError, app_error_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, generic_exception_handler)