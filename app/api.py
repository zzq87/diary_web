"""API 路由模块 — 使用 Pydantic 模型校验"""

import json
import logging
import asyncio
import zipfile
import io
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, UploadFile, File
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, StreamingResponse

from .config import (
    DIARY_DIR,
    SESSION_TIMEOUT,
    MAX_LOGIN_ATTEMPTS,
    ENCRYPTION_ENABLED,
    CONFIG_DIR,
    BASE_DIR,
    AUDIT_FILE,
    safe_chmod,
    ensure_dirs,
)
from .auth import (
    load_users,
    save_users,
    verify_password,
    hash_password,
    create_session,
    validate_session,
    invalidate_session,
    cleanup_expired_sessions,
    check_rate_limit,
    check_login_limit,
    audit_log,
    _load_rate_limits,
    _flush_rate_limits,
    create_user,
    delete_user,
    update_user,
    list_users,
    is_admin,
)
from . import search as search_index
from .diary import (
    get_diary_path,
    read_diary_file,
    read_diary_file_sync,
    read_diary_preview,
    write_diary_file,
    parse_tags,
    get_preview,
    sanitize_input,
    _get_diary_files,
    _invalidate_diary_files_cache,
    search_diaries,
    get_stats,
    get_calendar_month,
)
from .crypto import get_or_create_master_key
from .middleware import security_headers_middleware, require_auth, require_admin
from .errors import (
    AppError,
    AuthError,
    NotFoundError,
    ForbiddenError,
    RateLimitError,
    register_exception_handlers,
)
from .schemas import (
    LoginRequest,
    RegisterRequest,
    ChangePasswordRequest,
    UserCreateRequest,
    UserUpdateRequest,
    DiarySaveRequest,
    DecryptBackupRequest,
    LoginResponse,
    AuthStatusResponse,
    UsersResponse,
    DiaryEntry,
    DiariesResponse,
    DiaryDetail,
    SearchResponse,
    StatsResponse,
    CalendarResponse,
    AuditResponse,
    SettingsResponse,
    HealthResponse,
    RestoreResponse,
    ErrorResponse,
)

logger = logging.getLogger("diary.api")


def create_app() -> FastAPI:

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        ensure_dirs()
        logger.info(f"日记目录: {DIARY_DIR}")
        logger.info(f"加密存储: {'开启' if ENCRYPTION_ENABLED else '关闭'}")
        logger.info(f"会话超时: {SESSION_TIMEOUT}秒")

        _load_rate_limits()
        audit_log("SYSTEM_START", "system", "server started", "")

        flush_task = asyncio.create_task(_periodic_flush())
        session_cleanup_task = asyncio.create_task(_periodic_session_cleanup())
        yield

        flush_task.cancel()
        session_cleanup_task.cancel()
        try:
            await flush_task
            await session_cleanup_task
        except asyncio.CancelledError:
            pass
        _flush_rate_limits()
        audit_log("SYSTEM_STOP", "system", "server stopped", "")
        logger.info("日记本服务已关闭")

    async def _periodic_flush():
        while True:
            await asyncio.sleep(10)
            _flush_rate_limits()

    async def _periodic_session_cleanup():
        while True:
            await asyncio.sleep(300)
            cleanup_expired_sessions()

    app = FastAPI(
        title="本地日记本",
        description="安全增强版 Markdown 日记管理系统",
        lifespan=lifespan,
    )

    app.middleware("http")(security_headers_middleware)
    register_exception_handlers(app)
    _register_routes(app)
    return app


def _register_routes(app: FastAPI) -> None:

    # ─── 公开路由 ──────────────────────────────────────
    @app.get("/", response_class=HTMLResponse)
    async def index():
        response = FileResponse(str(BASE_DIR / "static" / "index.html"))
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response

    @app.post("/api/login", response_model=LoginResponse)
    async def login(data: LoginRequest, request: Request):
        client_ip = request.client.host or "unknown"

        if not check_login_limit(client_ip):
            audit_log("LOGIN_BLOCKED", "unknown", "login rate limit exceeded", client_ip)
            raise HTTPException(status_code=429, detail="登录尝试过多，请稍后重试")

        users = load_users()
        user = users.get(data.username)

        if not user or not verify_password(data.password, user["password_hash"]):
            audit_log("LOGIN_FAILED", data.username, "wrong password", client_ip)
            raise HTTPException(status_code=401, detail="用户名或密码错误")

        token = create_session(data.username, ip=client_ip)
        audit_log("LOGIN_SUCCESS", data.username, "", client_ip)

        password_changed = user.get("password_changed", False)

        response = JSONResponse(
            content=LoginResponse(
                token=token,
                username=data.username,
                session_timeout=SESSION_TIMEOUT,
                password_changed=password_changed,
                role=user.get("role", "user"),
            ).model_dump()
        )
        response.set_cookie(
            key="diary_token",
            value=token,
            httponly=True,
            samesite="lax",
            max_age=SESSION_TIMEOUT,
            secure=False,
        )
        return response

    @app.post("/api/logout")
    async def logout(request: Request):
        token = request.headers.get("X-Auth-Token", "") or request.cookies.get("diary_token", "")
        if token:
            username = validate_session(token) or "unknown"
            invalidate_session(token)
            audit_log("LOGOUT", username, "", request.client.host or "unknown")

        response = JSONResponse(content={"status": "ok"})
        response.delete_cookie(key="diary_token")
        return response

    @app.get("/api/auth/status", response_model=AuthStatusResponse)
    async def auth_status(request: Request):
        token = request.headers.get("X-Auth-Token", "") or request.cookies.get("diary_token", "")
        username = validate_session(token)
        if username:
            users = load_users()
            user = users.get(username, {})
            role = user.get("role", "admin" if username == "admin" else "user")
            return AuthStatusResponse(
                authenticated=True,
                username=username,
                role=role,
                password_changed=user.get("password_changed", False),
            )
        return AuthStatusResponse(authenticated=False)

    @app.post("/api/auth/register")
    async def register(data: RegisterRequest, request: Request):
        client_ip = request.client.host or "unknown"
        if not check_login_limit(client_ip):
            raise HTTPException(status_code=429, detail="尝试次数过多，请稍后重试")

        if create_user(data.username, data.password, role="user"):
            audit_log("USER_REGISTERED", data.username, f"ip={client_ip}", client_ip)
            return {"status": "ok", "message": "注册成功，请登录"}
        raise HTTPException(status_code=409, detail="用户名已存在")

    @app.post("/api/auth/change-password")
    @require_auth
    async def change_password(data: ChangePasswordRequest, request: Request):
        client_ip = request.client.host or "unknown"
        if not check_login_limit(client_ip):
            raise HTTPException(status_code=429, detail="尝试次数过多，请稍后重试")

        username = request.state.username
        users = load_users()
        user = users.get(username)

        if not user or not verify_password(data.old_password, user["password_hash"]):
            audit_log("PASSWORD_CHANGE_FAILED", username, "wrong old password", client_ip)
            raise HTTPException(status_code=401, detail="原密码错误")

        users[username]["password_hash"] = hash_password(data.new_password)
        users[username]["password_changed"] = True
        users[username]["password_changed_at"] = datetime.now().isoformat()
        save_users(users)
        audit_log("PASSWORD_CHANGED", username, "", client_ip)

        return {"status": "ok", "message": "密码已修改"}

    # ─── 用户管理（仅管理员）───────────────────────────
    @app.get("/api/users", response_model=UsersResponse)
    @require_admin
    async def get_users(request: Request):
        username = request.state.username
        audit_log("LIST_USERS", username, "", request.client.host or "unknown")
        return {"users": list_users()}

    @app.post("/api/users", status_code=201)
    @require_admin
    async def admin_create_user(data: UserCreateRequest, request: Request):
        admin_name = request.state.username
        if create_user(data.username, data.password, role=data.role):
            audit_log("ADMIN_CREATE_USER", admin_name, f"target={data.username} role={data.role}", request.client.host or "unknown")
            return {"status": "ok", "message": f"用户 {data.username} 已创建"}
        raise HTTPException(status_code=409, detail="用户名已存在")

    @app.put("/api/users/{target_username}")
    @require_admin
    async def admin_update_user(target_username: str, data: UserUpdateRequest, request: Request):
        admin_name = request.state.username
        updates = {}
        if data.role is not None:
            updates["role"] = data.role
        if data.password:
            updates["password_hash"] = hash_password(data.password)
            updates["password_changed"] = True

        if not updates:
            raise HTTPException(status_code=400, detail="没有要更新的字段")

        if update_user(target_username, **updates):
            audit_log("ADMIN_UPDATE_USER", admin_name, f"target={target_username}", request.client.host or "unknown")
            return {"status": "ok", "message": f"用户 {target_username} 已更新"}
        raise HTTPException(status_code=404, detail="用户不存在")

    @app.delete("/api/users/{target_username}")
    @require_admin
    async def admin_delete_user(target_username: str, request: Request):
        admin_name = request.state.username
        if target_username == admin_name:
            raise HTTPException(status_code=400, detail="不能删除自己")
        if delete_user(target_username):
            audit_log("ADMIN_DELETE_USER", admin_name, f"target={target_username}", request.client.host or "unknown")
            return {"status": "ok", "message": f"用户 {target_username} 已删除"}
        raise HTTPException(status_code=404, detail="用户不存在")

    # ─── 日记相关 ──────────────────────────────────────
    @app.get("/api/diaries", response_model=DiariesResponse)
    @require_auth
    async def list_diaries(request: Request, limit: int = 30, offset: int = 0):
        username = request.state.username
        limit = min(max(limit, 1), 100)
        offset = max(offset, 0)

        files = _get_diary_files()

        async def _read_entry(filepath: str) -> DiaryEntry | None:
            path = Path(filepath)
            date_str = path.stem
            month_str = path.parent.name
            year_str = path.parent.parent.name
            full_date = f"{year_str}-{month_str}-{date_str}"
            try:
                preview_content = await read_diary_preview(path, max_len=300)
                tags = parse_tags(preview_content)
                preview = get_preview(preview_content)
                title = ""
                first_line = preview_content.strip().split("\n")[0]
                if first_line.startswith("# "):
                    title = first_line[2:].strip()
                return DiaryEntry(
                    date=full_date,
                    title=title,
                    preview=preview,
                    tags=tags,
                    word_count=len(preview_content.replace(" ", "").replace("\n", "")),
                )
            except Exception as e:
                logger.error(f"读取日记失败 {full_date}: {e}")
                return None

        tasks = [_read_entry(f) for f in files[offset : offset + limit]]
        results = await asyncio.gather(*tasks)
        entries = [r for r in results if r is not None]

        audit_log("LIST_DIARIES", username, f"limit={limit} offset={offset}", request.client.host or "unknown")
        return {"entries": entries, "total": len(files)}

    @app.get("/api/diaries/{date}", response_model=DiaryDetail)
    @require_auth
    async def get_diary(date: str, request: Request):
        username = request.state.username
        try:
            path = get_diary_path(date)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        if not path.exists():
            raise HTTPException(status_code=404, detail="日记不存在")

        content = await read_diary_file(path)
        tags = parse_tags(content)

        audit_log("VIEW_DIARY", username, f"date={date}", request.client.host or "unknown")
        return {"date": date, "content": content, "tags": tags}

    @app.post("/api/diaries/{date}")
    @require_auth
    async def save_diary(date: str, data: DiarySaveRequest, request: Request):
        username = request.state.username
        try:
            path = get_diary_path(date)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        content = sanitize_input(data.content)
        if not content.strip():
            raise HTTPException(status_code=400, detail="内容不能为空")

        path.parent.mkdir(parents=True, exist_ok=True)
        await write_diary_file(path, content)

        _invalidate_diary_files_cache()
        tags_str = " ".join(parse_tags(content))
        search_index.update_in_index(content, str(path), date, tags_str)
        audit_log("SAVE_DIARY", username, f"date={date} size={len(content)}", request.client.host or "unknown")

        return {"status": "ok", "date": date, "encrypted": ENCRYPTION_ENABLED}

    @app.delete("/api/diaries/{date}")
    @require_auth
    async def delete_diary(date: str, request: Request):
        username = request.state.username
        try:
            path = get_diary_path(date)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        if not path.exists():
            raise HTTPException(status_code=404, detail="日记不存在")

        path.unlink()
        _invalidate_diary_files_cache()
        search_index.remove_from_index(str(path))
        audit_log("DELETE_DIARY", username, f"date={date}", request.client.host or "unknown")

        return {"status": "ok", "date": date}

    @app.get("/api/search", response_model=SearchResponse)
    @require_auth
    async def search(q: str, request: Request):
        username = request.state.username
        if not q or len(q) < 2:
            return {"results": [], "total": 0}

        q = sanitize_input(q, max_length=50)
        results = search_diaries(q)

        audit_log("SEARCH", username, f"query_len={len(q)} results={len(results)}", request.client.host or "unknown")
        return {"results": results, "total": len(results)}

    @app.get("/api/stats", response_model=StatsResponse)
    @require_auth
    async def stats(request: Request):
        username = request.state.username
        result = get_stats()
        audit_log("VIEW_STATS", username, "", request.client.host or "unknown")
        return result

    @app.get("/api/calendar/{year}/{month}", response_model=CalendarResponse)
    @require_auth
    async def calendar(year: int, month: int, request: Request):
        if year < 2000 or year > 2100 or month < 1 or month > 12:
            raise HTTPException(status_code=400, detail="无效日期")
        dates = get_calendar_month(year, month)
        return {"dates": dates}

    @app.get("/api/audit", response_model=AuditResponse)
    @require_auth
    async def audit(request: Request, limit: int = 50):
        username = request.state.username

        if not AUDIT_FILE.exists():
            return {"entries": [], "total": 0}

        lines = AUDIT_FILE.read_text(encoding="utf-8").strip().split("\n")
        entries = []
        for line in lines[-limit:]:
            if line.strip():
                try:
                    entry = json.loads(line)
                    # 格式化为字符串显示，保持前端兼容
                    formatted = f"[{entry.get('timestamp', '')}] user={entry.get('user', '')} action={entry.get('action', '')} detail={entry.get('detail', '')} ip={entry.get('ip', '')}"
                    entries.append(formatted)
                except json.JSONDecodeError:
                    # 兼容旧格式
                    entries.append(line)

        audit_log("VIEW_AUDIT", username, f"limit={limit}", request.client.host or "unknown")
        return {"entries": entries, "total": len(lines)}

    @app.get("/api/backup")
    @require_auth
    async def backup(request: Request):
        username = request.state.username

        def generate_backup():
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for filepath in sorted(DIARY_DIR.rglob("*.md")):
                    rel_path = filepath.relative_to(DIARY_DIR.parent)
                    zf.write(filepath, rel_path)

                metadata = {
                    "created": datetime.now().isoformat(),
                    "created_by": username,
                    "total_entries": len(list(DIARY_DIR.rglob("*.md"))),
                    "encrypted": ENCRYPTION_ENABLED,
                    "version": "3.0",
                }
                zf.writestr("metadata.json", __import__("json").dumps(metadata, ensure_ascii=False, indent=2))

            buf.seek(0)
            while True:
                chunk = buf.read(8192)
                if not chunk:
                    break
                yield chunk

        audit_log("BACKUP_CREATED", username, "", request.client.host or "unknown")
        return StreamingResponse(
            generate_backup(),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="diary_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip"'},
        )

    @app.post("/api/restore", response_model=RestoreResponse)
    @require_auth
    async def restore(request: Request, backup: UploadFile = File(...)):
        username = request.state.username

        if not backup.filename or not backup.filename.endswith(".zip"):
            raise HTTPException(status_code=400, detail="请上传 ZIP 备份文件")

        zip_bytes = await backup.read()

        try:
            zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="无效的 ZIP 文件")

        if "metadata.json" not in zf.namelist():
            raise HTTPException(status_code=400, detail="备份文件缺少 metadata.json，格式不正确")

        temp_dir = Path(tempfile.mkdtemp(prefix="diary_restore_"))

        try:
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
                        year_str, month_str = path_parts[-3], path_parts[-2]
                        day_str = Path(path_parts[-1]).stem

                        try:
                            datetime.strptime(f"{year_str}-{month_str}-{day_str}", "%Y-%m-%d")
                        except ValueError:
                            errors.append(f"无效日期: {name}")
                            skipped += 1
                            continue

                        dest_dir = temp_dir / year_str / month_str
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

            for item in temp_dir.iterdir():
                dest = DIARY_DIR / item.name
                if item.is_dir():
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.move(str(item), str(dest))

            _invalidate_diary_files_cache()
            audit_log("BACKUP_RESTORED", username, f"restored={restored} skipped={skipped}", request.client.host or "unknown")

            return {"status": "ok", "restored": restored, "skipped": skipped, "errors": errors[:10]}

        except Exception:
            raise
        finally:
            if temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)

    @app.post("/api/decrypt-backup")
    @require_auth
    async def decrypt_backup_api(data: DecryptBackupRequest, request: Request):
        username = request.state.username

        users = load_users()
        user = users.get(username)
        if not user or not verify_password(data.password, user["password_hash"]):
            audit_log("DECRYPT_BACKUP_AUTH_FAIL", username, "", request.client.host or "unknown")
            raise HTTPException(status_code=401, detail="密码错误")

        def generate_decrypted_backup():
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for filepath in sorted(DIARY_DIR.rglob("*.md")):
                    rel_path = filepath.relative_to(DIARY_DIR.parent)
                    try:
                        content = read_diary_file_sync(filepath)
                        zf.writestr(str(rel_path), content)
                    except Exception as e:
                        logger.warning(f"解密失败 {filepath}: {e}")
                        zf.write(filepath, rel_path)

                metadata = {
                    "created": datetime.now().isoformat(),
                    "created_by": username,
                    "total_entries": len(list(DIARY_DIR.rglob("*.md"))),
                    "decrypted": True,
                    "warning": "此备份包含明文日记，请妥善保管！",
                }
                zf.writestr("metadata.json", __import__("json").dumps(metadata, ensure_ascii=False, indent=2))

            buf.seek(0)
            while True:
                chunk = buf.read(8192)
                if not chunk:
                    break
                yield chunk

        audit_log("DECRYPTED_BACKUP", username, "", request.client.host or "unknown")
        return StreamingResponse(
            generate_decrypted_backup(),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="diary_backup_decrypted_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip"'},
        )

    @app.get("/api/settings", response_model=SettingsResponse)
    @require_auth
    async def settings(request: Request):
        return {
            "encryption_enabled": ENCRYPTION_ENABLED,
            "session_timeout": SESSION_TIMEOUT,
            "max_login_attempts": MAX_LOGIN_ATTEMPTS,
            "has_master_key": (CONFIG_DIR / "master.key").exists(),
        }

    @app.get("/api/health", response_model=HealthResponse)
    async def health_check():
        import shutil

        health = {
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "version": "3.0",
            "encryption": ENCRYPTION_ENABLED,
        }

        try:
            usage = shutil.disk_usage(DIARY_DIR)
            health["disk"] = {
                "total_gb": round(usage.total / (1024**3), 2),
                "free_gb": round(usage.free / (1024**3), 2),
                "used_percent": round(usage.used / usage.total * 100, 1),
            }
            if usage.free < 100 * 1024 * 1024:
                health["status"] = "warning"
                health["disk_warning"] = "磁盘空间不足"
        except Exception:
            pass

        if ENCRYPTION_ENABLED:
            try:
                get_or_create_master_key()
                health["crypto"] = "ok"
            except Exception as e:
                health["status"] = "error"
                health["crypto"] = f"error: {str(e)}"

        return health