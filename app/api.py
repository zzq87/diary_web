"""API 路由模块"""

import logging
import secrets
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import (
    HTMLResponse,
    FileResponse,
    JSONResponse,
    StreamingResponse,
)

from .config import (
    DIARY_DIR,
    SESSION_TIMEOUT,
    MAX_LOGIN_ATTEMPTS,
    ENCRYPTION_ENABLED,
    CONFIG_DIR,
    BASE_DIR,
    safe_chmod,
)
from .auth import (
    load_users,
    save_users,
    verify_password,
    hash_password,
    create_session,
    validate_session,
    invalidate_session,
    check_rate_limit,
    check_login_limit,
    audit_log,
    _load_rate_limits,
    _flush_rate_limits,
    create_user,
    delete_user,
    update_user,
    get_user_info,
    list_users,
    is_admin,
)
from .diary import (
    get_diary_path,
    read_diary_file,
    read_diary_preview,
    write_diary_file,
    parse_tags,
    get_preview,
    sanitize_input,
    calculate_streak,
    _get_diary_files,
    _invalidate_diary_files_cache,
    search_diaries,
    get_stats,
    get_calendar_month,
)
from .crypto import get_or_create_master_key
from .middleware import security_headers_middleware, require_auth, require_admin

logger = logging.getLogger("diary.api")


def create_app() -> FastAPI:
    import asyncio
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        from .config import ensure_dirs

        ensure_dirs()

        logger.info(f"日记目录: {DIARY_DIR}")
        logger.info(f"加密存储: {'开启' if ENCRYPTION_ENABLED else '关闭'}")
        logger.info(f"会话超时: {SESSION_TIMEOUT}秒")

        _load_rate_limits()
        audit_log("SYSTEM_START", "system", "server started", "")

        flush_task = asyncio.create_task(_periodic_flush())

        yield

        flush_task.cancel()
        try:
            await flush_task
        except asyncio.CancelledError:
            pass
        _flush_rate_limits()
        audit_log("SYSTEM_STOP", "system", "server stopped", "")
        logger.info("日记本服务已关闭")

    async def _periodic_flush():
        import asyncio

        while True:
            await asyncio.sleep(10)
            _flush_rate_limits()

    app = FastAPI(
        title="本地日记本",
        description="安全增强版 Markdown 日记管理系统",
        lifespan=lifespan,
    )

    app.middleware("http")(security_headers_middleware)
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

    @app.post("/api/login")
    async def login(request: Request):
        client_ip = request.client.host or "unknown"

        if not check_login_limit(client_ip):
            audit_log(
                "LOGIN_BLOCKED", "unknown", "login rate limit exceeded", client_ip
            )
            return JSONResponse(
                status_code=429, content={"error": "登录尝试过多，请稍后重试"}
            )

        try:
            body = await request.json()
            username = body.get("username", "").strip()
            password = body.get("password", "")
        except Exception:
            return JSONResponse(status_code=400, content={"error": "请求格式错误"})

        if not username or not password:
            return JSONResponse(
                status_code=400, content={"error": "用户名和密码不能为空"}
            )

        users = load_users()
        user = users.get(username)

        if not user or not verify_password(password, user["password_hash"]):
            audit_log("LOGIN_FAILED", username, "wrong password", client_ip)
            return JSONResponse(status_code=401, content={"error": "用户名或密码错误"})

        token = create_session(username, ip=client_ip)
        audit_log("LOGIN_SUCCESS", username, "", client_ip)

        password_changed = user.get("password_changed", False)

        response = JSONResponse(
            content={
                "token": token,
                "username": username,
                "session_timeout": SESSION_TIMEOUT,
                "password_changed": password_changed,
                "role": user.get("role", "user"),
            }
        )
        response.set_cookie(
            key="diary_token",
            value=token,
            httponly=True,
            samesite="lax",
            max_age=SESSION_TIMEOUT,
            secure=False,  # 本地使用
        )
        return response

    @app.post("/api/logout")
    async def logout(request: Request):
        token = request.headers.get("X-Auth-Token", "")
        if not token:
            token = request.cookies.get("diary_token", "")
        if token:
            username = validate_session(token) or "unknown"
            invalidate_session(token)
            audit_log("LOGOUT", username, "", request.client.host or "unknown")

        response = JSONResponse(content={"status": "ok"})
        response.delete_cookie(key="diary_token")
        return response

    @app.get("/api/auth/status")
    async def auth_status(request: Request):
        token = request.headers.get("X-Auth-Token", "")
        if not token:
            token = request.cookies.get("diary_token", "")

        username = validate_session(token)
        if username:
            users = load_users()
            user = users.get(username, {})
            role = user.get("role", "admin" if username == "admin" else "user")
            return {
                "authenticated": True,
                "username": username,
                "role": role,
                "password_changed": user.get("password_changed", False),
            }
        return {"authenticated": False}

    @app.post("/api/auth/register")
    async def register(request: Request):
        client_ip = request.client.host or "unknown"
        if not check_login_limit(client_ip):
            return JSONResponse(
                status_code=429, content={"error": "尝试次数过多，请稍后重试"}
            )

        try:
            body = await request.json()
            username = body.get("username", "").strip()
            password = body.get("password", "")
            confirm_password = body.get("confirm_password", "")
        except Exception:
            return JSONResponse(status_code=400, content={"error": "请求格式错误"})

        if not username or len(username) < 2:
            return JSONResponse(
                status_code=400, content={"error": "用户名至少 2 个字符"}
            )
        if len(username) > 32:
            return JSONResponse(
                status_code=400, content={"error": "用户名最多 32 个字符"}
            )
        if not username.replace("_", "").replace("-", "").isalnum():
            return JSONResponse(
                status_code=400,
                content={"error": "用户名只能包含字母、数字、下划线和连字符"},
            )
        if not password or len(password) < 6:
            return JSONResponse(status_code=400, content={"error": "密码至少 6 个字符"})
        if password != confirm_password:
            return JSONResponse(
                status_code=400, content={"error": "两次输入的密码不一致"}
            )

        if create_user(username, password, role="user"):
            audit_log("USER_REGISTERED", username, f"ip={client_ip}", client_ip)
            return {"status": "ok", "message": "注册成功，请登录"}
        return JSONResponse(status_code=409, content={"error": "用户名已存在"})

    @app.post("/api/auth/change-password")
    @require_auth
    async def change_password(request: Request):
        client_ip = request.client.host or "unknown"
        if not check_login_limit(client_ip):
            return JSONResponse(
                status_code=429, content={"error": "尝试次数过多，请稍后重试"}
            )

        try:
            body = await request.json()
            old_password = body.get("old_password", "")
            new_password = body.get("new_password", "")
        except Exception:
            return JSONResponse(status_code=400, content={"error": "请求格式错误"})

        if len(new_password) < 6:
            return JSONResponse(
                status_code=400, content={"error": "新密码至少 6 个字符"}
            )

        username = request.state.username
        users = load_users()
        user = users.get(username)

        if not user or not verify_password(old_password, user["password_hash"]):
            audit_log(
                "PASSWORD_CHANGE_FAILED", username, "wrong old password", client_ip
            )
            return JSONResponse(status_code=401, content={"error": "原密码错误"})

        users[username]["password_hash"] = hash_password(new_password)
        users[username]["password_changed"] = True
        users[username]["password_changed_at"] = datetime.now().isoformat()
        save_users(users)
        audit_log("PASSWORD_CHANGED", username, "", client_ip)

        return {"status": "ok", "message": "密码已修改"}

    # ─── 用户管理（仅管理员）───────────────────────────

    @app.get("/api/users")
    @require_admin
    async def get_users(request: Request):
        username = request.state.username
        audit_log("LIST_USERS", username, "", request.client.host or "unknown")
        return {"users": list_users()}

    @app.post("/api/users")
    @require_admin
    async def admin_create_user(request: Request):
        admin_name = request.state.username
        try:
            body = await request.json()
            new_username = body.get("username", "").strip()
            password = body.get("password", "")
            role = body.get("role", "user")
        except Exception:
            return JSONResponse(status_code=400, content={"error": "请求格式错误"})

        if not new_username or len(new_username) < 2:
            return JSONResponse(
                status_code=400, content={"error": "用户名至少 2 个字符"}
            )
        if len(new_username) > 32:
            return JSONResponse(
                status_code=400, content={"error": "用户名最多 32 个字符"}
            )
        if not password or len(password) < 6:
            return JSONResponse(status_code=400, content={"error": "密码至少 6 个字符"})
        if role not in ("admin", "user"):
            return JSONResponse(status_code=400, content={"error": "无效的角色"})

        if create_user(new_username, password, role=role):
            audit_log(
                "ADMIN_CREATE_USER",
                admin_name,
                f"target={new_username} role={role}",
                request.client.host or "unknown",
            )
            return {"status": "ok", "message": f"用户 {new_username} 已创建"}
        return JSONResponse(status_code=409, content={"error": "用户名已存在"})

    @app.put("/api/users/{target_username}")
    @require_admin
    async def admin_update_user(request: Request, target_username: str):
        admin_name = request.state.username
        try:
            body = await request.json()
            updates = {}
            if "role" in body:
                updates["role"] = body["role"]
            if "password" in body and body["password"]:
                if len(body["password"]) < 6:
                    return JSONResponse(
                        status_code=400, content={"error": "密码至少 6 个字符"}
                    )
                updates["password_hash"] = hash_password(body["password"])
                updates["password_changed"] = True
        except Exception:
            return JSONResponse(status_code=400, content={"error": "请求格式错误"})

        if not updates:
            return JSONResponse(status_code=400, content={"error": "没有要更新的字段"})

        if update_user(target_username, **updates):
            audit_log(
                "ADMIN_UPDATE_USER",
                admin_name,
                f"target={target_username}",
                request.client.host or "unknown",
            )
            return {"status": "ok", "message": f"用户 {target_username} 已更新"}
        return JSONResponse(status_code=404, content={"error": "用户不存在"})

    @app.delete("/api/users/{target_username}")
    @require_admin
    async def admin_delete_user(request: Request, target_username: str):
        admin_name = request.state.username
        if target_username == admin_name:
            return JSONResponse(status_code=400, content={"error": "不能删除自己"})
        if delete_user(target_username):
            audit_log(
                "ADMIN_DELETE_USER",
                admin_name,
                f"target={target_username}",
                request.client.host or "unknown",
            )
            return {"status": "ok", "message": f"用户 {target_username} 已删除"}
        return JSONResponse(status_code=404, content={"error": "用户不存在"})

    # ─── 受保护的路由 ──────────────────────────────────

    @app.get("/api/diaries")
    @require_auth
    async def list_diaries(request: Request, limit: int = 30, offset: int = 0):
        username = request.state.username
        limit = min(max(limit, 1), 100)
        offset = max(offset, 0)

        entries = []
        files = _get_diary_files()

        for filepath in files[offset : offset + limit]:
            path = Path(filepath)
            date_str = path.stem
            month_str = path.parent.name
            year_str = path.parent.parent.name
            full_date = f"{year_str}-{month_str}-{date_str}"

            try:
                # 优化：仅读取预览部分，减少解密开销
                preview_content = read_diary_preview(path, max_len=300)
                tags = parse_tags(preview_content)
                preview = get_preview(preview_content)

                title = ""
                first_line = preview_content.strip().split("\n")[0]
                if first_line.startswith("# "):
                    title = first_line[2:].strip()

                entries.append(
                    {
                        "date": full_date,
                        "title": title,
                        "preview": preview,
                        "tags": tags,
                        "word_count": len(
                            preview_content.replace(" ", "").replace("\n", "")
                        ),
                    }
                )
            except Exception as e:
                logger.error(f"读取日记失败 {full_date}: {e}")

        audit_log(
            "LIST_DIARIES",
            username,
            f"limit={limit} offset={offset}",
            request.client.host or "unknown",
        )
        return {"entries": entries, "total": len(files)}

    @app.get("/api/diaries/{date}")
    @require_auth
    async def get_diary(request: Request, date: str):
        username = request.state.username
        try:
            path = get_diary_path(date)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        if not path.exists():
            raise HTTPException(status_code=404, detail="日记不存在")

        content = read_diary_file(path)
        tags = parse_tags(content)

        audit_log(
            "VIEW_DIARY", username, f"date={date}", request.client.host or "unknown"
        )
        return {"date": date, "content": content, "tags": tags}

    @app.post("/api/diaries/{date}")
    @require_auth
    async def save_diary(request: Request, date: str):
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

        _invalidate_diary_files_cache()
        audit_log(
            "SAVE_DIARY",
            username,
            f"date={date} size={len(content)}",
            request.client.host or "unknown",
        )

        return {"status": "ok", "date": date, "encrypted": ENCRYPTION_ENABLED}

    @app.delete("/api/diaries/{date}")
    @require_auth
    async def delete_diary(request: Request, date: str):
        username = request.state.username
        try:
            path = get_diary_path(date)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        if not path.exists():
            raise HTTPException(status_code=404, detail="日记不存在")

        path.unlink()
        _invalidate_diary_files_cache()
        audit_log(
            "DELETE_DIARY", username, f"date={date}", request.client.host or "unknown"
        )

        return {"status": "ok", "date": date}

    @app.get("/api/search")
    @require_auth
    async def search(request: Request, q: str):
        username = request.state.username
        if not q or len(q) < 2:
            return {"results": [], "total": 0}

        q = sanitize_input(q, max_length=50)
        results = search_diaries(q)

        audit_log(
            "SEARCH",
            username,
            f"query_len={len(q)} results={len(results)}",
            request.client.host or "unknown",
        )
        return {"results": results, "total": len(results)}

    @app.get("/api/stats")
    @require_auth
    async def stats(request: Request):
        username = request.state.username
        result = get_stats()
        audit_log("VIEW_STATS", username, "", request.client.host or "unknown")
        return result

    @app.get("/api/calendar/{year}/{month}")
    @require_auth
    async def calendar(request: Request, year: int, month: int):
        if year < 2000 or year > 2100 or month < 1 or month > 12:
            raise HTTPException(status_code=400, detail="无效日期")

        dates = get_calendar_month(year, month)
        return {"dates": dates}

    @app.get("/api/audit")
    @require_auth
    async def audit(request: Request, limit: int = 50):
        username = request.state.username
        audit_file = CONFIG_DIR / "audit.log"

        if not audit_file.exists():
            return {"entries": []}

        lines = audit_file.read_text(encoding="utf-8").strip().split("\n")
        entries = lines[-limit:] if lines else []

        audit_log(
            "VIEW_AUDIT", username, f"limit={limit}", request.client.host or "unknown"
        )
        return {"entries": entries, "total": len(lines)}

    @app.get("/api/backup")
    @require_auth
    async def backup(request: Request):
        username = request.state.username
        import zipfile
        import io

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
                zf.writestr(
                    "metadata.json",
                    __import__("json").dumps(metadata, ensure_ascii=False, indent=2),
                )

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
            headers={
                "Content-Disposition": f'attachment; filename="diary_backup_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip"'
            },
        )

    @app.post("/api/restore")
    @require_auth
    async def restore(request: Request):
        username = request.state.username
        import zipfile
        import io
        import shutil

        try:
            form = await request.form()
            backup_file = form.get("backup")
            if not backup_file or not hasattr(backup_file, "read"):
                raise HTTPException(status_code=400, detail="请上传 ZIP 备份文件")
            zip_bytes = await backup_file.read()
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"上传失败: {str(e)}")

        try:
            zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="无效的 ZIP 文件")

        if "metadata.json" not in zf.namelist():
            raise HTTPException(
                status_code=400, detail="备份文件缺少 metadata.json，格式不正确"
            )

        # 事务性恢复：先解压到临时目录，成功后再移动
        import tempfile

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
                            datetime.strptime(
                                f"{year_str}-{month_str}-{day_str}", "%Y-%m-%d"
                            )
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

            # 所有文件解压成功后，移动到目标目录
            for item in temp_dir.iterdir():
                dest = DIARY_DIR / item.name
                if item.is_dir():
                    if dest.exists():
                        shutil.rmtree(dest)
                    shutil.move(str(item), str(dest))

            _invalidate_diary_files_cache()
            audit_log(
                "BACKUP_RESTORED",
                username,
                f"restored={restored} skipped={skipped}",
                request.client.host or "unknown",
            )

            return {
                "status": "ok",
                "restored": restored,
                "skipped": skipped,
                "errors": errors[:10],
            }

        except Exception:
            # 失败时清理临时目录
            raise
        finally:
            if temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)

    @app.post("/api/decrypt-backup")
    @require_auth
    async def decrypt_backup_api(request: Request):
        username = request.state.username
        from .crypto import get_or_create_master_key

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
            audit_log(
                "DECRYPT_BACKUP_AUTH_FAIL",
                username,
                "",
                request.client.host or "unknown",
            )
            raise HTTPException(status_code=401, detail="密码错误")

        import zipfile
        import io

        def generate_decrypted_backup():
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                for filepath in sorted(DIARY_DIR.rglob("*.md")):
                    rel_path = filepath.relative_to(DIARY_DIR.parent)
                    try:
                        content = read_diary_file(filepath)
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
                zf.writestr(
                    "metadata.json",
                    __import__("json").dumps(metadata, ensure_ascii=False, indent=2),
                )

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
            headers={
                "Content-Disposition": f'attachment; filename="diary_backup_decrypted_{datetime.now().strftime("%Y%m%d_%H%M%S")}.zip"'
            },
        )

    @app.get("/api/settings")
    @require_auth
    async def settings(request: Request):
        return {
            "encryption_enabled": ENCRYPTION_ENABLED,
            "session_timeout": SESSION_TIMEOUT,
            "max_login_attempts": MAX_LOGIN_ATTEMPTS,
            "has_master_key": (CONFIG_DIR / "master.key").exists(),
        }

    @app.get("/api/health")
    async def health_check():
        import shutil

        health = {
            "status": "ok",
            "timestamp": datetime.now().isoformat(),
            "version": "3.0",
            "encryption": ENCRYPTION_ENABLED,
        }

        # 检查磁盘空间
        try:
            usage = shutil.disk_usage(DIARY_DIR)
            health["disk"] = {
                "total_gb": round(usage.total / (1024**3), 2),
                "free_gb": round(usage.free / (1024**3), 2),
                "used_percent": round(usage.used / usage.total * 100, 1),
            }
            if usage.free < 100 * 1024 * 1024:  # 少于 100MB
                health["status"] = "warning"
                health["disk_warning"] = "磁盘空间不足"
        except Exception:
            health["disk"] = "unknown"

        # 检查加密模块
        if ENCRYPTION_ENABLED:
            try:
                get_or_create_master_key()
                health["crypto"] = "ok"
            except Exception as e:
                health["status"] = "error"
                health["crypto"] = f"error: {str(e)}"

        return health
