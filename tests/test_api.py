"""API 集成测试"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch, AsyncMock

from httpx import AsyncClient, ASGITransport
from fastapi.testclient import TestClient

from app import search as search_index
from app.api import create_app
from app.config import settings


@pytest.fixture
def temp_dir():
    with tempfile.TemporaryDirectory() as tmp:
        yield Path(tmp)


def _get_token(client, username="admin", password="test123456"):
    resp = client.post("/api/login", json={"username": username, "password": password})
    return resp.json()["token"]


@pytest.fixture
def app(temp_dir):
    search_index.reset()
    (temp_dir / "config").mkdir(parents=True, exist_ok=True)
    (temp_dir / "data").mkdir(parents=True, exist_ok=True)
    session_file = temp_dir / "config" / "sessions.enc.json"
    with patch("app.auth.USERS_FILE", temp_dir / "config" / "users.json"), \
         patch("app.auth.AUDIT_FILE", temp_dir / "config" / "audit.log"), \
         patch("app.auth.RATE_LIMIT_FILE", temp_dir / "config" / "rate_limits.json"), \
         patch("app.auth.DEFAULT_PASSWORD", "test123456"), \
         patch("app.auth._session_file", session_file), \
         patch("app.auth._rate_limit_mem", {}), \
         patch("app.auth._rate_limit_last_flush", 0.0), \
         patch("app.crypto.MASTER_KEY_FILE", temp_dir / "config" / "master.key"), \
         patch("app.diary.DIARY_DIR", temp_dir / "data"), \
         patch("app.diary.ENCRYPTION_ENABLED", False), \
         patch("app.search.CONFIG_DIR", temp_dir / "config"), \
         patch("app.api.DIARY_DIR", temp_dir / "data"), \
         patch("app.api.AUDIT_FILE", temp_dir / "config" / "audit.log"), \
         patch("app.api.ENCRYPTION_ENABLED", False), \
         patch("app.config.settings.diary_dir", temp_dir / "data"), \
         patch("app.config.settings.config_dir", temp_dir / "config"), \
         patch("app.config.settings.default_password", "test123456"), \
         patch("app.config.settings.master_key_file", temp_dir / "config" / "master.key"):
        test_app = create_app()
        yield test_app
        search_index.reset()


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.fixture
async def async_client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


class TestHealth:
    def test_health_check(self, client):
        response = client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("ok", "warning")
        assert "timestamp" in data
        assert data["version"] == "3.0"


class TestAuth:
    def test_login_success(self, client):
        # 默认 admin 用户
        response = client.post("/api/login", json={
            "username": "admin",
            "password": "test123456"
        })
        assert response.status_code == 200
        data = response.json()
        assert "token" in data
        assert data["username"] == "admin"
        assert "session_timeout" in data

    def test_login_wrong_password(self, client):
        response = client.post("/api/login", json={
            "username": "admin",
            "password": "wrong"
        })
        assert response.status_code == 401
        assert "错误" in response.json()["detail"]

    def test_login_missing_fields(self, client):
        response = client.post("/api/login", json={})
        assert response.status_code == 422

    def test_register_success(self, client):
        response = client.post("/api/auth/register", json={
            "username": "testuser",
            "password": "test123456",
            "confirm_password": "test123456"
        })
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

    def test_register_duplicate(self, client):
        client.post("/api/auth/register", json={
            "username": "dupuser",
            "password": "test123456",
            "confirm_password": "test123456"
        })
        response = client.post("/api/auth/register", json={
            "username": "dupuser",
            "password": "test123456",
            "confirm_password": "test123456"
        })
        assert response.status_code == 409

    def test_auth_status_unauthenticated(self, client):
        response = client.get("/api/auth/status")
        assert response.status_code == 200
        assert response.json()["authenticated"] is False

    def test_auth_status_authenticated(self, client):
        # 先登录
        login_resp = client.post("/api/login", json={
            "username": "admin",
            "password": "test123456"
        })
        token = login_resp.json()["token"]

        # 带 token 请求
        response = client.get("/api/auth/status", headers={"X-Auth-Token": token})
        assert response.status_code == 200
        data = response.json()
        assert data["authenticated"] is True
        assert data["username"] == "admin"


class TestDiaries:
    def test_list_diaries_empty(self, client):
        token = _get_token(client)
        response = client.get("/api/diaries", headers={"X-Auth-Token": token})
        assert response.status_code == 200
        data = response.json()
        assert "entries" in data
        assert "total" in data
        assert data["total"] == 0

    def test_save_and_get_diary(self, client):
        token = _get_token(client)
        date = "2026-01-15"

        # 保存日记
        save_resp = client.post(f"/api/diaries/{date}", 
            json={"content": "# 测试日记\n\n今天天气不错。"},
            headers={"X-Auth-Token": token}
        )
        assert save_resp.status_code == 200
        assert save_resp.json()["status"] == "ok"

        # 获取日记
        get_resp = client.get(f"/api/diaries/{date}", headers={"X-Auth-Token": token})
        assert get_resp.status_code == 200
        data = get_resp.json()
        assert data["date"] == date
        assert "测试日记" in data["content"]
        assert "tags" in data

    def test_save_diary_empty_content(self, client):
        token = _get_token(client)
        response = client.post("/api/diaries/2026-01-15", 
            json={"content": "   "},
            headers={"X-Auth-Token": token}
        )
        assert response.status_code == 400

    def test_delete_diary(self, client):
        token = _get_token(client)
        date = "2026-01-16"

        client.post(f"/api/diaries/{date}", 
            json={"content": "待删除"},
            headers={"X-Auth-Token": token}
        )
        
        del_resp = client.delete(f"/api/diaries/{date}", headers={"X-Auth-Token": token})
        assert del_resp.status_code == 200
        assert del_resp.json()["status"] == "ok"

        # 验证已删除
        get_resp = client.get(f"/api/diaries/{date}", headers={"X-Auth-Token": token})
        assert get_resp.status_code == 404

    def test_search_diaries(self, client):
        token = _get_token(client)
        date = "2026-01-17"
        client.post(f"/api/diaries/{date}", 
            json={"content": "今天学习了 #Python 和 #FastAPI"},
            headers={"X-Auth-Token": token}
        )

        search_resp = client.get("/api/search?q=Python", headers={"X-Auth-Token": token})
        assert search_resp.status_code == 200
        data = search_resp.json()
        assert data["total"] >= 1
        assert len(data["results"]) >= 1


class TestStats:
    def test_get_stats(self, client):
        token = _get_token(client)
        response = client.get("/api/stats", headers={"X-Auth-Token": token})
        assert response.status_code == 200
        data = response.json()
        assert "total_entries" in data
        assert "streak" in data
        assert "tags" in data


class TestCalendar:
    def test_get_calendar(self, client):
        token = _get_token(client)
        response = client.get("/api/calendar/2026/1", headers={"X-Auth-Token": token})
        assert response.status_code == 200
        data = response.json()
        assert "dates" in data


class TestSettings:
    def test_get_settings(self, client):
        token = _get_token(client)
        response = client.get("/api/settings", headers={"X-Auth-Token": token})
        assert response.status_code == 200
        data = response.json()
        assert "encryption_enabled" in data
        assert "session_timeout" in data


class TestAudit:
    def test_get_audit(self, client):
        token = _get_token(client)
        response = client.get("/api/audit", headers={"X-Auth-Token": token})
        assert response.status_code == 200
        data = response.json()
        assert "entries" in data
        assert "total" in data


class TestRateLimit:
    def test_login_rate_limit(self, client):
        # 连续失败登录超过限制
        for _ in range(6):
            client.post("/api/login", json={"username": "admin", "password": "wrong"})
        
        # 第 7 次应该被限制
        response = client.post("/api/login", json={"username": "admin", "password": "wrong"})
        assert response.status_code == 429


class TestSearchEdgeCases:
    def test_search_empty_query(self, client):
        token = _get_token(client)
        resp = client.get("/api/search?q=", headers={"X-Auth-Token": token})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0

    def test_search_short_query(self, client):
        token = _get_token(client)
        resp = client.get("/api/search?q=a", headers={"X-Auth-Token": token})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0

    def test_search_no_results(self, client):
        token = _get_token(client)
        resp = client.get("/api/search?q=zzz_not_exist", headers={"X-Auth-Token": token})
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert len(data["results"]) == 0


class TestWithEncryption:
    @pytest.fixture
    def enc_app(self, temp_dir):
        search_index.reset()
        (temp_dir / "config").mkdir(parents=True, exist_ok=True)
        (temp_dir / "data").mkdir(parents=True, exist_ok=True)
        session_file = temp_dir / "config" / "sessions.enc.json"
        with patch("app.auth.USERS_FILE", temp_dir / "config" / "users.json"), \
             patch("app.auth.AUDIT_FILE", temp_dir / "config" / "audit.log"), \
             patch("app.auth.RATE_LIMIT_FILE", temp_dir / "config" / "rate_limits.json"), \
             patch("app.auth.DEFAULT_PASSWORD", "test123456"), \
             patch("app.auth._session_file", session_file), \
             patch("app.auth._rate_limit_mem", {}), \
             patch("app.auth._rate_limit_last_flush", 0.0), \
             patch("app.crypto.MASTER_KEY_FILE", temp_dir / "config" / "master.key"), \
             patch("app.diary.DIARY_DIR", temp_dir / "data"), \
             patch("app.diary.ENCRYPTION_ENABLED", True), \
             patch("app.search.CONFIG_DIR", temp_dir / "config"), \
             patch("app.api.DIARY_DIR", temp_dir / "data"), \
             patch("app.api.AUDIT_FILE", temp_dir / "config" / "audit.log"), \
             patch("app.api.ENCRYPTION_ENABLED", True), \
             patch("app.config.settings.diary_dir", temp_dir / "data"), \
             patch("app.config.settings.config_dir", temp_dir / "config"), \
             patch("app.config.settings.default_password", "test123456"), \
             patch("app.config.settings.master_key_file", temp_dir / "config" / "master.key"):
            test_app = create_app()
            yield test_app
            search_index.reset()

    def test_save_and_read_encrypted_diary(self, enc_app, temp_dir):
        from fastapi.testclient import TestClient
        client = TestClient(enc_app)
        token = _get_token(client)
        date = "2026-06-15"

        save_resp = client.post(f"/api/diaries/{date}",
            json={"content": "# 加密测试\n\n这是一篇加密日记。"},
            headers={"X-Auth-Token": token}
        )
        assert save_resp.status_code == 200
        assert save_resp.json()["encrypted"] is True

        get_resp = client.get(f"/api/diaries/{date}", headers={"X-Auth-Token": token})
        assert get_resp.status_code == 200
        data = get_resp.json()
        assert "加密测试" in data["content"]

        raw = (temp_dir / "data" / "2026" / "06" / "15.md").read_text(encoding="utf-8")
        assert raw.startswith("ENC:")