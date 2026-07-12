"""SQLite FTS5 全文搜索索引模块"""

import re
import sqlite3
import threading
from pathlib import Path
from typing import Optional

from .config import CONFIG_DIR, SEARCH_DB_FILE

_db_path: Optional[Path] = None
_conn: Optional[sqlite3.Connection] = None
_conn_lock = threading.Lock()


def _get_db_path() -> Path:
    global _db_path
    if _db_path is None:
        _db_path = SEARCH_DB_FILE
    return _db_path


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        _conn = sqlite3.connect(str(_get_db_path()), check_same_thread=False)
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.execute("PRAGMA busy_timeout=5000")
        _conn.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS diary_index "
            "USING fts5("
            "  content,"
            "  path UNINDEXED,"
            "  date UNINDEXED,"
            "  preview UNINDEXED,"
            "  tags UNINDEXED,"
            "  tokenize='unicode61'"
            ")"
        )
    return _conn


def close() -> None:
    global _conn, _db_path
    with _conn_lock:
        if _conn is not None:
            _conn.close()
            _conn = None
        _db_path = None


def reset() -> None:
    global _conn, _db_path
    with _conn_lock:
        if _conn is not None:
            try:
                _conn.close()
            except Exception:
                pass
            _conn = None
        _db_path = None


def _extract_preview(content: str, max_len: int = 200) -> str:
    for line in content.strip().split("\n"):
        line = line.strip()
        if line and not line.startswith("#"):
            return line[:max_len]
    return content.strip()[:max_len]


def build_index(files: list[tuple[str, str, str, str, str]]) -> None:
    """files: [(content, path, date, preview, tags_str), ...]"""
    with _conn_lock:
        conn = _get_conn()
        conn.execute("BEGIN")
        conn.execute("DELETE FROM diary_index")
        conn.executemany(
            "INSERT INTO diary_index(content, path, date, preview, tags) "
            "VALUES (?, ?, ?, ?, ?)",
            files,
        )
        conn.commit()


def update_in_index(content: str, path: str, date: str, tags: str) -> None:
    preview = _extract_preview(content)
    with _conn_lock:
        conn = _get_conn()
        conn.execute("DELETE FROM diary_index WHERE path = ?", (path,))
        conn.execute(
            "INSERT INTO diary_index(content, path, date, preview, tags) "
            "VALUES (?, ?, ?, ?, ?)",
            (content, path, date, preview, tags),
        )
        conn.commit()


def remove_from_index(path: str) -> None:
    with _conn_lock:
        conn = _get_conn()
        conn.execute("DELETE FROM diary_index WHERE path = ?", (path,))
        conn.commit()


_FTS5_SPECIAL = re.compile(r'["*()+\-^]|(?:AND|OR|NOT|NEAR)\b', re.IGNORECASE)


def _sanitize_fts5(query: str) -> str:
    query = _FTS5_SPECIAL.sub("", query).strip()
    if not query:
        return ""
    terms = query.split()
    return " AND ".join(f'"{t}"' for t in terms)


def search(query: str, limit: int = 50) -> list[dict]:
    safe_query = _sanitize_fts5(query)
    if not safe_query:
        return []
    with _conn_lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                "SELECT path, date, preview, tags FROM diary_index "
                "WHERE content MATCH ? ORDER BY rank LIMIT ?",
                (safe_query, limit),
            ).fetchall()
        except sqlite3.OperationalError:
            return []
    results = []
    for path, date, preview, tags in rows:
        tag_list = tags.split() if tags else []
        results.append({
            "path": path,
            "date": date,
            "preview": preview,
            "tags": tag_list,
        })
    return results



