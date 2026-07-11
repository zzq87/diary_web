"""日记操作模块：读写、搜索、统计、缓存（异步 I/O）"""

import glob
import re
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import aiofiles

from .config import DIARY_DIR, ENCRYPTION_ENABLED
from .crypto import get_or_create_master_key, encrypt_data, decrypt_data
from . import search as search_index

# ─── 缓存 ──────────────────────────────────────────────

_streak_cache = {"value": 0, "computed_at": 0.0, "ttl": 300}
_stats_cache = {"value": None, "computed_at": 0.0, "ttl": 60}
_diary_files_cache = {"files": None, "computed_at": 0.0, "ttl": 300}
_fts_built = False


# ─── 路径 ──────────────────────────────────────────────

def get_diary_path(date_str: str) -> Path:
    try:
        date = datetime.strptime(date_str, "%Y-%m-%d")
    except ValueError:
        raise ValueError(f"无效日期: {date_str}")

    path = DIARY_DIR / str(date.year) / f"{date.month:02d}" / f"{date.day:02d}.md"
    if not str(path.resolve()).startswith(str(DIARY_DIR.resolve())):
        raise ValueError("路径遍历攻击检测")
    return path


# ─── 解密辅助 ──────────────────────────────────────────

def _decrypt_content(raw_content: str) -> str:
    if ENCRYPTION_ENABLED and raw_content.startswith("ENC:"):
        key = get_or_create_master_key()
        encrypted = raw_content[4:]
        return decrypt_data(encrypted, key).decode("utf-8")
    return raw_content


# ─── 异步读写 ──────────────────────────────────────────

async def read_diary_file(path: Path) -> str:
    async with aiofiles.open(path, "r", encoding="utf-8") as f:
        raw_content = await f.read()
    return _decrypt_content(raw_content)


async def read_diary_preview(path: Path, max_len: int = 200) -> str:
    async with aiofiles.open(path, "r", encoding="utf-8") as f:
        raw_content = await f.read()
    return _decrypt_content(raw_content)[:max_len]


async def write_diary_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if ENCRYPTION_ENABLED:
        key = get_or_create_master_key()
        encrypted = encrypt_data(content.encode("utf-8"), key)
        async with aiofiles.open(path, "w", encoding="utf-8") as f:
            await f.write(f"ENC:{encrypted}")
    else:
        async with aiofiles.open(path, "w", encoding="utf-8") as f:
            await f.write(content)


# ─── 辅助 ──────────────────────────────────────────────

def parse_tags(content: str) -> list[str]:
    tags = re.findall(r"#([\w\u4e00-\u9fff]+)", content)
    return list(set(tags))


def get_preview(content: str, max_length: int = 100) -> str:
    lines = content.strip().split("\n")
    for line in lines:
        line = line.strip()
        if line and not line.startswith("#"):
            return line[:max_length]
    return ""


def sanitize_input(text: str, max_length: int = 10000) -> str:
    if not text:
        return ""
    text = text[:max_length]
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    return text


# ─── 文件列表缓存 ─────────────────────────────────────

def _get_diary_files() -> list[str]:
    now = time.time()
    if (
        _diary_files_cache["files"] is not None
        and now - _diary_files_cache["computed_at"] < _diary_files_cache["ttl"]
    ):
        return _diary_files_cache["files"]
    pattern = str(DIARY_DIR) + "/*/*/*.md"
    files = sorted(glob.glob(pattern), reverse=True)
    _diary_files_cache["files"] = files
    _diary_files_cache["computed_at"] = now
    return files


def _invalidate_diary_files_cache() -> None:
    _diary_files_cache["computed_at"] = 0
    _diary_files_cache["files"] = None
    _stats_cache["computed_at"] = 0
    global _fts_built
    _fts_built = False


# ─── Streak ────────────────────────────────────────────

def calculate_streak() -> int:
    now = time.time()
    if now - _streak_cache["computed_at"] < _streak_cache["ttl"]:
        return _streak_cache["value"]

    existing_dates: set[str] = set()
    for filepath in _get_diary_files():
        path = Path(filepath)
        year_str = path.parent.parent.name
        month_str = path.parent.name
        day_str = path.stem
        existing_dates.add(f"{year_str}-{month_str}-{day_str}")

    streak = 0
    today = datetime.now()
    for i in range(365):
        date = today - timedelta(days=i)
        if date.strftime("%Y-%m-%d") in existing_dates:
            streak += 1
        else:
            break

    _streak_cache["value"] = streak
    _streak_cache["computed_at"] = now
    return streak


# ─── 搜索索引 (FTS5) ─────────────────────────────────

def _ensure_fts_index() -> None:
    global _fts_built
    if _fts_built:
        return
    files = []
    total_entries = 0
    total_words = 0
    first_date = None
    last_date = None
    all_tags: dict[str, int] = {}
    for filepath in _get_diary_files():
        path = Path(filepath)
        try:
            content = read_diary_file_sync(path)
            date_str = path.stem
            month_str = path.parent.name
            year_str = path.parent.parent.name
            full_date = f"{year_str}-{month_str}-{date_str}"
            tags = parse_tags(content)
            tags_str = " ".join(tags)
            preview = get_preview(content)
            files.append((content, str(filepath), full_date, preview, tags_str))
            total_entries += 1
            total_words += len(content.replace(" ", "").replace("\n", ""))
            for tag in tags:
                all_tags[tag] = all_tags.get(tag, 0) + 1
            if first_date is None:
                first_date = full_date
            last_date = full_date
        except Exception:
            continue
    if files:
        search_index.build_index(files)
        sorted_tags = dict(sorted(all_tags.items(), key=lambda x: x[1], reverse=True))
        _stats_cache["value"] = {
            "total_entries": total_entries,
            "total_words": total_words,
            "first_date": first_date,
            "last_date": last_date,
            "streak": calculate_streak(),
            "tags": sorted_tags,
            "encrypted": ENCRYPTION_ENABLED,
        }
        _stats_cache["computed_at"] = time.time()
    _fts_built = True


def search_diaries(query: str) -> list[dict]:
    _ensure_fts_index()
    results = search_index.search(query)
    mapped = []
    for r in results:
        mapped.append({
            "date": r["date"],
            "preview": r["preview"],
            "tags": r["tags"],
        })
    return mapped


def read_diary_file_sync(path: Path) -> str:
    """同步版本（供搜索索引构建使用）"""
    raw_content = path.read_text(encoding="utf-8")
    return _decrypt_content(raw_content)


# ─── 统计 ──────────────────────────────────────────────

def get_stats() -> dict:
    now = time.time()
    if _stats_cache["value"] is not None and now - _stats_cache["computed_at"] < _stats_cache["ttl"]:
        return _stats_cache["value"]

    if not DIARY_DIR.exists() or not _get_diary_files():
        result = {
            "total_entries": 0,
            "total_words": 0,
            "first_date": None,
            "last_date": None,
            "streak": 0,
            "tags": {},
            "encrypted": ENCRYPTION_ENABLED,
        }
        _stats_cache["value"] = result
        _stats_cache["computed_at"] = now
        return result

    _ensure_fts_index()

    if _stats_cache["value"] is not None:
        return _stats_cache["value"]

    return get_stats()


# ─── 日历 ──────────────────────────────────────────────

def get_calendar_month(year: int, month: int) -> list[dict]:
    pattern = str(DIARY_DIR) + f"/{year:04d}/{month:02d}/*.md"
    dates_with_entries = set()
    for filepath in glob.glob(pattern):
        path = Path(filepath)
        dates_with_entries.add(int(path.stem))
    from calendar import monthrange
    _, days_in_month = monthrange(year, month)
    return [
        {"day": d, "has_entry": d in dates_with_entries}
        for d in range(1, days_in_month + 1)
    ]