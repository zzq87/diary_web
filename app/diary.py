"""日记操作模块：读写、搜索、统计、缓存"""

import glob
import re
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from .config import DIARY_DIR, ENCRYPTION_ENABLED
from .crypto import get_or_create_master_key, encrypt_data, decrypt_data

# ─── 缓存 ──────────────────────────────────────────────

_streak_cache = {"value": 0, "computed_at": 0.0, "ttl": 300}
_stats_cache: dict = {"value": None, "computed_at": 0.0, "ttl": 60}
_diary_files_cache: dict = {"files": None, "computed_at": 0.0, "ttl": 30}
_search_index: dict = {"index": {}, "built_at": 0.0, "ttl": 120}
_index_lock = threading.Lock()


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


# ─── 读写 ──────────────────────────────────────────────


def read_diary_file(path: Path) -> str:
    raw_content = path.read_text(encoding="utf-8")
    if ENCRYPTION_ENABLED and raw_content.startswith("ENC:"):
        key = get_or_create_master_key()
        encrypted = raw_content[4:]
        content = decrypt_data(encrypted, key)
        return content.decode("utf-8")
    return raw_content


def read_diary_preview(path: Path, max_len: int = 200) -> str:
    raw_content = path.read_text(encoding="utf-8")
    if ENCRYPTION_ENABLED and raw_content.startswith("ENC:"):
        key = get_or_create_master_key()
        encrypted = raw_content[4:]
        content = decrypt_data(encrypted, key)
        content_str = content.decode("utf-8")
        # 只返回前 max_len 字符作为预览
        return content_str[:max_len]
    return raw_content[:max_len]


def write_diary_file(path: Path, content: str) -> None:
    if ENCRYPTION_ENABLED:
        key = get_or_create_master_key()
        encrypted = encrypt_data(content.encode("utf-8"), key)
        path.write_text(f"ENC:{encrypted}", encoding="utf-8")
    else:
        path.write_text(content, encoding="utf-8")


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
    _search_index["built_at"] = 0  # 使搜索索引失效


# ─── Streak ────────────────────────────────────────────


def calculate_streak() -> int:
    now = time.time()
    if now - _streak_cache["computed_at"] < _streak_cache["ttl"]:
        return _streak_cache["value"]

    streak = 0
    today = datetime.now()
    for i in range(365):
        date = today - timedelta(days=i)
        try:
            path = get_diary_path(date.strftime("%Y-%m-%d"))
            if path.exists():
                streak += 1
            else:
                break
        except ValueError:
            break

    _streak_cache["value"] = streak
    _streak_cache["computed_at"] = now
    return streak


# ─── 搜索索引 ─────────────────────────────────────────


def _build_search_index() -> dict[str, str]:
    """构建简易搜索索引：{filepath: lowercase_content_preview}"""
    index = {}
    for filepath in _get_diary_files():
        path = Path(filepath)
        try:
            raw = path.read_text(encoding="utf-8")
            if ENCRYPTION_ENABLED and raw.startswith("ENC:"):
                key = get_or_create_master_key()
                content = decrypt_data(raw[4:], key).decode("utf-8").lower()
            else:
                content = raw.lower()
            index[filepath] = content
        except Exception:
            continue
    return index


def _get_search_index() -> dict[str, str]:
    now = time.time()
    if (
        _search_index["index"]
        and now - _search_index["built_at"] < _search_index["ttl"]
    ):
        return _search_index["index"]
    with _index_lock:
        _search_index["index"] = _build_search_index()
        _search_index["built_at"] = now
    return _search_index["index"]


def search_diaries(query: str) -> list[dict]:
    query_lower = query.lower()
    index = _get_search_index()
    results = []

    for filepath, content_lower in index.items():
        if query_lower not in content_lower:
            continue

        path = Path(filepath)
        try:
            content = read_diary_file(path)
        except Exception:
            continue

        # 找到包含查询词的行
        for line in content.split("\n"):
            if query_lower in line.lower() and not line.startswith("# "):
                date_str = path.stem
                month_str = path.parent.name
                year_str = path.parent.parent.name
                full_date = f"{year_str}-{month_str}-{date_str}"
                results.append(
                    {
                        "date": full_date,
                        "preview": line.strip()[:150],
                        "tags": parse_tags(content),
                    }
                )
                break

    return results


# ─── 统计 ──────────────────────────────────────────────


def get_stats() -> dict:
    now = time.time()
    if (
        _stats_cache["value"] is not None
        and now - _stats_cache["computed_at"] < _stats_cache["ttl"]
    ):
        return _stats_cache["value"]

    if not DIARY_DIR.exists():
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

    total_entries = 0
    total_words = 0
    first_date = None
    last_date = None
    all_tags: dict[str, int] = {}

    files = sorted(_get_diary_files())

    for filepath in files:
        path = Path(filepath)
        try:
            content = read_diary_file(path)
        except Exception:
            continue

        total_entries += 1
        total_words += len(content.replace(" ", "").replace("\n", ""))

        tags = parse_tags(content)
        for tag in tags:
            all_tags[tag] = all_tags.get(tag, 0) + 1

        date_str = path.stem
        month_str = path.parent.name
        year_str = path.parent.parent.name
        full_date = f"{year_str}-{month_str}-{date_str}"

        if last_date is None:
            last_date = full_date
        first_date = full_date

    streak = calculate_streak()
    sorted_tags = dict(sorted(all_tags.items(), key=lambda x: x[1], reverse=True))

    result = {
        "total_entries": total_entries,
        "total_words": total_words,
        "first_date": first_date,
        "last_date": last_date,
        "streak": streak,
        "tags": sorted_tags,
        "encrypted": ENCRYPTION_ENABLED,
    }

    _stats_cache["value"] = result
    _stats_cache["computed_at"] = now
    return result


# ─── 日历 ──────────────────────────────────────────────


def get_calendar_month(year: int, month: int) -> list[int]:
    pattern = str(DIARY_DIR) + f"/{year:04d}/{month:02d}/*.md"
    dates = []
    for filepath in glob.glob(pattern):
        path = Path(filepath)
        dates.append(int(path.stem))
    return sorted(dates)
