"""日记模块测试"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import patch

from app.diary import (
    get_diary_path,
    parse_tags,
    get_preview,
    calculate_streak,
)


class TestDiaryPath:
    def test_valid_date(self):
        path = get_diary_path("2026-05-20")
        assert path.name == "20.md"
        assert "2026" in str(path)
        assert "05" in str(path)

    def test_invalid_date_raises(self):
        with pytest.raises(ValueError):
            get_diary_path("not-a-date")

    def test_invalid_date_format_raises(self):
        with pytest.raises(ValueError):
            get_diary_path("2026/05/20")


class TestParseTags:
    def test_single_tag(self):
        assert parse_tags("#work meeting") == ["work"]

    def test_multiple_tags(self):
        tags = parse_tags("#work #life #test")
        assert set(tags) == {"work", "life", "test"}

    def test_chinese_tags(self):
        tags = parse_tags("#工作 #生活")
        assert set(tags) == {"工作", "生活"}

    def test_no_tags(self):
        assert parse_tags("no tags here") == []

    def test_duplicate_tags_removed(self):
        tags = parse_tags("#a #a #a")
        assert tags == ["a"]


class TestPreview:
    def test_gets_first_non_heading_line(self):
        content = "# Title\n\nThis is the content."
        assert get_preview(content) == "This is the content."

    def test_skips_multiple_headings(self):
        content = "# H1\n## H2\n### H3\nReal content"
        assert get_preview(content) == "Real content"

    def test_respects_max_length(self):
        content = "a" * 200
        preview = get_preview(content, max_length=50)
        assert len(preview) == 50

    def test_empty_content(self):
        assert get_preview("") == ""


class TestStreak:
    def test_no_entries_returns_zero(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("app.diary.DIARY_DIR", Path(tmpdir)):
                streak = calculate_streak()
                assert streak == 0
