"""认证模块测试"""

import pytest
import os

from app.auth import hash_password, verify_password, sanitize_input


class TestPassword:
    def test_hash_and_verify(self):
        pwd = "my_secure_password"
        hashed = hash_password(pwd)
        assert verify_password(pwd, hashed)

    def test_wrong_password_fails(self):
        pwd = "correct"
        hashed = hash_password(pwd)
        assert not verify_password("wrong", hashed)

    def test_different_hashes_for_same_password(self):
        pwd = "same"
        h1 = hash_password(pwd)
        h2 = hash_password(pwd)
        assert h1 != h2  # salt 不同

    def test_empty_password(self):
        hashed = hash_password("")
        assert verify_password("", hashed)
        assert not verify_password("notempty", hashed)


class TestSanitize:
    def test_removes_control_chars(self):
        from app.diary import sanitize_input

        result = sanitize_input("hello\x00world\x01test")
        assert "\x00" not in result
        assert "\x01" not in result

    def test_truncates_to_max_length(self):
        from app.diary import sanitize_input

        long_text = "a" * 20000
        result = sanitize_input(long_text, max_length=100)
        assert len(result) <= 100

    def test_empty_input(self):
        from app.diary import sanitize_input

        assert sanitize_input("") == ""
        assert sanitize_input(None) == ""
