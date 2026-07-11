"""加密模块测试"""

import pytest
import base64
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from app.crypto import encrypt_data, decrypt_data, get_or_create_master_key


class TestCrypto:
    def setup_method(self):
        self.key = os.urandom(32)

    def test_encrypt_decrypt_roundtrip(self):
        plaintext = b"Hello, World!"
        encrypted = encrypt_data(plaintext, self.key)
        decrypted = decrypt_data(encrypted, self.key)
        assert decrypted == plaintext

    def test_encrypt_decrypt_unicode(self):
        plaintext = "\u4e2d\u6587\u6d4b\u8bd5".encode("utf-8")
        encrypted = encrypt_data(plaintext, self.key)
        decrypted = decrypt_data(encrypted, self.key)
        assert decrypted == plaintext

    def test_encryption_produces_different_output(self):
        plaintext = b"same text"
        enc1 = encrypt_data(plaintext, self.key)
        enc2 = encrypt_data(plaintext, self.key)
        assert enc1 != enc2  # nonce 不同

    def test_decrypt_wrong_key_fails(self):
        plaintext = b"secret"
        encrypted = encrypt_data(plaintext, self.key)
        wrong_key = os.urandom(32)
        with pytest.raises(Exception):
            decrypt_data(encrypted, wrong_key)

    def test_decrypt_invalid_data_fails(self):
        with pytest.raises(Exception):
            decrypt_data("not-base64!!!", self.key)

    def test_decrypt_too_short_fails(self):
        short = base64.b64encode(b"short").decode()
        with pytest.raises(ValueError, match="密文过短"):
            decrypt_data(short, self.key)

    def test_get_or_create_master_key_returns_32_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            key_file = Path(tmp) / "master.key"
            with patch("app.crypto.MASTER_KEY_FILE", key_file), \
                 patch("app.crypto.SECRET_KEY", ""):
                key = get_or_create_master_key()
                assert len(key) == 32
