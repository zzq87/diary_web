"""加密模块 — AES-256-GCM，无降级回退"""

import os
import base64
import logging
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import MASTER_KEY_FILE, SECRET_KEY, safe_chmod, logger

logger = logging.getLogger("diary.crypto")


def get_or_create_master_key() -> bytes:
    if SECRET_KEY:
        import hashlib
        return hashlib.sha256(SECRET_KEY.encode()).digest()

    if MASTER_KEY_FILE.exists():
        return MASTER_KEY_FILE.read_bytes()

    key = os.urandom(32)
    MASTER_KEY_FILE.write_bytes(key)
    safe_chmod(MASTER_KEY_FILE, 0o600)
    logger.warning("已生成新的加密密钥，请备份 master.key 文件")
    return key


def encrypt_data(plaintext: bytes, key: bytes) -> str:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt_data(ciphertext_b64: str, key: bytes) -> bytes:
    raw = base64.b64decode(ciphertext_b64)
    if len(raw) < 28:
        raise ValueError("密文过短，不是 AES-GCM 格式")
    nonce, ciphertext = raw[:12], raw[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
