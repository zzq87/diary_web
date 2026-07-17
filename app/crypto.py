"""加密模块 — ChaCha20-Poly1305，向后兼容 AES-256-GCM"""

import os
import base64
import logging
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM

from .config import MASTER_KEY_FILE, SECRET_KEY, safe_chmod

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
    chacha = ChaCha20Poly1305(key)
    nonce = os.urandom(12)
    ciphertext = chacha.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt_data(ciphertext_b64: str, key: bytes) -> bytes:
    raw = base64.b64decode(ciphertext_b64)
    if len(raw) < 28:
        raise ValueError("密文过短")
    nonce, ciphertext = raw[:12], raw[12:]

    # Try ChaCha20-Poly1305 (new), fallback to AES-GCM (legacy)
    for cls in (ChaCha20Poly1305, AESGCM):
        try:
            cipher = cls(key)
            return bytes(cipher.decrypt(nonce, ciphertext, None))
        except Exception:
            continue

    raise ValueError("解密失败: 所有算法均无法解密")
