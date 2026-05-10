#!/usr/bin/env python3
"""日记备份解密工具

用法:
    python decrypt_backup.py backup.zip          # 解密到当前目录
    python decrypt_backup.py backup.zip -o /tmp  # 解密到指定目录
    python decrypt_backup.py backup.zip -l        # 列出备份内容
    python decrypt_backup.py backup.zip --raw      # 不解密，直接解压
"""

import argparse
import json
import sys
import zipfile
from pathlib import Path
import hashlib
import base64

# ─── 加密模块（与 server.py 相同） ──────────────────
def decrypt_data(ciphertext_b64: str, key: bytes) -> bytes:
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        raw = base64.b64decode(ciphertext_b64)
        nonce, ciphertext = raw[:12], raw[12:]
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    except ImportError:
        return _simple_decrypt(ciphertext_b64, key)


def _simple_decrypt(ciphertext_b64: str, key: bytes) -> bytes:
    data = base64.b64decode(ciphertext_b64)
    result = bytearray()
    for i, b in enumerate(data):
        result.append(b ^ key[i % len(key)])
    return bytes(result)


def find_master_key() -> bytes:
    """查找 master.key 文件"""
    candidates = [
        Path(__file__).parent / "config" / "master.key",
        Path(__file__).parent / ".hermes" / "diary_web" / "config" / "master.key",
        Path.home() / ".hermes" / "diary_web" / "config" / "master.key",
    ]
    
    for path in candidates:
        if path.exists():
            return path.read_bytes()
    
    return None


def list_backup(zip_path: str):
    """列出备份内容"""
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile:
        print("❌ 无效的 ZIP 文件")
        sys.exit(1)
    
    # 读取元数据
    if "metadata.json" in zf.namelist():
        metadata = json.loads(zf.read("metadata.json"))
        print("📦 备份信息:")
        print(f"   创建时间: {metadata.get('created', '未知')}")
        print(f"   创建者:   {metadata.get('created_by', '未知')}")
        print(f"   日记数:   {metadata.get('total_entries', 0)}")
        print(f"   已加密:   {'是' if metadata.get('encrypted') else '否'}")
        if metadata.get('decrypted'):
            print(f"   ⚠️  明文备份，请妥善保管!")
        print()
    
    # 列出文件
    md_files = [n for n in zf.namelist() if n.endswith('.md')]
    print(f"📄 日记文件 ({len(md_files)} 篇):")
    for name in sorted(md_files):
        size = zf.getinfo(name).file_size
        print(f"   {name} ({size} bytes)")
    
    zf.close()


def decrypt_backup(zip_path: str, output_dir: str = None, raw: bool = False):
    """解密备份"""
    try:
        zf = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile:
        print("❌ 无效的 ZIP 文件")
        sys.exit(1)
    
    # 读取元数据
    if "metadata.json" in zf.namelist():
        metadata = json.loads(zf.read("metadata.json"))
        if metadata.get('decrypted'):
            print("ℹ️  此备份已是明文，无需解密")
            raw = True
        elif not metadata.get('encrypted'):
            print("ℹ️  此备份未加密，直接解压")
            raw = True
    
    if not raw:
        # 需要解密
        master_key = find_master_key()
        if not master_key:
            print("❌ 找不到 master.key 加密密钥")
            print("请将此工具放在 diary_web 目录下，或设置 --key 参数")
            sys.exit(1)
        print(f"🔑 已找到加密密钥 ({len(master_key)} bytes)")
    
    output = Path(output_dir) if output_dir else Path.cwd()
    output.mkdir(parents=True, exist_ok=True)
    
    md_files = [n for n in zf.namelist() if n.endswith('.md')]
    restored = 0
    failed = 0
    
    for name in md_files:
        try:
            content = zf.read(name).decode("utf-8")
            
            if not raw and content.startswith("ENC:"):
                # 解密
                decrypted = decrypt_data(content[4:], master_key)
                content = decrypted.decode("utf-8")
            
            # 写入文件
            dest_path = output / name
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            dest_path.write_text(content, encoding="utf-8")
            restored += 1
        except Exception as e:
            print(f"   ❌ 失败: {name} - {e}")
            failed += 1
    
    zf.close()
    
    print(f"\n✅ 解密完成!")
    print(f"   成功: {restored} 篇")
    if failed:
        print(f"   失败: {failed} 篇")
    print(f"   输出目录: {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="日记备份解密工具")
    parser.add_argument("backup", help="备份 ZIP 文件路径")
    parser.add_argument("-o", "--output", help="输出目录（默认当前目录）")
    parser.add_argument("-l", "--list", action="store_true", help="列出备份内容")
    parser.add_argument("--raw", action="store_true", help="不解密，直接解压")
    parser.add_argument("--key", help="指定 master.key 路径")
    
    args = parser.parse_args()
    
    if args.list:
        list_backup(args.backup)
    else:
        decrypt_backup(args.backup, args.output, args.raw)
