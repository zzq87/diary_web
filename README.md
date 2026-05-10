# 📝 本地日记本 — 安全增强版

轻量级命令行日记管理工具，基于 Markdown 文件存储，无需数据库。

## 安全特性

| 功能 | 说明 |
|------|------|
| 🔐 AES-256 加密 | 日记文件使用 AES-256-GCM 加密存储 |
| 🔑 密码认证 | PBKDF2-SHA256 哈希存储，支持修改密码 |
| 🛡️ 会话管理 | Token 认证 + 自动超时锁定 |
| 📜 审计日志 | 所有操作记录（登录、读写、删除） |
| ⚡ 速率限制 | 登录爆破防护 + API 频率限制 |
| 🔒 安全响应头 | CSP、X-Frame-Options、XSS 防护 |
| 🛑 路径遍历防护 | 防止 `../` 目录穿越攻击 |
| 💾 加密备份 | 一键导出 ZIP 备份 |

## 快速启动

```bash
cd /home/zq/diary_web
.venv/bin/python server.py
```

默认账号：`admin` / `admin123`
⚠️ **首次登录后请立即修改密码！**

## 访问地址

- 本地：http://127.0.0.1:9000
- 局域网：http://192.168.1.2:9000

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DIARY_DIR` | `./data` | 日记存储路径 |
| `DIARY_SECRET_KEY` | 自动生成 | 加密主密钥 |
| `DIARY_SESSION_TIMEOUT` | `3600` | 会话超时（秒） |
| `DIARY_MAX_LOGIN_ATTEMPTS` | `5` | 最大登录尝试次数 |
| `DIARY_LOGIN_LOCKOUT` | `300` | 登录锁定时间（秒） |
| `DIARY_ENCRYPT` | `true` | 是否启用加密 |

## 数据文件

```
diary_web/
├── data/              # 日记文件（加密存储）
│   └── 2026/
│       └── 05/
│           └── 10.md  # ENC: 开头表示已加密
├── config/
│   ├── master.key     # 加密密钥（重要！请备份）
│   ├── users.json     # 用户数据（哈希存储）
│   ├── sessions.json  # 会话令牌
│   ├── rate_limits.json
│   └── audit.log      # 审计日志
├── server.py
└── static/
    └── index.html
```

## 重要提示

1. **备份 master.key** — 丢失后无法解密已有日记
2. **首次登录修改密码** — 默认密码 admin123
3. **定期导出备份** — 设置页面支持一键下载 ZIP
