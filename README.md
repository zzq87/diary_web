# 📝 本地日记本 — 安全增强版 v3

轻量级 Web 日记管理工具，基于 Markdown 文件存储，无需数据库。

## 安全特性

| 功能 | 说明 |
|------|------|
| 🔐 AES-256 加密 | 日记文件使用 AES-256-GCM 加密存储（无降级回退） |
| 🔑 密码认证 | PBKDF2-SHA256（600000 次迭代）哈希存储 |
| 🛡️ 会话管理 | httpOnly Cookie 认证 + 自动超时锁定 |
| 📜 审计日志 | 所有操作记录（登录、读写、删除） |
| ⚡ 速率限制 | 登录爆破防护 + API 频率限制 |
| 🔒 安全响应头 | CSP（无 unsafe-inline）、X-Frame-Options、XSS 防护 |
| 🛑 路径遍历防护 | 防止 `../` 目录穿越攻击 |
| 💾 加密备份 | 流式 ZIP 备份，支持事务性恢复 |
| 🧹 Markdown 消毒 | 渲染时移除 script/iframe 等危险标签 |

## 快速启动

```bash
cd diary_web
pip install -r requirements.txt
python main.py
```

默认账号：`admin` / `admin123`
⚠️ **首次登录后请立即修改密码！**

## 访问地址

- 本地：http://127.0.0.1:9000
- 局域网：http://<your-ip>:9000

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `DIARY_DIR` | `./data` | 日记存储路径 |
| `DIARY_SECRET_KEY` | 自动生成 | 加密主密钥 |
| `DIARY_SESSION_TIMEOUT` | `3600` | 会话超时（秒） |
| `DIARY_MAX_LOGIN_ATTEMPTS` | `5` | 最大登录尝试次数 |
| `DIARY_LOGIN_LOCKOUT` | `300` | 登录锁定时间（秒） |
| `DIARY_ENCRYPT` | `true` | 是否启用加密 |
| `DIARY_DEFAULT_PASSWORD` | `admin123` | 默认密码（建议修改） |
| `DIARY_PBKDF2_ITERATIONS` | `600000` | 密码哈希迭代次数 |
| `DIARY_PORT` | `9000` | 服务端口 |
| `DIARY_PROXY_CONNECT_ADDR` | `192.168.1.2` | WSL 端口转发目标地址 |

## 项目结构

```
diary_web/
├── app/                 # 应用模块
│   ├── __init__.py
│   ├── api.py           # API 路由
│   ├── auth.py          # 认证（密码、用户、Session、速率限制）
│   ├── config.py        # 配置管理
│   ├── crypto.py        # 加密模块（AES-256-GCM）
│   ├── diary.py         # 日记操作（读写、搜索、统计）
│   └── middleware.py    # 中间件（安全头、认证装饰器）
├── static/
│   └── index.html       # 前端页面
├── tests/               # 单元测试
│   ├── test_crypto.py
│   ├── test_auth.py
│   └── test_diary.py
├── main.py              # 入口文件
├── requirements.txt
├── decrypt_backup.py    # 离线解密工具
└── README.md
```

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
│   └── audit.log      # 审计日志（| 分隔符）
```

## 运行测试

```bash
pip install pytest
pytest tests/ -v
```

## 重要提示

1. **备份 master.key** — 丢失后无法解密已有日记
2. **首次登录修改密码** — 通过 `DIARY_DEFAULT_PASSWORD` 环境变量设置自定义默认密码
3. **定期导出备份** — 设置页面支持一键下载 ZIP
4. **旧 XOR 加密文件** — v3 不再支持 XOR 回退，升级前请确保所有文件已迁移为 AES-GCM 格式
