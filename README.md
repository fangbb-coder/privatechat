# Private Chat v3.7.0 — HTTPS 安全加固版加密聊天系统

> 本仓库已完成两轮安全加固：首轮全面审计与修复（见 `REPOSITORY_ANALYSIS_REPORT.md`），
> 次轮 HTTPS/MITM 防护加固（强制 TLS + HSTS/CSP + RSA-OAEP-SHA256 对齐）。
> 当前版本：**v3.7.0**（main 分支）。
> 推荐通过 Docker Compose + Nginx 反向代理部署，完整操作手册见 `docs/DEPLOYMENT_OPERATION_MANUAL.md`，
> 简明部署指南见 `docker/DEPLOY.md`。

---

## 📌 版本说明

| 版本 | 说明 |
|------|------|
| v3.6.0 | 原始发布版本（存在若干安全与可用性问题） |
| v3.6.1 | 首轮 AI 安全修复：补全缺失模块、密钥分离、强 KDF、CSP 加固、异常脱敏、RSA 解密加固、删除用户二次确认等 |
| **v3.7.0** | **当前版本，HTTPS/MITM 防护加固 + 关键 Bug 修复**。变更如下。 |

### v3.7.0 变更一览（HTTPS 安全加固 + Bug 修复）

**🔴 关键 Bug 修复（登录/注册不可用）**
- ✅ **前端 JS 语法错误**：修复 `frontend/index.html` 消息渲染循环结尾的 `});`（误带 `)`），改为正确的 `}`。该错误导致整页 JS 解析中断，**登录/注册按钮点击无反应**。
- ✅ **RSA 密码解密失败**：前端 Web Crypto API 使用 `RSA-OAEP` + **SHA-256**，而后端 `PKCS1_OAEP.new()` 默认使用 SHA-1，哈希算法不匹配导致登录提示"密码解密失败，请刷新页面重试"。已在 `RSAEncryptor.encrypt/decrypt` 与 `decrypt_session_key` 中显式指定 `hashAlgo=SHA256`，前后端对齐。

**🛡️ MITM 防护（HTTPS 强制）**
- ✅ **ForceTLSMiddleware**：生产环境（`ENVIRONMENT=production` + `FORCE_TLS=true`）拒绝 `X-Forwarded-Proto != https` 的请求，返回 403，防止 HTTP 明文传输下的中间人攻击。
- ✅ **Nginx HTTPS 反向代理**：提供 `nginx-privatechat.conf` 模板，负责 TLS 终止、HTTP→HTTPS 强制跳转、`wss://` WebSocket 代理，并透传 `X-Forwarded-Proto: https` 触发应用层 ForceTLS 放行。
- ✅ **HSTS**：`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`，仅在 HTTPS 响应中声明（避免在偶发 HTTP 响应中误导）。
- ✅ **CSP 等安全响应头**：`SecurityHeadersMiddleware` 统一下发 CSP / X-Content-Type-Options / X-Frame-Options / Referrer-Policy / Permissions-Policy / Cache-Control。

**🔐 加密栈清理（移除剩余技术债）**
- ✅ **移除 AESEncryptor（CBC）**：消息加密统一为 AES-256-GCM（带认证标签防篡改），不再保留 CBC 旧消息兼容路径。
- ✅ **移除 RSA PKCS#1 v1.5 回退**：`RSAEncryptor.decrypt` 统一使用 RSA-OAEP，不再兼容旧 JSEncrypt 客户端；新前端已全用 OAEP。
- ✅ **移除 `DEFAULT_ENCRYPTION_KEY`**：消息加密改用 RSA-OAEP 协商的随机 session key + AES-256-GCM，不再依赖静态密码。

**⚙️ 配置**
- ✅ `APP_VERSION` 升至 `3.7.0`；新增 `FORCE_TLS=true`；`ALLOWED_ORIGINS`/`WS_ALLOWED_ORIGINS` 同时放行 HTTP（过渡）与 HTTPS 来源。
- ✅ `.env.example` 同步新增 `FORCE_TLS` 配置项与说明。

### v3.6.1 变更一览（首轮 AI 安全修复）

**🔴 致命修复**
- ✅ 补全缺失的 `utils/config.py` 与 `utils/logger.py` 模块（原仓库无法启动）
- ✅ 从 git 移除已泄露的 `data/.secret_key` 跟踪（**部署时必须重新生成密钥**）
- ✅ 移除硬编码默认管理员凭据，改为环境变量注入或首次随机生成

**🟠 高危修复**
- ✅ **密钥分离**：JWT 签名密钥 `SECRET_KEY` 与数据库字段加密密钥 `DB_ENCRYPTION_KEY` 独立
- ✅ **强 KDF**：数据库字段加密改用 PBKDF2-SHA256（20 万次迭代 + 固定盐）替代裸 SHA-256
- ✅ **TrustedHost 校验**：生产环境 `ALLOWED_HOSTS` 禁止 `["*"]`，配置为空或非法直接拒绝启动
- ✅ **CSP 加固**：脚本走 `script-src 'self'`；如未将内联脚本迁出，需补 `'unsafe-inline' 'unsafe-hashes'` 兼容 `onclick` 内联事件（v3.6.1 部署笔记中加了这两项；如将 inline `<script>` 与 `onclick` 迁出到 `app.js` 等外部脚本，可恢复严格策略）
- ✅ **异常脱敏**：全局异常处理器返回 `error_id`，不再把堆栈细节回传客户端
- ✅ **RSA 解密加固**：统一错误路径 + 随机 sentinel，降低填充预言可区分性
- ✅ **删除用户二次确认**：删除账户要求管理员密码校验（与踢出/禁用一致）

**🟡 中危修复**
- ✅ **HMAC 等值查询**：users/password_history/refresh_tokens 新增 `username_hmac` 列与索引，避免用户名查询时全表扫描解密
- ✅ **密码历史按用户过滤**：修复密码历史比对会跨用户的逻辑错误
- ✅ **消息内存上限**：`messages` 字典按条数上限（默认 1000）自动淘汰最旧消息，防止内存泄漏
- ✅ **Refresh Token 原子轮换**：撤销旧 + 写入新改为单事务，防竞态
- ✅ **Docker 镜像修复**：拷贝前端、非 root 用户运行、多阶段构建、内置健康检查
- ✅ **裸异常处理**：30+ 处 `except Exception: pass/continue` 改为捕获具体类型并记录日志
- ✅ **配置对齐**：`.env.example` 与 `Settings` 字段完整同步，共 35 项
- ✅ **依赖管理**：移除未维护的 `passlib`、锁定版本下限、纠正 `python-jose` 实际依赖

**🟢 低危修复**
- ✅ 移除 DEBUG 日志中的密钥/IV/明文输出
- ✅ 新增 7 项安全基线测试（`tests/`），全部通过

---

## ✨ 核心特性

### 1. 用户注册与登录
- 支持用户自行注册账户
- 默认管理员用户名：`admin`（**密码首次启动时随机生成并打印一次日志；或通过 `ADMIN_PASSWORD` 环境变量设置**）
- 基于 JWT 的安全认证（Access Token 30 分钟 + Refresh Token 7 天）
- RSA-2048 加密登录密码传输
- 多端同时登录（默认每用户最多 5 个活跃会话，超出则踢最早）
- Token 轮换机制（原子化）

### 2. 密码策略
- 最小 8 位，最大 64 位
- 必须包含大小写字母、数字、特殊字符
- 前端实时验证 + 后端二次验证
- bcrypt 哈希存储 + 最近 N 条历史防重复（默认 5 条）
- 登录密码经 **RSA-2048-OAEP（SHA-256）** 加密传输，前端使用 Web Crypto API，后端 `hashAlgo=SHA256` 对齐解密

### 3. 端到端消息加密
- 聊天消息 **AES-256-GCM**（带认证标签防篡改，与浏览器 Web Crypto API 兼容），使用 RSA-OAEP 协商的随机 session key，无需静态密码
- 数据库敏感字段 **AES-256-GCM**（PBKDF2-SHA256 派生，独立密钥，HMAC 等值查询）
- **RSA-2048-OAEP（SHA-256）** 非对称密钥交换（前后端哈希算法对齐），持久化存储于 `backend/keys/`
- v3.7.0 已移除 AESEncryptor(CBC) 与 RSA PKCS#1 v1.5 回退，加密栈统一为 RSA-OAEP + AES-256-GCM

### 4. 实时聊天
- WebSocket 实时通信 + 自动重连 + 心跳
- 在线用户列表实时同步
- 连接/断开系统通知
- 已读/撤回（默认 2 分钟）
- 表情选择器、暗黑模式、移动端响应式

### 5. 管理员功能
- 发布系统公告、查看用户/消息统计
- 禁用/启用、踢出、**删除用户（需密码二次确认）**
- 不能对自己执行踢出/禁用/删除

### 6. 安全防线
- 登录失败 5 次锁定 15 分钟
- IP 失败 20 次锁定 30 分钟
- REST 请求 60 次/分钟 · WS 连接 20 次/分钟（单 IP）
- 生产 CORS / Host / WS-Origin 强制校验（禁止 `*`）
- CSP / X-Frame / HSTS / X-Content-Type / Referrer-Policy / Permissions-Policy 响应头
- **MITM 防护（v3.7.0）**：生产环境 `FORCE_TLS=true` 时拒绝非 HTTPS 请求；Nginx 终止 TLS 并透传 `X-Forwarded-Proto: https`；HSTS preload 锁定 HTTPS
- Loguru 结构化日志 + 日志掩码工具 + 文件轮转
- **生产环境镜像以非 root 用户运行**

---

## 🚀 快速开始

### 方式一：Docker 一键部署（推荐）

```bash
# 开发/试用（自动生成密钥、构建并启动）
./docker/deploy.sh --dev
# 访问：http://localhost:8080
```

生产部署详见 [`docs/DEPLOYMENT_OPERATION_MANUAL.md`](docs/DEPLOYMENT_OPERATION_MANUAL.md) 或：

```bash
cp docker/.env.docker.example .env
# 编辑 .env 填写 SECRET_KEY / DB_ENCRYPTION_KEY / ALLOWED_* / ADMIN_PASSWORD
docker compose up -d --build
# 仓库 v3.6.1 起附带 docker/docker-compose.yml（之前缺失）；
# 9090 端口映射到容器 8080，含 data/logs/keys 三个命名卷与健康检查。

# 查看首屏默认管理员密码（首次启动时输出一次到日志）
docker logs privatechat | grep "默认管理员账户"
```

### 方式二：裸源（仅开发调试）

```bash
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 开发模式（自动生成密钥、允许 localhost 跨域）
ENVIRONMENT=development python3 main.py
# 访问：http://localhost:8080
```

### 首次登录

- **管理员密码**：首次启动时查看日志末尾 `默认管理员账户已创建 - 用户名: admin, 首次随机密码: ...`；或读取 `.env` 中 `ADMIN_PASSWORD`
- **消息加密**：v3.7.0 起无需静态加密密码，聊天密钥由 RSA-OAEP 协商的随机 session key 派生（AES-256-GCM），登录后自动建立
- 注册：点击登录页"立即注册"，按密码强度要求填写即可

---

## 📚 文档索引

| 文档 | 用途 |
|------|------|
| [`docker/DEPLOY.md`](docker/DEPLOY.md) | **Docker 部署简明指南 v3.7.0**（含 Nginx HTTPS 反代、自签证书、故障排查） |
| [`docs/DEPLOYMENT_OPERATION_MANUAL.md`](docs/DEPLOYMENT_OPERATION_MANUAL.md) | **部署操作手册 v1.0**（环境准备、部署、运维、监控、备份、升级、故障排查全套） |
| [`nginx-privatechat.conf`](nginx-privatechat.conf) | v3.7.0 Nginx HTTPS 反向代理模板（自签证书 + wss 代理 + ForceTLS 透传） |
| [`REPOSITORY_ANALYSIS_REPORT.md`](REPOSITORY_ANALYSIS_REPORT.md) | 仓库问题审计报告（问题分级 + 修复建议） |
| [`docker/docker-compose.yml`](docker/docker-compose.yml) | 生产 compose 模板（端口映射 + 命名卷 + 健康检查） |
| [`docker/.env.docker.example`](docker/.env.docker.example) | 生产部署 `.env` 模板（35 项） |
| [`backend/.env.example`](backend/.env.example) | 裸源部署 `.env` 模板（含 v3.7.0 `FORCE_TLS`） |

---

## 🔐 关键安全提醒

1. **密钥绝不能泄露**：`.env` 含 `SECRET_KEY` 与 `DB_ENCRYPTION_KEY`，已加入 `.gitignore`。**两密钥一旦在生产固定后不可更换**（更换需做数据迁移），请在密码管理器中备份。
2. **生产模式必须配置域名**：`ALLOWED_ORIGINS`、`ALLOWED_HOSTS`、`WS_ALLOWED_ORIGINS` 三项不填写或为 `*`，应用会直接拒绝启动。
3. **管理员密码必须在首次启动后立即修改**。
4. **RSA 密钥卷丢失 = 历史消息无法解密**：`chat-keys` 命名卷与数据库卷分开备份，详见操作手册第九章。
5. **单实例单 worker**：应用进程内维护在线用户/消息/限流计数，如需多实例需先迁移至 Redis。

---

## 🛠️ 技术栈

| 层 | 技术 |
|----|------|
| 后端 | FastAPI、WebSocket、python-jose（JWT）、bcrypt、PyCryptodome（AES-256-GCM/CBC + RSA）、SQLite（字段级加密）、Pydantic v2 + pydantic-settings、Loguru、SlowAPI |
| 前端 | 原生 HTML/CSS/JS + CryptoJS + JSEncrypt + WebSocket + SessionStorage |
| 部署 | Docker Engine 24+、Docker Compose v2、命名卷（data/logs/keys）、Nginx 反代 HTTPS |
| 测试 | pytest（7 项安全基线） |

---

## 📂 项目结构

```
/workspace
├── backend/
│   ├── main.py                 # 后端主程序（FastAPI app + WS + REST）
│   ├── requirements.txt        # Python 依赖
│   ├── .env.example            # 裸源配置模板
│   ├── models/                 # Pydantic 数据模型
│   │   ├── __init__.py
│   │   └── user.py             # 用户/登录/消息/删除请求模型
│   └── utils/                  # 工具模块
│       ├── __init__.py
│       ├── config.py           # ⭐ 配置管理（生产校验 + 密钥分离）
│       ├── logger.py           # ⭐ 日志初始化
│       ├── encryption.py       # ⭐ AES/RSA/密码哈希/DB 加密（强 KDF）
│       ├── security.py         # 登录失败跟踪 + 速率限制器
│       └── log_masking.py      # 日志掩码
├── frontend/
│   └── index.html              # 前端单页（内联 CSS/JS）
├── docker/
│   ├── Dockerfile              # 多阶段构建 + 非 root + 健康检查
│   ├── docker-compose.yml      # ⭐ 生产 compose（环境变量/卷/日志）
│   ├── .env.docker.example     # .env 生产模板
│   ├── deploy.sh               # ⭐ 一键部署脚本
│   └── DEPLOY.md               # Docker 简明指南
├── docs/
│   └── DEPLOYMENT_OPERATION_MANUAL.md  # ⭐ 完整部署操作手册 v1.0
├── nginx-privatechat.conf      # ⭐ v3.7.0 Nginx HTTPS 反代模板（自签证书 + wss）
├── tests/                      # pytest 安全基线测试
├── REPOSITORY_ANALYSIS_REPORT.md
├── pytest.ini
├── .gitignore
├── .dockerignore
└── README.md                   # 本文档
```

---

## 🇨🇳 中国大陆部署提示

国内网络环境直接按上述步骤会卡在几处公共 CDN / 镜像 / 域名上，按下面小改可一次跑通。

### 4.1 代码 clone

GitHub HTTPS 经常被 GFW 掐或极慢，用代理镜像：

```bash
git clone --depth 1 https://gh-proxy.com/https://github.com/fangbb-coder/privatechat.git
# 备选：https://mirror.ghproxy.com/  https://ghproxy.net/
```

### 4.2 Docker 镜像源

`registry-1.docker.io` 在 ECS 出站经常连不上。给 `/etc/docker/daemon.json` 配国内 mirror：

```json
{
  "registry-mirrors": ["https://docker.m.daocloud.io"]
}
# 备选（任选一个能 ping 通的）：https://docker.mirrors.ustc.edu.cn  https://hub-mirror.c.163.com
# 重启：systemctl restart docker
# 验证：docker info | grep "Registry Mirrors"
```

> 经验：阿里云 `docker.mirrors.aliyun.com` 与腾讯云 `mirror.ccs.tencent-cloud.com` 的 host 在 ECS 内 DNS 解析不到（NXDOMAIN），daocloud 是验证可用的一个。

### 4.3 apt 源（Dockerfile 内 `apt-get install`）

`deb.debian.org` 在国内 build 慢（拉 21MB gcc 经常卡十几分钟）。在 `docker/Dockerfile` 改阿里云源：

```dockerfile
RUN set -eux;     if [ -f /etc/apt/sources.list.d/debian.sources ]; then         sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources;     fi;     if [ -f /etc/apt/sources.list ]; then         sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list;     fi
```

### 4.4 pip 跨阶段传递

原 `Dockerfile` 用 `pip install --user` 装到 `~/.local`，runtime stage 不会自动进 `sys.path`（`No module named uvicorn`），必须改 `--target`：

```dockerfile
# builder 阶段
RUN pip install --no-cache-dir --target=/install -r requirements.txt

# runtime 阶段
COPY --from=builder --chown=app:app /install /home/app/.local
ENV PYTHONPATH=/home/app/.local:/app:/app/backend
```

### 4.5 前端 JS 国内加载

`frontend/index.html` 默认引用 `cdnjs.cloudflare.com/.../crypto-js.min.js` 与 `jsencrypt.min.js`，国内用户 CDN 经常被墙，会导致登录按钮**点了无反应**（fetch 根本没发出去）。把 JS 下载到 `frontend/` 用项目自带的 `/static/` 路由 serve：

```bash
curl -o frontend/crypto-js.min.js https://cdn.jsdelivr.net/npm/crypto-js@4.1.1/crypto-js.min.js
curl -o frontend/jsencrypt.min.js https://cdn.jsdelivr.net/npm/jsencrypt@3.3.2/bin/jsencrypt.min.js
sed -i 's|https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js|/static/crypto-js.min.js|' frontend/index.html
sed -i 's|https://cdnjs.cloudflare.com/ajax/libs/jsencrypt/3.3.2/jsencrypt.min.js|/static/jsencrypt.min.js|' frontend/index.html
docker compose build   # 重新 build 让 JS 进 image
```

### 4.6 浏览器双 CSP 冲突

后端 `SecurityHeadersMiddleware` 发的 `script-src 'self'` 与 `frontend/index.html` `<meta CSP>` 的 `script-src 'self' 'unsafe-inline'` union 后取最严，内联 `<script>` 与 `onclick` 全被拒，**登录按钮看似无反应**。如未迁移内联脚本到外部文件，需在 `backend/main.py` 同步加：

```python
"script-src 'self' 'unsafe-inline' 'unsafe-hashes'; "
```

### 4.7 公网无域名 / 自签证书

v3.7.0 提供了公网 IP + 自签证书的可落地方案（已验证于阿里云 ECS）：

1. **`.env`** 里 `ALLOWED_ORIGINS` / `WS_ALLOWED_ORIGINS` 同时填 HTTP 与 HTTPS（过渡期），如 `http://39.107.111.43:9090,https://39.107.111.43`；`ENVIRONMENT=production`、`FORCE_TLS=true`。
2. **Nginx 自签证书**：仓库附带 `nginx-privatechat.conf` 模板（监听 80 跳转 443、`wss://` 代理、透传 `X-Forwarded-Proto: https`）。自签证书生成：

   ```bash
   mkdir -p /etc/nginx/ssl
   openssl req -x509 -newkey rsa:2048 -nodes -keyout /etc/nginx/ssl/selfsigned.key \
     -out /etc/nginx/ssl/selfsigned.crt -days 825 -subj "/CN=39.107.111.43"
   # 拷贝模板并 reload
   cp nginx-privatechat.conf /etc/nginx/conf.d/
   nginx -t && nginx -s reload
   ```

3. **云安全组**：放行 443（HTTPS）与 80（跳转用）。浏览器首次访问自签证书会提示 `NET::ERR_CERT_AUTHORITY_INVALID`，点"高级 → 继续前往"即可（生产建议尽快上 Let's Encrypt 正式证书）。
4. **Docker 端口**：compose 仍映射 `9090:8080`，Nginx 反代到 `127.0.0.1:9090`，对外仅暴露 443。

### 4.8 GitHub 推送走代理

ECS 上 `git push github.com` 超时，可临时走代理镜像（token 仍放 URL user 部分）：

```bash
git remote set-url origin "https://x-access-token:<TOKEN>@gh-proxy.com/https://github.com/<user>/<repo>.git"
git push origin main
# 完事立刻把 remote URL 改回 https://github.com/<user>/<repo>.git 防止 token 留在 .git/config
```

---
---

## 🧪 测试

```bash
pip install pytest
python -m pytest tests/ -q
# 预期：7 passed
```

---

## 🌐 外网访问建议

1. **Nginx + Let's Encrypt**（首选生产方案）：见操作手册 5.3 节、附录 B 完整模板
2. **Cloudflare Tunnel**：零信任、无需开放端口
3. **FRP**：仓库内提供 `frp/` 示例
4. **Ngrok**：仅用于临时演示

---

## ⚠️ 注意事项

1. 生产环境务必使用 HTTPS，HTTP 仅用于本地调试。v3.7.0 起 `FORCE_TLS=true` 会在生产环境强制拒绝非 HTTPS 请求，需 Nginx 透传 `X-Forwarded-Proto: https`。
2. 更改 `SECRET_KEY` 会让所有登录态失效；更改 `DB_ENCRYPTION_KEY` 会让历史用户/token 解密失败，生产绝不能随意变更。
3. `RSA keys` 更换将导致**登录密码 RSA 解密失败与历史消息无法解密**，请务必做好备份。
4. v3.7.0 起消息密钥由 RSA-OAEP 协商的随机 session key 派生，无需各方约定相同静态密码。
5. 自签证书浏览器会告警 `NET::ERR_CERT_AUTHORITY_INVALID`，仅适合内网/演示；公网生产请使用 Let's Encrypt 正式证书。

---

## 📄 许可证

MIT License
