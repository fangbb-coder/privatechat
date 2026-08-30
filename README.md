# Private Chat v3.7.0 — HTTPS 安全加固版加密聊天系统

> 当前版本：**v3.7.0**（`main` 分支）。
> 推荐通过 Docker Compose + Nginx 反向代理部署，完整操作手册见 `docs/DEPLOYMENT_OPERATION_MANUAL.md`，
> 简明部署指南见 `docker/DEPLOY.md`。

---

## ✨ 核心特性

### 1. 用户注册与登录
- 支持用户自行注册账户
- 默认管理员用户名：`admin`（**密码首次启动时随机生成并打印一次日志；或通过 `ADMIN_PASSWORD` 环境变量设置**）
- 基于 JWT 的安全认证（Access Token 30 分钟 + Refresh Token 7 天）
- RSA-2048-OAEP（SHA-256）加密登录密码传输，前后端哈希算法严格对齐
- 多端同时登录（默认每用户最多 5 个活跃会话，超出则踢最早）
- Refresh Token 原子轮换（撤销旧 + 写入新，单事务）

### 2. 密码策略
- 最小 8 位，最大 64 位
- 必须包含大小写字母、数字、特殊字符
- 前端实时验证 + 后端二次验证
- bcrypt 哈希存储 + 最近 N 条历史防重复（默认 5 条）

### 3. 端到端消息加密
- 聊天消息统一采用 **AES-256-GCM**（带认证标签防篡改，与浏览器 Web Crypto API 原生兼容）
- 会话密钥由 RSA-OAEP 协商的随机 session key 派生，无需约定静态密码
- 数据库敏感字段 **AES-256-GCM**（PBKDF2-SHA256 派生，独立密钥，HMAC 等值查询）
- RSA-2048-OAEP（SHA-256）非对称密钥交换，持久化存储于 `backend/keys/`

### 4. 实时聊天
- WebSocket 实时通信 + 自动重连 + 心跳
- 在线用户列表实时同步
- 连接/断开系统通知
- 已读/撤回（默认 2 分钟撤回窗口）
- 表情选择器、暗黑模式、移动端响应式

### 5. 管理员功能
- 发布系统公告、查看用户/消息统计
- 禁用/启用、踢出、**删除用户（需管理员密码二次确认）**
- 不能对自己执行踢出/禁用/删除

### 6. 安全防线
- 登录失败 5 次锁定 15 分钟；IP 失败 20 次锁定 30 分钟
- REST 请求 60 次/分钟 · WS 连接 20 次/分钟（单 IP 限流）
- 生产环境 CORS / Host / WS-Origin 强制校验（禁止 `*`）
- CSP / X-Frame / HSTS / X-Content-Type / Referrer-Policy / Permissions-Policy 统一安全响应头
- **MITM 防护**：生产环境 `FORCE_TLS=true` 时拒绝非 HTTPS 请求；Nginx 终止 TLS 并透传 `X-Forwarded-Proto: https`；HSTS preload 锁定 HTTPS
- 密钥分离：JWT 签名密钥 `SECRET_KEY` 与数据库字段加密密钥 `DB_ENCRYPTION_KEY` 独立
- 强 KDF：字段加密使用 PBKDF2-SHA256（20 万次迭代 + 固定盐）
- 异常脱敏：全局异常处理器返回 `error_id`，堆栈细节仅写入服务器日志
- Loguru 结构化日志 + 日志掩码 + 文件轮转
- **生产环境 Docker 镜像以非 root 用户运行**，含多阶段构建与容器健康检查

---

## 🚀 快速开始

### 方式一：Docker 一键部署（推荐）

```bash
# 开发/试用（自动生成密钥、构建并启动）
./docker/deploy.sh --dev
# 访问：http://localhost:8080
```

生产部署：

```bash
cp docker/.env.docker.example .env
# 编辑 .env 填写 SECRET_KEY / DB_ENCRYPTION_KEY / ALLOWED_* / ADMIN_PASSWORD
docker compose up -d --build

# 查看首屏默认管理员密码（首次启动时输出一次到日志）
docker logs privatechat | grep "默认管理员账户"
```

完整生产部署（Nginx HTTPS 反代、域名、证书、备份、升级、监控）见
[`docs/DEPLOYMENT_OPERATION_MANUAL.md`](docs/DEPLOYMENT_OPERATION_MANUAL.md) 与
[`docker/DEPLOY.md`](docker/DEPLOY.md)。

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

- **管理员密码**：首次启动查看日志末尾 `默认管理员账户已创建 - 用户名: admin, 首次随机密码: ...`；或读取 `.env` 中 `ADMIN_PASSWORD`
- **消息加密**：无需静态加密密码，聊天密钥由 RSA-OAEP 协商的随机 session key 派生（AES-256-GCM），登录后自动建立
- 注册：点击登录页"立即注册"，按密码强度要求填写即可

---

## 📚 文档索引

| 文档 | 用途 |
|------|------|
| [`docker/DEPLOY.md`](docker/DEPLOY.md) | Docker 部署简明指南（含 Nginx HTTPS 反代、证书、故障排查） |
| [`docs/DEPLOYMENT_OPERATION_MANUAL.md`](docs/DEPLOYMENT_OPERATION_MANUAL.md) | 完整部署操作手册（环境准备、部署、运维、监控、备份、升级、故障排查） |
| [`nginx-privatechat.conf`](nginx-privatechat.conf) | Nginx HTTPS 反向代理模板（自签证书 + `wss://` 代理 + ForceTLS 透传） |
| [`REPOSITORY_ANALYSIS_REPORT.md`](REPOSITORY_ANALYSIS_REPORT.md) | 仓库问题审计报告（问题分级 + 修复建议） |
| [`docker/docker-compose.yml`](docker/docker-compose.yml) | 生产 Compose 模板（端口映射 + 命名卷 + 健康检查） |
| [`docker/.env.docker.example`](docker/.env.docker.example) | 生产部署 `.env` 模板 |
| [`backend/.env.example`](backend/.env.example) | 裸源部署 `.env` 模板（含 `FORCE_TLS`） |

---

## 🔐 关键安全提醒

1. **密钥绝不能泄露**：`.env` 含 `SECRET_KEY` 与 `DB_ENCRYPTION_KEY`，已加入 `.gitignore`。**两密钥一旦在生产固定后不可更换**（更换需做数据迁移），请在密码管理器中备份。
2. **生产模式必须配置域名/来源**：`ALLOWED_ORIGINS`、`ALLOWED_HOSTS`、`WS_ALLOWED_ORIGINS` 三项不填写或为 `*`，应用会直接拒绝启动。
3. **管理员密码必须在首次启动后立即修改**。
4. **RSA 密钥卷丢失 = 历史消息无法解密**：`chat-keys` 命名卷与数据库卷分开备份，详见操作手册第九章。
5. **单实例单 worker**：应用进程内维护在线用户/消息/限流计数，如需多实例需先迁移至 Redis。
6. **公网访问必须走 HTTPS**：`FORCE_TLS=true` + Nginx 透传 `X-Forwarded-Proto: https`；绝不能把 8080/9090 直接暴露到公网。

---

## 🛠️ 技术栈

| 层 | 技术 |
|----|------|
| 后端 | FastAPI、WebSocket、python-jose（JWT）、bcrypt、PyCryptodome（AES-256-GCM + RSA-OAEP）、SQLite（字段级加密）、Pydantic v2 + pydantic-settings、Loguru、SlowAPI |
| 前端 | 原生 HTML/CSS/JS + Web Crypto API + WebSocket + SessionStorage |
| 部署 | Docker Engine 24+、Docker Compose v2、命名卷（data / logs / keys）、Nginx 反代 HTTPS |
| 测试 | pytest（安全基线测试套件） |

---

## 📂 项目结构

```
/workspace
├── backend/
│   ├── main.py                 # 后端主程序（FastAPI + WS + REST）
│   ├── requirements.txt        # Python 依赖
│   ├── .env.example            # 裸源配置模板
│   ├── models/                 # Pydantic 数据模型
│   │   ├── __init__.py
│   │   └── user.py             # 用户 / 登录 / 消息 / 删除请求模型
│   └── utils/                  # 工具模块
│       ├── __init__.py
│       ├── config.py           # 配置管理（生产强校验 + 密钥分离）
│       ├── logger.py           # 日志初始化
│       ├── encryption.py       # AES / RSA / 密码哈希 / DB 加密（强 KDF）
│       ├── security.py         # 登录失败跟踪 + 速率限制器
│       └── log_masking.py      # 日志掩码
├── frontend/
│   └── index.html              # 前端单页（内联 CSS / JS）
├── docker/
│   ├── Dockerfile              # 多阶段构建 + 非 root + 健康检查
│   ├── docker-compose.yml      # 生产 Compose（环境变量 / 卷 / 日志）
│   ├── .env.docker.example     # 生产 `.env` 模板
│   ├── deploy.sh               # 一键部署脚本
│   └── DEPLOY.md               # Docker 简明指南
├── docs/
│   └── DEPLOYMENT_OPERATION_MANUAL.md  # 完整部署操作手册
├── nginx-privatechat.conf      # Nginx HTTPS 反代模板
├── tests/                      # pytest 安全基线测试
├── REPOSITORY_ANALYSIS_REPORT.md
├── pytest.ini
├── .gitignore
├── .dockerignore
└── README.md                   # 本文档
```

---

## 🇨🇳 中国大陆部署提示

国内网络直接按通用步骤会在公共 CDN / 镜像 / 域名处卡住，按下面调整可一次跑通。

### 代码 clone

GitHub HTTPS 经常被限速或阻断，可用代理镜像：

```bash
git clone --depth 1 https://gh-proxy.com/https://github.com/fangbb-coder/privatechat.git
# 备选：https://mirror.ghproxy.com/  https://ghproxy.net/
```

### Docker 镜像源

`registry-1.docker.io` 在 ECS 出站经常连不上。给 `/etc/docker/daemon.json` 配国内 mirror：

```json
{
  "registry-mirrors": ["https://docker.m.daocloud.io"]
}
# 备选（任选一个能 ping 通的）：https://docker.mirrors.ustc.edu.cn  https://hub-mirror.c.163.com
# 重启：systemctl restart docker
# 验证：docker info | grep "Registry Mirrors"
```

### pip 源加速（构建时）

`docker/Dockerfile` 的 pip 安装通过 `--build-arg` 注入国内镜像即可，无需改文件：

```bash
docker compose build --build-arg PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple \
                     --build-arg PIP_TRUSTED_HOST=pypi.tuna.tsinghua.edu.cn
```

### apt 源（Dockerfile 内 `apt-get install`）

`deb.debian.org` 在国内构建时经常拉取缓慢。可在 `docker/Dockerfile` 的 builder stage 顶部替换为阿里云源：

```dockerfile
RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
        sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources; \
    fi; \
    if [ -f /etc/apt/sources.list ]; then \
        sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list; \
    fi
```

### 前端 JS 离线化

`frontend/index.html` 默认引用 Cloudflare CDN 上的 `crypto-js.min.js` 与 `jsencrypt.min.js`，国内用户经常打不开，导致登录按钮无反应。把 JS 下载到本地，通过 `/static/` 路由服务：

```bash
curl -o frontend/crypto-js.min.js https://cdn.jsdelivr.net/npm/crypto-js@4.1.1/crypto-js.min.js
curl -o frontend/jsencrypt.min.js  https://cdn.jsdelivr.net/npm/jsencrypt@3.3.2/bin/jsencrypt.min.js
sed -i 's|https://cdnjs.cloudflare.com/ajax/libs/crypto-js/4.1.1/crypto-js.min.js|/static/crypto-js.min.js|' frontend/index.html
sed -i 's|https://cdnjs.cloudflare.com/ajax/libs/jsencrypt/3.3.2/jsencrypt.min.js|/static/jsencrypt.min.js|'   frontend/index.html
docker compose build   # 重新构建让 JS 打进镜像
```

### 公网无域名 / 自签证书

公网 IP + 自签证书的已验证方案（验证于阿里云 ECS）：

1. **`.env`**：`ALLOWED_ORIGINS` / `WS_ALLOWED_ORIGINS` 同时填 HTTP 与 HTTPS（过渡期），如 `http://39.107.111.43:9090,https://39.107.111.43`；`ENVIRONMENT=production`、`FORCE_TLS=true`。
2. **Nginx 自签证书**：仓库附 `nginx-privatechat.conf` 模板（80→443 跳转、`wss://` 代理、透传 `X-Forwarded-Proto: https`）。

   ```bash
   mkdir -p /etc/nginx/ssl
   openssl req -x509 -newkey rsa:2048 -nodes \
     -keyout /etc/nginx/ssl/selfsigned.key \
     -out    /etc/nginx/ssl/selfsigned.crt -days 825 -subj "/CN=39.107.111.43"
   cp nginx-privatechat.conf /etc/nginx/conf.d/
   nginx -t && nginx -s reload
   ```

3. **云安全组**：放行 443（HTTPS）与 80（跳转用）。浏览器首次访问自签证书会提示 `NET::ERR_CERT_AUTHORITY_INVALID`，点"高级 → 继续前往"即可（公网生产建议尽快上 Let's Encrypt 正式证书）。
4. **Docker 端口**：Compose 仍映射 `9090:8080`，Nginx 反代到 `127.0.0.1:9090`，对外仅暴露 443。

### GitHub 推送走代理

ECS 上 `git push github.com` 超时，可临时走代理镜像（token 仍放 URL user 部分）：

```bash
git remote set-url origin "https://x-access-token:<TOKEN>@gh-proxy.com/https://github.com/<user>/<repo>.git"
git push origin main
# 完成后立刻把 remote URL 改回 https://github.com/<user>/<repo>.git 防止 token 留在 .git/config
```

---

## 🧪 测试

```bash
pip install pytest
python -m pytest tests/ -q
```

---

## 🌐 外网访问建议

1. **Nginx + Let's Encrypt**（首选生产方案）：见操作手册 5.3 节与 `nginx-privatechat.conf` 模板
2. **Cloudflare Tunnel**：零信任、无需开放端口
3. **FRP**：仓库内提供 `frp/` 示例配置
4. **Ngrok**：仅用于临时演示

---

## ⚠️ 注意事项

1. 生产环境务必使用 HTTPS，HTTP 仅用于本地调试。`FORCE_TLS=true` 会在生产环境强制拒绝非 HTTPS 请求，需 Nginx 透传 `X-Forwarded-Proto: https`。
2. 更改 `SECRET_KEY` 会让所有登录态失效；更改 `DB_ENCRYPTION_KEY` 会让历史用户 / Token 解密失败，生产绝不能随意变更。
3. `RSA keys` 更换将导致登录密码 RSA 解密失败与历史消息无法解密，请务必做好备份。
4. 消息密钥由 RSA-OAEP 协商的随机 session key 派生，无需各方约定相同静态密码。
5. 自签证书浏览器会告警 `NET::ERR_CERT_AUTHORITY_INVALID`，仅适合内网 / 演示；公网生产请使用 Let's Encrypt 正式证书。

---

## 📄 许可证

MIT License
