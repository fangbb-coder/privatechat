# Private Chat 部署指南 v3.7.0

> 本版本（v3.7.0）在 v3.6.1 安全修复基础上完成 **HTTPS/MITM 防护加固** 与 **关键 Bug 修复**：
> - 强制 TLS（`FORCE_TLS`）、HSTS、CSP 等安全响应头
> - Nginx HTTPS 反向代理（自签证书 + `wss://` 代理）
> - RSA-OAEP 前后端 SHA-256 对齐（修复登录"密码解密失败"）
> - 前端 JS 语法修复（修复登录/注册按钮无反应）
>
> 已修复全部安全问题（详见 `REPOSITORY_ANALYSIS_REPORT.md`），可直接用于生产。

---

## 一、环境要求

- Docker 20.10+（建议 24+）
- Docker Compose v2（`docker compose` 子命令）或 v1（`docker-compose`）
- Nginx（用于 HTTPS 反向代理；裸 HTTP 仅适合本地调试）
- 单机部署；如需多实例，需先将进程内状态迁移到 Redis

---

## 二、快速部署（Docker）

### 方式 A：一键脚本（开发/试用）

```bash
./docker/deploy.sh --dev
```

脚本会自动生成密钥、创建 `.env`、构建镜像并启动服务。完成后访问 http://localhost:8080。

### 方式 B：生产部署

1. **准备配置**

   ```bash
   cp docker/.env.docker.example .env
   ```

2. **生成密钥**（在 `.env` 中填入）

   ```bash
   # JWT 密钥
   python3 -c "import secrets; print(secrets.token_urlsafe(48))"
   # 数据库加密密钥
   python3 -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

3. **编辑 `.env`**，必须填写以下项：

   - `SECRET_KEY`：JWT 签名密钥（长度 ≥ 32）
   - `DB_ENCRYPTION_KEY`：数据库字段加密密钥（长度 ≥ 32）
   - `ENVIRONMENT=production`：生产模式
   - `FORCE_TLS=true`：v3.7.0 新增，生产环境强制 HTTPS（拒绝 `X-Forwarded-Proto != https`）
   - `ALLOWED_ORIGINS`：允许的前端来源，同时填 HTTP（过渡）与 HTTPS，如 `http://39.107.111.43:9090,https://39.107.111.43`
   - `ALLOWED_HOSTS`：受信任主机，如 `39.107.111.43,localhost,127.0.0.1`
   - `WS_ALLOWED_ORIGINS`：WebSocket 允许的来源，与 `ALLOWED_ORIGINS` 一致
   - `ADMIN_PASSWORD`：首次创建管理员用的密码（留空则随机生成并打印在日志中）
   - `APP_VERSION=3.7.0`

4. **启动**

   ```bash
   ./docker/deploy.sh --up
   # 或直接
   docker compose up -d --build
   ```

5. **查看状态与日志**

   ```bash
   docker compose ps
   docker compose logs -f
   ```

---

## 三、部署脚本命令一览

| 命令 | 说明 |
|------|------|
| `./docker/deploy.sh --dev` | 开发模式：自动生成密钥与配置并启动 |
| `./docker/deploy.sh --up` | 构建并启动（需已存在 `.env`） |
| `./docker/deploy.sh --down` | 停止并移除容器 |
| `./docker/deploy.sh --restart` | 重启服务 |
| `./docker/deploy.sh --logs` | 查看实时日志 |
| `./docker/deploy.sh --status` | 查看容器状态 |

---

## 四、Nginx HTTPS 反向代理（v3.7.0 重点）

> 生产环境必须前置 Nginx 终止 TLS。应用层 `ForceTLSMiddleware` 依赖 Nginx 透传的
> `X-Forwarded-Proto: https` 放行请求，否则返回 403「生产环境要求 HTTPS 访问」。
> 安全响应头（HSTS/CSP）由应用层 `SecurityHeadersMiddleware` 统一下发，Nginx 仅负责 TLS 与代理。

仓库附带模板 [`nginx-privatechat.conf`](../nginx-privatechat.conf)，以公网 IP + 自签证书为例：

```nginx
# HTTP -> HTTPS 强制跳转
server {
    listen 80;
    server_name 39.107.111.43;
    return 301 https://$host$request_uri;
}

# HTTPS 反向代理
server {
    listen 443 ssl http2;
    server_name 39.107.111.43;

    ssl_certificate     /etc/nginx/ssl/selfsigned.crt;
    ssl_certificate_key /etc/nginx/ssl/selfsigned.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    client_max_body_size 10m;

    # 前端与 API
    location / {
        proxy_pass http://127.0.0.1:9090;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;   # ⭐ 触发应用层 ForceTLS 放行
        proxy_set_header X-Request-ID $request_id;
    }

    # WebSocket (wss)
    location /ws {
        proxy_pass http://127.0.0.1:9090;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
    }
}
```

### 4.1 自签证书生成与启用

```bash
# 1. 生成自签证书（公网 IP 场景，CN 填 IP）
mkdir -p /etc/nginx/ssl
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout /etc/nginx/ssl/selfsigned.key \
  -out /etc/nginx/ssl/selfsigned.crt \
  -days 825 -subj "/CN=39.107.111.43"

# 2. 部署模板
cp nginx-privatechat.conf /etc/nginx/conf.d/
nginx -t && nginx -s reload

# 3. 云安全组放行 443（HTTPS）与 80（跳转）
```

> 自签证书浏览器会提示 `NET::ERR_CERT_AUTHORITY_INVALID`，点「高级 → 继续前往」即可。
> 公网生产建议尽快换 Let's Encrypt 正式证书（有域名时用 certbot 自动签发）。

### 4.2 域名 + Let's Encrypt（正式生产）

```bash
# 有域名时
certbot --nginx -d chat.example.com
# certbot 会自动改写 nginx 配置并接管证书续期
```

此时 `.env`：

```
ALLOWED_ORIGINS=https://chat.example.com
ALLOWED_HOSTS=chat.example.com
WS_ALLOWED_ORIGINS=https://chat.example.com
FORCE_TLS=true
ENVIRONMENT=production
```

### 4.3 仅本机监听（可选）

如希望 Docker 端口仅本机访问、由 Nginx 转发，可将 compose 端口映射改为 `127.0.0.1:9090:8080`，对外只暴露 443。

---

## 五、数据持久化

`docker-compose.yml` 使用三个命名卷，确保容器重建后数据不丢失：

| 卷名 | 容器路径 | 用途 |
|------|----------|------|
| `chat-data` | `/app/data` | SQLite 数据库（用户、token、密码历史） |
| `chat-logs` | `/app/logs` | 应用日志 |
| `chat-keys` | `/app/backend/keys` | RSA 密钥对（更换会导致旧消息无法解密） |

备份示例：

```bash
# 备份数据
docker run --rm -v private-chat_chat-data:/data -v $(pwd):/backup alpine \
  tar czf /backup/chat-data-$(date +%Y%m%d).tar.gz -C /data .

# 备份 RSA 密钥（重要：丢失则无法解密历史消息）
docker run --rm -v private-chat_chat-keys:/data -v $(pwd):/backup alpine \
  tar czf /backup/chat-keys-$(date +%Y%m%d).tar.gz -C /data .
```

---

## 六、安全注意事项

1. **密钥不可泄露**：`.env` 含 `SECRET_KEY` 与 `DB_ENCRYPTION_KEY`，切勿提交到版本库（已在 `.gitignore` 中忽略）。
2. **首次登录后修改管理员密码**：若 `ADMIN_PASSWORD` 留空，首次启动日志会打印一次性随机密码，请立即登录修改。
3. **生产配置校验**：生产环境若未配置 `SECRET_KEY`/`DB_ENCRYPTION_KEY`/`ALLOWED_ORIGINS`/`ALLOWED_HOSTS`，应用会拒绝启动。
4. **强制 HTTPS**：`FORCE_TLS=true` 时，未经反代透传 `X-Forwarded-Proto: https` 的请求会被拒绝（403）。直连 `http://IP:9090` 仅用于调试，且需临时设 `FORCE_TLS=false`。
5. **单实例运行**：容器以单 worker 运行（应用使用进程内状态）。多实例需先迁移状态到 Redis。
6. **镜像以非 root 用户运行**：容器内进程以 `app` 用户运行，符合最小权限原则。

---

## 七、故障排查（含 v3.7.0 实测案例）

| 现象 | 原因 / 排查 |
|------|------|
| 容器启动后立即退出 | `docker compose logs` 查看是否配置校验失败（密钥/域名缺失） |
| 健康检查失败 | `docker inspect --format='{{.State.Health.Status}}' privatechat`，检查 `/health` 是否可达 |
| 浏览器提示 `ERR_TIMED_OUT` | 云安全组未放行 443；放行 443（与 80 跳转端口） |
| 浏览器提示 `ERR_CERT_AUTHORITY_INVALID` | 自签证书正常告警，点「高级 → 继续前往」；正式生产换 Let's Encrypt |
| 登录/注册按钮**点了无反应** | 前端 JS 语法错误（v3.7.0 已修复 `});`→`}`）；如仍出现，检查 `frontend/index.html` 是否为最新版本并重新 build 镜像 |
| 登录提示「密码解密失败，请刷新页面重试」 | RSA 哈希算法不匹配：前端 Web Crypto 用 SHA-256，后端须 `PKCS1_OAEP.new(..., hashAlgo=SHA256)`（v3.7.0 已修复） |
| 生产环境 403「生产环境要求 HTTPS 访问」 | `FORCE_TLS=true` 但 Nginx 未透传 `X-Forwarded-Proto: https`；检查反代 location 块 |
| 前端加载但无法连接 WS | 检查 `WS_ALLOWED_ORIGINS` 与反向代理的 WebSocket 头配置（`Upgrade`/`Connection`） |
| 旧数据解密失败 | `DB_ENCRYPTION_KEY` 变更会导致旧数据无法解密；换库或换密钥需重新初始化 |
| 权限错误无法写日志 | 卷权限问题，`docker compose down -v` 后重启重建卷（注意会丢数据） |

---

## 八、升级到 v3.7.0（从 v3.6.x）

已在 v3.6.x 部署的实例升级步骤：

1. 拉取最新 main 代码：

   ```bash
   git pull origin main
   ```

2. 更新 `.env`：新增 `FORCE_TLS=true`，`APP_VERSION=3.7.0`，`ALLOWED_ORIGINS`/`WS_ALLOWED_ORIGINS` 追加 HTTPS 来源。

3. 配置 Nginx HTTPS 反代（见第四章），生成自签证书并 reload。

4. 重建并重启容器（**保留数据卷，用户数据不丢**）：

   ```bash
   docker compose up -d --build
   ```

5. 验证：浏览器访问 `https://<IP>`，确认登录/注册可用、消息收发正常、`wss://` 连接建立。

> v3.7.0 移除了 AESEncryptor(CBC) 与 RSA PKCS#1 v1.5 回退。若存在 v3.6.0 旧客户端用 JSEncrypt + CBC 发送的历史消息，将无法解密；建议所有客户端升级到新前端。
