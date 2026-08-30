# Private Chat 部署指南

本指南介绍如何通过 Docker 一键部署 Private Chat。已修复全部安全问题（详见 `REPOSITORY_ANALYSIS_REPORT.md`），可直接用于生产。

## 一、环境要求

- Docker 20.10+（建议 24+）
- Docker Compose v2（`docker compose` 子命令）或 v1（`docker-compose`）
- 单机部署；如需多实例，需先将进程内状态迁移到 Redis

## 二、快速部署（推荐）

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
   - `ALLOWED_ORIGINS`：允许的前端来源，如 `https://chat.example.com`
   - `ALLOWED_HOSTS`：受信任主机，如 `chat.example.com,localhost,127.0.0.1`（建议包含 `localhost,127.0.0.1` 以供容器内健康检查通过）
   - `WS_ALLOWED_ORIGINS`：WebSocket 允许的来源
   - `ADMIN_PASSWORD`：首次创建管理员用的密码（留空则随机生成并打印在日志中）

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

## 三、部署脚本命令一览

| 命令 | 说明 |
|------|------|
| `./docker/deploy.sh --dev` | 开发模式：自动生成密钥与配置并启动 |
| `./docker/deploy.sh --up` | 构建并启动（需已存在 `.env`） |
| `./docker/deploy.sh --down` | 停止并移除容器 |
| `./docker/deploy.sh --restart` | 重启服务 |
| `./docker/deploy.sh --logs` | 查看实时日志 |
| `./docker/deploy.sh --status` | 查看容器状态 |

## 四、数据持久化

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

## 五、反向代理与 HTTPS

生产环境建议在前置 Nginx 反向代理并启用 HTTPS，仅暴露 443。
Nginx 层负责 HTTP→HTTPS 跳转与 HSTS/CSP（纵深防御，与应用层中间件叠加）：

```nginx
# HTTP → HTTPS 强制跳转
server {
    listen 80;
    server_name chat.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name chat.example.com;

    ssl_certificate     /etc/ssl/chat.example.com.pem;
    ssl_certificate_key /etc/ssl/chat.example.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # HSTS（反代层；应用层中间件也会在 HTTPS 响应重复声明）
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

    # CSP（反代层；与后端 SecurityHeadersMiddleware 一致，纵深防御）
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' wss:; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'" always;

    # 前端与 API
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    # WebSocket
    location /ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 600s;
    }
}
```

此时 `.env` 配置：

```
ALLOWED_ORIGINS=https://chat.example.com
ALLOWED_HOSTS=chat.example.com
WS_ALLOWED_ORIGINS=https://chat.example.com
HOST_PORT=8080     # 仅本机监听，由 Nginx 转发
```

如需仅本机监听，可将 compose 端口映射改为 `127.0.0.1:8080:8080`。

## 六、安全注意事项

1. **密钥不可泄露**：`.env` 含 `SECRET_KEY` 与 `DB_ENCRYPTION_KEY`，切勿提交到版本库（已在 `.gitignore` 中忽略）。
2. **首次登录后修改管理员密码**：若 `ADMIN_PASSWORD` 留空，首次启动日志会打印一次性随机密码，请立即登录修改。
3. **生产配置校验**：生产环境若未配置 `SECRET_KEY`/`DB_ENCRYPTION_KEY`/`ALLOWED_ORIGINS`/`ALLOWED_HOSTS`，应用会拒绝启动。
4. **单实例运行**：容器以单 worker 运行（应用使用进程内状态）。多实例需先迁移状态到 Redis。
5. **镜像以非 root 用户运行**：容器内进程以 `app` 用户运行，符合最小权限原则。

## 七、故障排查

| 现象 | 排查 |
|------|------|
| 容器启动后立即退出 | `docker compose logs` 查看是否配置校验失败（密钥/域名缺失） |
| 健康检查失败 | `docker inspect --format='{{.State.Health.Status}}' private-chat`，检查 `/health` 是否可达 |
| 前端加载但无法连接 WS | 检查 `WS_ALLOWED_ORIGINS` 与反向代理的 WebSocket 头配置 |
| 旧数据解密失败 | `DB_ENCRYPTION_KEY` 变更会导致旧数据无法解密；换库或换密钥需重新初始化 |
| 权限错误无法写日志 | 卷权限问题，`docker compose down -v` 后重启重建卷（注意会丢数据） |
