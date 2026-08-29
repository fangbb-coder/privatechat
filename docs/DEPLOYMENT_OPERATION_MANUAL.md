# Private Chat 部署操作手册 v3.6.1

> 文档版本：v1.0 · 更新日期：2026-08-29
> 适用版本：Private Chat v3.6.x（安全增强版）
> 前置阅读：`REPOSITORY_ANALYSIS_REPORT.md`（已修复问题清单）

---

## 目录

1. [手册概述](#一手册概述)
2. [环境准备](#二环境准备)
3. [部署方式](#三部署方式)
4. [配置详解](#四配置详解)
5. [验证与验收](#五验证与验收)
6. [日常运维](#六日常运维)
7. [监控与日志](#七监控与日志)
8. [安全加固](#八安全加固)
9. [备份与恢复](#九备份与恢复)
10. [升级与回滚](#十升级与回滚)
11. [故障排查](#十一故障排查)
12. [附录](#十二附录)

---

## 一、手册概述

### 1.1 系统定位

Private Chat 是一套端到端加密的 Web 聊天系统，特点：

- 消息 AES-256-CBC 加密（客户端-服务端链路）
- 数据库字段级 AES-256-GCM 加密（独立密钥，PBKDF2 强 KDF）
- 登录密码 bcrypt 哈希 + 历史密码防复用
- RSA-2048 密钥对（登录密码非对称加密传输）
- 登录限流 + IP 封禁 + WebSocket 速率限制
- 严格 CSP / CORS / Host 校验
- 容器非 root 运行

### 1.2 部署拓扑（推荐）

```
                    ┌───────────────────────────────────┐
   公网 HTTPS ──────┤  Nginx / Caddy / 负载均衡          │
   (443)            │  - TLS 终止 / 证书 / WAF           │
                    └──────────────┬────────────────────┘
                                   │ 8080 (仅本机监听)
                    ┌──────────────▼────────────────────┐
                    │  Docker Host (Linux x86_64)        │
                    │  ┌──────────────────────────────┐ │
                    │  │  private-chat:3.6.1           │ │
                    │  │  - 非 root 用户运行            │ │
                    │  │  - 单 worker (单实例)          │ │
                    │  └───────┬──────┬──────┬─────────┘ │
                    │   chat-data │logs │keys (命名卷)  │
                    └──────────────────────────────────┘
```

### 1.3 手册适用场景

| 场景 | 章节 |
|------|------|
| 初次部署（开发/测试） | 第二章 + 第三章 3.1 |
| 初次部署（生产） | 第二章 + 第三章 3.2 |
| 配置调优 | 第四章 |
| 验证部署是否正确 | 第五章 |
| 日常启停/升级/备份 | 第六、九、十章 |
| 监控与安全合规 | 第七、八章 |
| 出问题了不会解决 | 第十一章 |

---

## 二、环境准备

### 2.1 硬件要求

| 部署规模 | 用户并发 | CPU | 内存 | 磁盘 |
|----------|---------|-----|------|------|
| 微型（≤50 人） | ≤20 | 2 vCPU | 2 GB | 20 GB SSD |
| 小型（≤200 人） | ≤100 | 4 vCPU | 4 GB | 50 GB SSD |
| 中型（≤1000 人） | ≤500 | 8 vCPU | 8 GB | 100 GB SSD |
| 大型（>1000 人） | >500 | 建议先将状态迁移到 Redis，再做水平扩展 | | |

> 数据库使用 SQLite，单实例单文件。中型以上建议评估是否迁移到 PostgreSQL。

### 2.2 操作系统

支持：

- Ubuntu 22.04 LTS / 24.04 LTS（推荐，验证最多）
- Debian 11 / 12
- CentOS Stream 9 / Rocky Linux 9
- RHEL 9（需启用 EPEL 提供 docker-compose 插件）

最低内核：Linux 5.4+（cgroup v2 推荐）。

### 2.3 Docker 环境安装

本项目**必须通过 Docker Compose 部署**（不推荐裸源部署）。以下给出 Ubuntu/Debian 一键安装：

```bash
# ----- 1. 卸载系统自带的旧版本 -----
sudo apt-get remove -y docker docker-engine docker.io containerd runc \
  2>/dev/null || true

# ----- 2. 安装依赖 -----
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release

# ----- 3. 添加 Docker 官方 GPG 密钥 -----
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# ----- 4. 添加仓库 -----
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# ----- 5. 安装 Docker Engine + Compose 插件 -----
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# ----- 6. 验证 -----
docker --version          # >= 20.10，建议 24+
docker compose version    # v2，输出 Docker Compose version v2.x
```

**可选**：允许当前用户无需 `sudo` 执行 docker：

```bash
sudo usermod -aG docker $USER
newgrp docker            # 或注销重登
docker run --rm hello-world
```

### 2.4 系统优化（生产必做）

#### 2.4.1 内核参数

```bash
# 备份
sudo cp /etc/sysctl.conf /etc/sysctl.conf.bak.$(date +%Y%m%d)

# 追加以下内容到 /etc/sysctl.conf
cat <<'EOF' | sudo tee -a /etc/sysctl.conf
# Private Chat 优化
fs.file-max = 1048576
fs.inotify.max_user_instances = 8192
fs.inotify.max_user_watches = 262144
net.core.somaxconn = 65535
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_max_syn_backlog = 65535
EOF

# 立即生效
sudo sysctl -p
```

#### 2.4.2 文件句柄限制

```bash
sudo cp /etc/security/limits.conf /etc/security/limits.conf.bak.$(date +%Y%m%d)
cat <<'EOF' | sudo tee -a /etc/security/limits.conf
# Private Chat
* soft nofile 131072
* hard nofile 131072
* soft nproc 65535
* hard nproc 65535
EOF
```

#### 2.4.3 Docker 守护进程配置

```bash
sudo mkdir -p /etc/docker
cat <<'EOF' | sudo tee /etc/docker/daemon.json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "50m",
    "max-file": "3"
  },
  "storage-driver": "overlay2",
  "live-restore": true,
  "userland-proxy": false
}
EOF

sudo systemctl daemon-reload
sudo systemctl restart docker
sudo systemctl enable docker
```

### 2.5 网络与防火墙

#### 端口

| 端口 | 协议 | 来源 | 用途 |
|------|------|------|------|
| 8080 | TCP | 127.0.0.1 / 反代主机 | 应用 HTTP（默认映射） |
| 443 | TCP | 公网 | Nginx/反代 HTTPS（如用反代） |
| 80 | TCP | 公网 | 仅做 HTTPS 跳转 |

> **生产要求**：应用端口 8080 **不要直接对公网开放**，应通过 Nginx/Caddy 反向代理提供 HTTPS。

#### UFW 示例（Ubuntu）

```bash
sudo ufw allow 22/tcp comment "SSH"
sudo ufw allow 80/tcp comment "HTTP redirect"
sudo ufw allow 443/tcp comment "HTTPS"
# 如反代在本机：无需开放 8080；如反代在其他主机，仅授权反代 IP
# sudo ufw allow from 10.0.0.10 to any port 8080 proto tcp comment "Reverse Proxy -> App"
sudo ufw --force enable
sudo ufw status numbered
```

#### 域名与证书

- 提前准备域名，如 `chat.example.com`，A 记录指向服务器公网 IP
- 准备 TLS 证书。推荐使用 Let's Encrypt（certbot）免费签发并自动续期：
  ```bash
  sudo apt-get install -y certbot python3-certbot-nginx
  sudo certbot --nginx -d chat.example.com --agree-tos --no-eff-email -m admin@example.com
  ```

### 2.6 时间同步

聊天与 token 严重依赖系统时间准确：

```bash
sudo timedatectl set-timezone Asia/Shanghai
sudo timedatectl set-ntp on
timedatectl status    # 确认 "NTP service: active" 与 "System clock synchronized: yes"
```

### 2.7 获取源码 / 部署文件

从仓库检出到部署目录（建议 `/opt/private-chat`）：

```bash
sudo mkdir -p /opt/private-chat
sudo chown $USER:$USER /opt/private-chat
cd /opt/private-chat
# Git 方式（推荐）
git clone --branch fix/ai-security-remediation <your_repo_url> .
# 或直接上传以下文件/目录：backend/ frontend/ docker/ docker-compose.yml
```

检查必需文件：

```bash
ls -1
# backend/
# docker/
# docker-compose.yml
# frontend/
```

---

## 三、部署方式

提供三种方式，按需求选择。

### 3.1 方式一：一键脚本（推荐 开发/测试/PoC）

`docker/deploy.sh` 自动生成密钥与配置并启动。

```bash
cd /opt/private-chat
chmod +x docker/deploy.sh
./docker/deploy.sh --dev
```

脚本会输出：
- 管理员账号（默认 `admin`）与随机密码
- 访问地址 `http://localhost:8080`

### 3.2 方式二：生产标准部署（推荐 正式环境）

#### Step 1：准备 .env

```bash
cd /opt/private-chat
cp docker/.env.docker.example .env
chmod 600 .env    # 关键：仅当前用户可读，防止密钥泄露
```

#### Step 2：生成密钥

```bash
# JWT 密钥（长度 >= 64 字符）
SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(48))")
# 数据库加密密钥（长度 >= 43 字符）
DB_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
# 管理员密码（符合强度要求：>=8，含大小写+数字+特殊字符）
ADMIN_PW="PC_$(python3 -c "import secrets; print(secrets.token_urlsafe(10))")!"

echo "SECRET_KEY=$SECRET_KEY"
echo "DB_ENCRYPTION_KEY=$DB_KEY"
echo "ADMIN_PASSWORD=$ADMIN_PW"
# 保存到密码管理器！
```

#### Step 3：编辑 `.env`（生产必填项）

| 变量 | 必填 | 示例 |
|------|------|------|
| `SECRET_KEY` | ✔ | Step 2 生成值 |
| `DB_ENCRYPTION_KEY` | ✔ | Step 2 生成值 |
| `ADMIN_PASSWORD` | ✔/留空 | Step 2 生成值；留空会随机生成并打印一次 |
| `ALLOWED_ORIGINS` | ✔ | `https://chat.example.com` |
| `ALLOWED_HOSTS` | ✔ | `chat.example.com,localhost,127.0.0.1` |
| `WS_ALLOWED_ORIGINS` | ✔ | `https://chat.example.com` |

**最小可用生产 .env 示例**（可直接复制后替换）：

```
ENVIRONMENT=production
HOST_PORT=8080
SECRET_KEY=<上一步生成>
DB_ENCRYPTION_KEY=<上一步生成>
ADMIN_PASSWORD=<上一步生成>
ALLOWED_ORIGINS=https://chat.example.com
ALLOWED_HOSTS=chat.example.com,localhost,127.0.0.1
WS_ALLOWED_ORIGINS=https://chat.example.com
LOG_LEVEL=INFO
```

#### Step 4：构建并启动

```bash
# 构建镜像 + 后台启动（这一步通常 2-5 分钟）
docker compose up -d --build
```

#### Step 5：查看状态

```bash
docker compose ps       # State 应是 Up (healthy)
docker compose logs -f  # 实时日志，Ctrl+C 退出
```

出现 `Private Chat 3.6.1 启动成功` 表示成功。

### 3.3 方式三：裸源部署（不推荐）

用于无法使用 Docker 的特殊场景。详见附录 12.1。

---

## 四、配置详解

全部环境变量定义在 `backend/utils/config.py::Settings`，共 35 项。常用关键项：

### 4.1 密钥类

| 变量 | 默认 | 说明 |
|------|------|------|
| `SECRET_KEY` | 自动生成（仅开发） | JWT 签名密钥；**生产必须显式设置 ≥32 字符**。丢失 = 所有人都要重新登录 |
| `DB_ENCRYPTION_KEY` | 自动生成（仅开发） | 数据库字段加密密钥；**生产必须显式设置 ≥32 字符**。丢失 = 用户名/token 解密失败 = 全库失效 |

> ⚠️ **两密钥一旦生产固定，不可更换**（更换需重做数据迁移）。务必在密码管理器中备份。

### 4.2 登录与安全

| 变量 | 默认 | 说明 |
|------|------|------|
| `ADMIN_USERNAMES` | `admin` | 初始管理员用户名列表（逗号分隔） |
| `ADMIN_PASSWORD` | 空（随机生成） | 首次创建管理员时使用的密码。生产建议显式设置 |
| `MAX_LOGIN_ATTEMPTS` | `5` | 连续失败多少次后锁定账户 |
| `LOGIN_LOCK_MINUTES` | `15` | 账户锁定时长（分钟） |
| `IP_LOCK_THRESHOLD` | `20` | 同 IP 总失败次数阈值 |
| `IP_LOCK_MINUTES` | `30` | IP 锁定时长（分钟） |
| `PASSWORD_HISTORY_COUNT` | `5` | 历史密码重复禁止（最近 N 条） |

### 4.3 Token 与会话

| 变量 | 默认 | 说明 |
|------|------|------|
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | 登录后 Web 会话多久过期 |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | 刷新 token 有效期，超过则需重新登录 |
| `MAX_ACTIVE_SESSIONS` | `5` | 每个用户最多多少端同时登录，超出则踢最早的 |

### 4.4 CORS/Host（安全相关，务必正确）

| 变量 | 示例 | 说明 |
|------|------|------|
| `ALLOWED_ORIGINS` | `https://a.com,https://b.com` | 浏览器跨域访问时允许的前端来源 |
| `ALLOWED_HOSTS` | `chat.example.com,localhost,127.0.0.1` | 允许的 Host 头（`TrustedHostMiddleware`），避免 Host 头攻击。**必须包含 localhost 用于健康检查** |
| `WS_ALLOWED_ORIGINS` | 同 `ALLOWED_ORIGINS` | WebSocket 连接的 Origin 校验。可填 `*`（开发） |

### 4.5 性能/消息

| 变量 | 默认 | 说明 |
|------|------|------|
| `MAX_STORED_MESSAGES` | `1000` | 内存中缓存的最近消息条数（用于撤回、在线用户补发），超出自动淘汰 |
| `MAX_MESSAGE_LENGTH` | `5000` | 单条消息最大字符 |
| `MESSAGE_RECALL_MINUTES` | `2` | 发送后多久内允许撤回 |
| `RATE_LIMIT_PER_MINUTE` | `60` | 单 IP 每分钟最多多少次 REST 请求 |
| `WS_CONNECTIONS_PER_MINUTE` | `20` | 单 IP 每分钟最多多少次 WebSocket 连接 |

### 4.6 日志

| 变量 | 默认 | 说明 |
|------|------|------|
| `LOG_LEVEL` | `INFO` | `DEBUG`/`INFO`/`WARNING`/`ERROR` |

修改 `.env` 后，**重启容器才生效**：

```bash
docker compose restart
```

---

## 五、验证与验收

部署完成后按以下清单逐一验证：

### 5.1 容器状态

```bash
cd /opt/private-chat

# 容器应 Up (healthy)
docker compose ps
# 预期输出：
# NAME           IMAGE               STATUS
# private-chat   private-chat:3.6.1  Up About a minute (healthy)

# 无报错启动日志
docker compose logs private-chat | grep -E "启动成功|ERROR|CRITICAL|校验失败"
# 只应该看到一行 "Private Chat 3.6.1 启动成功"
```

### 5.2 健康检查与基本接口

```bash
# 直接从容器内部（模拟健康检查）
docker exec private-chat python -c "
import urllib.request
req = urllib.request.Request('http://127.0.0.1:8080/health', headers={'Host':'localhost'})
r = urllib.request.urlopen(req, timeout=3)
print('/health:', r.status)
assert r.status == 200
"

# 外部：走反代 HTTPS
curl -sS -o /dev/null -w "GET / (HTTPS) -> %{http_code}\n" https://chat.example.com/
curl -sS https://chat.example.com/api/public-key | python3 -c "
import sys, json
d = json.load(sys.stdin)
assert 'public_key' in d or 'publicKey' in d
print('RSA 公钥接口正常')
"
```

### 5.3 UI 与登录

1. 浏览器打开 `https://chat.example.com/`
2. 页面正常渲染，无 JS 报错（打开 DevTools → Console）
3. 用首次启动日志中的管理员账号 + 密码登录
4. 登录成功后，新开第二个浏览器/无痕窗口注册普通用户
5. 两端互发消息：送达、加密状态标记、撤回功能正常
6. 测试 WebSocket 稳定性：刷新一侧，另一侧仍保持在线列表更新

### 5.4 安全基线

```bash
# 1. 响应头包含安全字段（X-Content-Type-Options、X-Frame-Options、CSP 等）
curl -sS -I https://chat.example.com/ | grep -iE "x-content|x-frame|csp|hsts|permissions"

# 2. 非法 Host 头应被拦截
curl -sS -o /dev/null -w "非法 Host 头拦截 -> %{http_code} (expect 400)\n" \
  -H "Host: evil.com" http://127.0.0.1:8080/

# 3. 非 HTTPS 来源 CORS 被拒（实际跨域会失败）
curl -sS -o /dev/null -w "CORS 非允许来源 -> %{http_code}\n" \
  -H "Origin: https://evil.com" \
  -X OPTIONS https://chat.example.com/api/login
```

### 5.5 数据持久化验证

```bash
# 正常停止容器再启动，数据保留
docker compose down
docker compose up -d
docker exec private-chat ls -la /app/data     # chat.db 应存在
docker exec private-chat ls -la /app/backend/keys   # public.pem / private.pem 应存在
```

验收通过后，进入日常运维阶段。

---

## 六、日常运维

### 6.1 启停

| 动作 | 命令 |
|------|------|
| 启动 | `docker compose up -d --build`（首次/源码变更后） / `docker compose start` |
| 停止 | `docker compose stop`（保留容器） / `docker compose down`（删除容器） |
| 重启 | `docker compose restart` |
| 查看状态 | `docker compose ps` |
| 查看日志 | `docker compose logs -f --tail 100` |
| 进入容器 | `docker exec -it private-chat bash` |

### 6.2 管理员密码变更

登录 Web UI → 右上角设置 → 修改密码，或在容器内：

```bash
docker exec -it private-chat python -c "
import os, sys; sys.path.insert(0, '/app'); os.chdir('/app')
from backend.utils.config import settings
from backend.main import user_db, PasswordHasher
user = user_db.get_user('admin')
user_db.change_password('admin', sys.argv[1])
print('管理员密码已更新')
" -- "NewStr0ng!P@ssword"
```

### 6.3 手动封禁用户

```bash
# 禁用用户（可恢复）
docker exec private-chat python -c "
import sys; sys.path.insert(0, '/app')
from backend.main import user_db
user_db.disable_user('bad_user', True)
print('已禁用 bad_user')
"

# 启用
docker exec private-chat python -c "
import sys; sys.path.insert(0, '/app')
from backend.main import user_db
user_db.disable_user('bad_user', False)
"

# 彻底删除（需先调用管理 API 删除，否则级联不完整）
curl -sS -X DELETE https://chat.example.com/api/admin/user/bad_user \
  -H "Authorization: Bearer <管理员 token>" \
  -H "Content-Type: application/json" \
  -d '{"admin_password": "<管理员当前密码>"}'
```

### 6.4 手动清理过期数据

容器内已有定时清理过期 token 的逻辑（启动时 + 登录触发）。如需强制清理：

```bash
docker exec private-chat python -c "
import sys; sys.path.insert(0, '/app')
from backend.main import user_db
user_db.cleanup_expired_refresh_tokens()
print('过期 refresh tokens 已清理')
"
```

---

## 七、监控与日志

### 7.1 日志位置

| 来源 | 路径 | 保留策略 |
|------|------|----------|
| 应用文件日志（按天轮转） | 命名卷 `chat-logs` 中的 `app.log` | 10MB 轮转，压缩保留 14 天 |
| Docker stdout 日志 | `/var/lib/docker/containers/<id>/<id>-json.log` | 每文件 10MB，保留 3 个 |

查看应用日志：

```bash
# 直接查看命名卷
VOL_PATH=$(docker volume inspect private-chat_chat-logs -f '{{.Mountpoint}}')
sudo tail -50f "$VOL_PATH/app.log"

# 或通过容器
docker exec private-chat tail -50f /app/logs/app.log
```

### 7.2 日志级别切换

编辑 `.env` → `LOG_LEVEL=DEBUG`，然后 `docker compose restart`。  
**生产环境请勿长时间 DEBUG**（日志量剧增）。

### 7.3 关键字段解析

应用日志格式：

```
2026-08-21 07:38:18 | INFO     | utils.logger:setup_logger:61 - 日志系统已初始化
2026-08-21 07:38:19 | WARNING  | main:_ensure_default_admin:355 - 默认管理员账户已创建
^ 时间戳                ^级别     ^模块:函数:行号    ^消息
```

可通过以下 grep 筛重点：

```bash
# 错误与告警
grep -E "ERROR|CRITICAL|WARNING" "$VOL_PATH/app.log" | tail -100

# 登录失败 / 限流
grep -E "登录失败|locked|rate.limit|refused" "$VOL_PATH/app.log"

# 审计：管理员操作
grep -E "管理员|禁用|删除用户|撤销" "$VOL_PATH/app.log"
```

### 7.4 健康监控（Prometheus 示例）

应用未内置 /metrics，但可通过 `/health` + Docker 自身指标做基础监控。以下是一个 `blackbox_exporter` 探测片段：

```yaml
modules:
  private_chat_http:
    prober: http
    http:
      valid_http_versions: ["HTTP/1.1", "HTTP/2.0"]
      valid_status_codes: [200]
      preferred_ip_protocol: ip4
      headers:
        Host: chat.example.com
```

告警条件：
- `probe_success == 0` → 服务不可用
- `container_health_status != 1`（cAdvisor） → 健康检查失败
- `container_memory_usage_bytes / container_spec_memory_limit_bytes > 0.85` → 内存超 85%

---

## 八、安全加固

### 8.1 文件权限

```bash
cd /opt/private-chat
chmod 600 .env
chmod 700 docker/deploy.sh
# 代码文件保持默认 644 即可
```

### 8.2 定期轮换

| 项 | 建议周期 | 方式 |
|------|---------|------|
| TLS 证书 | Let's Encrypt 每 60 天自动续期 | `certbot renew` |
| JWT 签名密钥 | 重大人员变动 / 季度 | 需所有用户重新登录 |
| 管理员密码 | 月度 / 人员变动 | Web UI 修改 |
| 依赖漏洞扫描 | 月度 | 见 8.4 |

### 8.3 访问控制

- 只通过堡垒机登录部署服务器；禁用 root SSH 密码登录
- 仅反代 IP（若独立）可连接 8080，其他全部防火墙丢弃
- `.env` 禁止在 git / 群聊 / 工单中粘贴

### 8.4 漏洞扫描（推荐每月执行一次）

```bash
# 镜像 CVE 扫描（Trivy）
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $HOME/.cache/trivy:/root/.cache/trivy \
  aquasec/trivy image private-chat:3.6.1

# Python 依赖漏洞
docker exec private-chat python -m pip install -q pip-audit \
  && docker exec private-chat python -m pip_audit -f json
```

### 8.5 会话安全

- Token 存在 sessionStorage 中，关闭浏览器自动失效。
- 敏感操作（删除用户、禁用用户）需二次验证管理员密码。
- 密码泄露事件发生后：管理员密码立即变更 + `DB_ENCRYPTION_KEY` 不变（避免迁移成本），但需强制用户重设密码（可禁用全部账户并发送通知）。

---

## 九、备份与恢复

### 9.1 备份清单

需要备份三类数据，前两类**必须加密保存**：

| 数据 | 位置 | 频率 |
|------|------|------|
| ① SQLite 数据库（用户/密码/token） | 命名卷 `chat-data` | 每日 |
| ② RSA 密钥对（端到端消息密钥） | 命名卷 `chat-keys` | 一次（首次生成后备份，更新时再备） |
| ③ 日志（审计） | 命名卷 `chat-logs` | 每日归档 180 天 |

### 9.2 一键备份脚本

保存为 `/opt/private-chat/scripts/backup.sh`（加执行权限）：

```bash
#!/usr/bin/env bash
# Private Chat 一键备份
# 用法: ./backup.sh [输出目录]
set -euo pipefail

OUT_DIR="${1:-/opt/private-chat/backups}"
mkdir -p "$OUT_DIR"
TS=$(date +%Y%m%d_%H%M%S)

cd "$(dirname "$0")/.."
COMPOSE_ROOT=$(pwd)

# 1. 先做数据库在线 checkpoint（防写入期间不一致）
echo "[1/4] 数据库 checkpoint..."
docker exec private-chat python -c "
import sqlite3, os
conn = sqlite3.connect('/app/data/chat.db')
conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
conn.close()
"

# 2. 打包卷内容
echo "[2/4] 备份 chat-data / chat-keys / chat-logs..."
for vol in chat-data chat-keys chat-logs; do
  docker run --rm \
    -v "private-chat_${vol}:/vol:ro" \
    -v "${OUT_DIR}:/out" \
    alpine tar czf "/out/${vol}_${TS}.tar.gz" -C /vol .
done

# 3. 生成 .env 副本（加密：需要 openssl）
echo "[3/4] 备份 .env（AES 加密）..."
if command -v openssl >/dev/null && [[ -f "${COMPOSE_ROOT}/.env" ]]; then
  read -rsp "备份加密密码: " ENC_PW; echo
  openssl enc -aes-256-cbc -pbkdf2 -salt \
    -in "${COMPOSE_ROOT}/.env" \
    -out "${OUT_DIR}/dotenv_${TS}.enc" \
    -k "$ENC_PW"
  echo "  -> dotenv_${TS}.enc (已加密，请独立保管密码)"
fi

# 4. 清理 30 天前备份（按保留策略）
echo "[4/4] 清理 30 天前备份..."
find "$OUT_DIR" -type f -mtime +30 -name "*.tar.gz" -delete
find "$OUT_DIR" -type f -mtime +30 -name "*.enc" -delete

echo "完成：$OUT_DIR (最新备份 ${TS})"
ls -lh "$OUT_DIR" | tail -10
```

### 9.3 恢复流程（灾难恢复演练）

> 每季度至少演练一次。

1. **准备新服务器**：按第二章部署 Docker 与代码
2. **恢复卷**：
   ```bash
   # 恢复 chat-data
   docker run --rm -v private-chat_chat-data:/vol \
     -v /path/to/backups:/back alpine \
     tar xzf /back/chat-data_YYYYMMDD_HHMMSS.tar.gz -C /vol

   # 恢复 chat-keys（重要：否则消息无法解密）
   docker run --rm -v private-chat_chat-keys:/vol \
     -v /path/to/backups:/back alpine \
     tar xzf /back/chat-keys_YYYYMMDD_HHMMSS.tar.gz -C /vol
   ```
3. **恢复 .env**：
   ```bash
   openssl enc -aes-256-cbc -pbkdf2 -d \
     -in dotenv_YYYYMMDD_HHMMSS.enc -out .env -k <备份加密密码>
   chmod 600 .env
   ```
4. **启动 + 验收**：
   ```bash
   docker compose up -d --build
   # 执行第五章全部验收项
   ```

---

## 十、升级与回滚

### 10.1 升级流程

1. **备份！**（第九章）先完整备份再动。
2. 拉取新版本源码：
   ```bash
   cd /opt/private-chat
   git fetch
   git checkout <新版本 tag 或 commit>
   ```
3. 读新版本 `CHANGELOG.md` 或 release notes，关注：
   - 是否新增环境变量（补到 `.env`）
   - 是否有数据迁移脚本
4. 重新构建并启动：
   ```bash
   # 先给旧镜像打 tag，便于回滚
   docker tag private-chat:3.6.1 private-chat:3.6.1.bak
   docker compose up -d --build
   ```
5. 执行第五章验收，失败立即回滚。

### 10.2 回滚

```bash
# 回滚镜像
docker tag private-chat:3.6.1.bak private-chat:3.6.1

# 回滚代码
git checkout <上一版本 commit>

# 重新 up
docker compose up -d
```

> 如果升级中进行了数据库迁移且不兼容旧版本，则需要结合第九章恢复流程同时回滚数据。

---

## 十一、故障排查

按"现象 → 可能原因 → 排查命令 → 修复"的结构给出常见故障全链路。

### 11.1 启动类：容器启动失败

#### 11.1.1 容器启动后立即退出（Restarting / Exited 1）

**排查**：
```bash
cd /opt/private-chat
docker compose logs --tail 50 private-chat
```

**情况 A：日志末尾出现 `ValueError: 配置校验失败`**

| 常见报错 | 原因 | 修复 |
|----------|------|------|
| `production 环境必须显式设置 SECRET_KEY` | 没填 `.env` 的 `SECRET_KEY` | 填值并重启 |
| `DB_ENCRYPTION_KEY 长度必须 >= 32` | 长度不足 | 重新生成长密钥 |
| `必须配置 ALLOWED_HOSTS` | 未填或值为空 | 填写 `域名,localhost,127.0.0.1` |
| `ALLOWED_HOSTS 不能为 ['*']` | 填了 `*` | 改为具体域名列表 |

**情况 B：日志报 `ModuleNotFoundError` / `ImportError`**

原因：镜像构建不完整或依赖安装失败。  
修复：强制重新构建（`--no-cache`）：
```bash
docker compose build --no-cache private-chat
docker compose up -d
```

**情况 C：`.env` 未加载，compose 提示 `interpolation mandated but empty value`**

原因：`.env` 中缺少某个 `:?` 标记的必填变量（`SECRET_KEY` 等）。  
修复：按错误提示补全 `.env`。

#### 11.1.2 构建时 `pip install` 失败（网络/代理）

```bash
# 错误示例：ERROR: Could not find a version that satisfies the requirement
# 或 sslerror / time out

# 解决方案 1：设置 pip 国内镜像
# 编辑 backend/requirements.txt 顶部加
# -i https://pypi.tuna.tsinghua.edu.cn/simple

# 解决方案 2：构建时传代理
docker compose build --build-arg HTTP_PROXY=http://10.0.0.1:7890 private-chat
```

#### 11.1.3 启动日志：`PermissionError: [Errno 13] Permission denied: /app/data/chat.db`

原因：命名卷被 root 创建，容器内 `app` 用户无法写。  
修复：
```bash
# 以 root 身份进入修复属主
docker run --rm -u 0 -v private-chat_chat-data:/vol alpine \
  chown -R 999:999 /vol       # 999 通常是 container 内 app 用户 uid，可用下条命令确认：
# 确认容器内 app 用户 UID：docker exec private-chat id app
docker compose restart
```

---

### 11.2 访问类：浏览器连不上

#### 11.2.1 所有页面都返回 `400 Invalid host header`

**原因**：TrustedHostMiddleware 生效，但请求的 Host 头不在 `ALLOWED_HOSTS` 中。

**排查**：
```bash
# 假设反代域名是 chat.example.com
curl -sS -o /dev/null -w "%{http_code}\n" \
  -H "Host: chat.example.com" http://127.0.0.1:8080/
# 若此命令返回 200 → 反代没把 Host 头正确透传
```

**修复**：
1. 反代 Nginx 中必须有 `proxy_set_header Host $host;`
2. `.env` 的 `ALLOWED_HOSTS` 必须包含 `chat.example.com,localhost,127.0.0.1`
3. 改完重启应用容器 + 重载 Nginx：`docker compose restart` + `sudo nginx -s reload`

#### 11.2.2 健康检查一直 unhealthy

```bash
# 查看详细健康检查状态
docker inspect --format='{{json .State.Health}}' private-chat | python3 -m json.tool
# 最近一次 Log 的 Output 字段会说明失败原因（状态码 / timeout）
```

常见原因：
- `ALLOWED_HOSTS` 不含 `localhost`（修复：加进去重启）
- 应用进程未监听 8080（看 11.1）
- 容器内没装 python（极少，但构建失败会出现）

#### 11.2.3 浏览器 WebSocket 反复断开 / 控制台 403

**原因**：WebSocket 的 Origin 校验失败 / 反代 WebSocket 配置错误。

**排查**：
```bash
# 容器日志中是否出现 "WebSocket连接被拒绝 - Origin验证失败"
docker compose logs | grep -iE "origin|ws|websocket"

# 浏览器 DevTools → Network → WS 协议的请求：
#   检查 Request Headers 中的 Origin 值
#   与 .env 的 WS_ALLOWED_ORIGINS 对比
```

**修复**：
1. `.env` 的 `WS_ALLOWED_ORIGINS` 追加缺失的 Origin（逗号分隔）
2. Nginx `/ws` 块必须带：
   ```
   proxy_http_version 1.1;
   proxy_set_header Upgrade $http_upgrade;
   proxy_set_header Connection "upgrade";
   proxy_read_timeout 600s;
   ```

#### 11.2.4 跨域 CORS 报错（DevTools Console 报 `blocked by CORS policy`）

原因：前端部署的域名不在 `ALLOWED_ORIGINS`。  
修复：`.env` 的 `ALLOWED_ORIGINS` 加入前端域名（含协议 `https://`），重启应用。

---

### 11.3 功能类：登录/聊天异常

#### 11.3.1 登录一直提示"用户名或密码错误"

**排查**：
1. 用管理员账号能登录吗？→ 能 → 该用户密码错误或被禁用
   ```bash
   docker exec private-chat python -c "
   import sys; sys.path.insert(0, '/app')
   from backend.main import user_db
   u = user_db.get_user('alice')
   print('用户存在:', bool(u), '禁用:', u['is_disabled'] if u else None)
   "
   ```
2. 日志是否提示账户被锁定：
   ```bash
   docker compose logs | grep -iE "locked|lock"
   ```
3. 前后端 RSA 解密失败？→ 浏览器 Console / 应用日志有无 "RSA 解密失败"

**修复**：
- 被锁定 → 等待 `LOGIN_LOCK_MINUTES` 分钟后重试，或管理员重置密码
- RSA 解密失败 → 检查 `HTTP://chat.example.com/api/public-key` 返回的公钥是否正确完整

#### 11.3.2 收不到对方消息 / 发送没响应

通常是 WebSocket 通道断开或被阻塞。

排查：
1. 浏览器 DevTools → Network → WS 帧（Frames）里看对方消息帧是否到达
2. `docker compose logs` 有无 "客户端连接断开"、"rate limit"、"Origin 验证失败"
3. 确认 `clients` 是否为该用户维护了连接（临时加 debug 接口）：

```bash
docker exec private-chat python -c "
import sys; sys.path.insert(0, '/app')
from backend.main import clients
users = {c['username'] for c in clients}
print('在线用户:', sorted(users))
print('总连接数:', len(clients))
"
```

#### 11.3.3 "消息加密/解密失败"

- 原因 A：聊天双方约定的"加密密码"不同 → 同步密码
- 原因 B：RSA 私钥被替换 → 恢复 chat-keys 卷备份
- 原因 C：`DEFAULT_ENCRYPTION_KEY` 在 .env 中与首次部署时不同 → 保持一致

#### 11.3.4 无法撤回消息

- 撤回窗口超过 `MESSAGE_RECALL_MINUTES`（默认 2 分钟）
- 或应用重启后 `messages` 内存缓存被清空 → 这是已知限制；撤回仅依赖进程内状态
- 或 `MAX_STORED_MESSAGES` 太小，消息已被淘汰 → 调大该值

---

### 11.4 数据类：数据丢失 / 解密失败

#### 11.4.1 重启后所有用户都提示账号不存在

**原因**：`DB_ENCRYPTION_KEY` 被改动。所有用户名是 HMAC + 加密存储，密钥一改就无法索引。

**排查**：
```bash
# 对比当前 .env 的 DB_ENCRYPTION_KEY 与备份时的版本
# 列出容器内 chat.db 的 users 表记录数（应 >0）
docker exec private-chat python -c "
import sqlite3
conn = sqlite3.connect('/app/data/chat.db')
print('users 记录数:', conn.execute('SELECT COUNT(*) FROM users').fetchone()[0])
"
```

**修复**：从密码管理器取回原 `DB_ENCRYPTION_KEY` 填回 `.env` 并重启。**无备份则不可逆丢数据**。

#### 11.4.2 消息历史显示"解密失败"

**原因**：`chat-keys` 卷中的 RSA 私钥被替换。  
**修复**：按第九章 9.3 恢复 `chat-keys_*.tar.gz` 备份。

#### 11.4.3 数据库锁（`sqlite3.OperationalError: database is locked`）

偶发是正常的。频繁出现：
- 容器 CPU 严重不足（升级规格）
- 数据目录在网络盘上（改回本地 SSD）
- 同时多进程操作数据库（本项目应仅单 worker，检查 compose 是否 `--workers 2+`，应保持为 1）

---

### 11.5 安全类 / 合规类

#### 11.5.1 安全响应头缺失

```bash
# 检查
curl -sS -I https://chat.example.com/ | grep -iE "content-security|strict-transport|x-frame"
```

如为空：
- 是否走了 `ENVIRONMENT=development`？开发环境不加安全头（应设置 `ENVIRONMENT=production`）
- 是否被中间 WAF / 反代剥离了响应头（Nginx `proxy_pass_header` 需确认）

#### 11.5.2 发现 IP 异常大量登录失败

```bash
# 找到攻击 IP
docker compose logs | grep -E "登录失败|login_fail" | awk '{print $IP}' \
  | sort | uniq -c | sort -rn | head -20

# 临时封禁（示例 UFW）
sudo ufw insert 1 deny from 192.0.2.100 comment "chat brute force"
```

应用本身有 IP 锁定（`IP_LOCK_THRESHOLD`/`IP_LOCK_MINUTES`），但前置 WAF/Cloudflare 流量清洗更重要。

---

### 11.6 故障诊断通用流程

遇到新故障不知道从哪下手，走这套五步：

1. **看容器状态** → `docker compose ps`
2. **看日志** → `docker compose logs --tail 200 private-chat`
3. **看健康检查** → `docker inspect private-chat` → Health.Log
4. **看卷权限** → 9.1.3 的 PermissionError 修复命令
5. **回退到最简复现**：用 `ENVIRONMENT=development HOST=0.0.0.0 python -m uvicorn backend.main:app` 直接裸跑验证是否真的是代码问题。

如果还解决不了，收集信息后发工单：

```
环境: Ubuntu 22.04 / Docker 26.1 / Compose v2.27
现象: 浏览器打开后 10s 断 WS
已做:
  - docker compose ps: healthy
  - 日志 grep Origin: 发现 "Origin验证失败: http://new.example.com"
  - .env 中未加 new.example.com
临时绕过: 加了域名后恢复，但为什么会有这个 Origin？
```

---

## 十二、附录

### 12.1 附录 A：裸源部署（无 Docker）

> 强烈不推荐。仅用于 Docker 不可用场景。

```bash
# 1. 准备 Python 3.11+
sudo apt install -y python3.11 python3-venv python3-pip

# 2. 项目目录
cd /opt/private-chat
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt

# 3. 环境变量
cp docker/.env.docker.example .env
# 填好密钥与域名后，使用如下方式加载：
export $(grep -v '^#' .env | xargs)

# 4. 启动（建议用 systemd 托管，systemd unit 示例如下）
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8080 --workers 1
```

systemd unit 示例 `/etc/systemd/system/private-chat.service`：

```ini
[Unit]
Description=Private Chat
After=network.target

[Service]
Type=simple
User=appuser
WorkingDirectory=/opt/private-chat
EnvironmentFile=-/opt/private-chat/.env
ExecStart=/opt/private-chat/.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 8080 --workers 1
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 12.2 附录 B：Nginx 完整配置模板

保存为 `/etc/nginx/sites-available/chat.example.com.conf`，`ln -s` 到 sites-enabled。

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name chat.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name chat.example.com;

    # 建议 certbot 自动管理以下两行
    ssl_certificate     /etc/letsencrypt/live/chat.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chat.example.com/privkey.pem;

    # TLS 安全基线
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # 上传限制（聊天无文件，但防滥用）
    client_max_body_size 1m;

    # 前端/API
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # 超时
        proxy_connect_timeout 10s;
        proxy_send_timeout    300s;
        proxy_read_timeout    300s;

        # 响应头安全基线（与应用重复设置无妨）
        add_header X-Content-Type-Options nosniff always;
        add_header X-Frame-Options DENY always;
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header Referrer-Policy strict-origin-when-cross-origin always;
    }

    # WebSocket 专属 location（比通用 location 优先级高）
    location = /ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
    }

    # 日志（可选接入 ELK/结构化日志采集）
    access_log /var/log/nginx/chat.example.com.access.log;
    error_log  /var/log/nginx/chat.example.com.error.log warn;
}
```

### 12.3 附录 C：快速自检命令集（运维日常）

```bash
# 保存为 ./scripts/sanity.sh，chmod +x 后每日巡检
cd /opt/private-chat

echo "===== 1. 容器状态 ====="
docker compose ps

echo -e "\n===== 2. 健康检查详情 ====="
docker inspect --format='状态={{.State.Health.Status}} 失败次数={{.State.Health.FailingStreak}}' private-chat

echo -e "\n===== 3. 启动错误 ====="
docker compose logs private-chat 2>&1 | grep -iE "error|critical|exception|校验失败|解密失败" | tail -10

echo -e "\n===== 4. API 自检 ====="
for path in /health /api/public-key; do
  code=$(curl -sSo /dev/null -w "%{http_code}" -H "Host: chat.example.com" http://127.0.0.1:8080$path)
  echo "$path -> $code"
done

echo -e "\n===== 5. 响应安全头 ====="
curl -sSI https://chat.example.com/ | grep -iE "x-frame|x-content|csp|strict-transport|permissions" | sort

echo -e "\n===== 6. 最近 100 条审计 ====="
VOL=$(docker volume inspect private-chat_chat-logs -f '{{.Mountpoint}}')
sudo tail -100 "$VOL/app.log" 2>/dev/null | grep -iE "管理员|禁用|删除|登录失败|locked|撤销" | tail -10
```

### 12.4 附录 D：变更记录

| 版本 | 日期 | 变更 |
|------|------|------|
| v1.0 | 2026-08-29 | 初版发布（对应 Private Chat v3.6.1 安全增强版） |

---

**EOF — 有问题请结合仓库内 `docker/deploy.sh --help` 与 `REPOSITORY_ANALYSIS_REPORT.md` 一并查阅。**
