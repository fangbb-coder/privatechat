#!/usr/bin/env bash
# Private Chat - 一键部署脚本
# 用法：
#   ./docker/deploy.sh            # 交互式生成 .env 并启动
#   ./docker/deploy.sh --dev      # 开发模式（自动生成密钥，不强制校验域名）
#   ./docker/deploy.sh --up       # 直接启动（已有 .env）
#   ./docker/deploy.sh --down     # 停止并移除容器
#   ./docker/deploy.sh --logs    # 查看日志
#   ./docker/deploy.sh --restart  # 重启
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

ENV_FILE="$PROJECT_DIR/.env"
MODE="${1:-}"

# 颜色
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# 检查 docker / compose 命令
COMPOSE_CMD=""
if command -v docker compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
else
    error "未找到 docker compose 或 docker-compose，请先安装 Docker。"
    exit 1
fi

gen_key() {
    python3 -c "import secrets; print(secrets.token_urlsafe(${1:-48}))" 2>/dev/null \
        || openssl rand -base64 "${1:-48}" 2>/dev/null \
        || head -c "${1:-48}" /dev/urandom | base64
}

generate_env() {
    if [[ -f "$ENV_FILE" ]]; then
        warn "检测到已存在 .env 文件。"
        read -rp "是否覆盖？(y/N) " confirm
        [[ "$confirm" =~ ^[Yy]$ ]] || { info "保留现有 .env，继续启动。"; return 0; }
    fi

    local dev_mode=0
    [[ "${1:-}" == "--dev" ]] && dev_mode=1

    local secret_key db_key admin_password
    secret_key=$(gen_key 48)
    db_key=$(gen_key 32)
    admin_password=$(gen_key 12)

    cat > "$ENV_FILE" <<EOF
# 由 deploy.sh 生成于 $(date '+%Y-%m-%d %H:%M:%S')
# 模式: $([[ $dev_mode -eq 1 ]] && echo "开发（dev，自动生成密钥与域名）" || echo "生产")

APP_NAME=Private Chat
APP_VERSION=3.6.1
ENVIRONMENT=$([[ $dev_mode -eq 1 ]] && echo "development" || echo "production")
HOST_PORT=8080

# 密钥（已自动生成）
SECRET_KEY=$secret_key
DB_ENCRYPTION_KEY=$db_key

# 管理员
ADMIN_USERNAMES=admin
ADMIN_PASSWORD=$admin_password

ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
MAX_ACTIVE_SESSIONS=5

MIN_PASSWORD_LENGTH=8
MAX_PASSWORD_LENGTH=64
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGITS=true
PASSWORD_REQUIRE_SPECIAL=true
PASSWORD_HISTORY_COUNT=5

MAX_LOGIN_ATTEMPTS=5
LOGIN_LOCK_MINUTES=15
IP_LOCK_THRESHOLD=20
IP_LOCK_MINUTES=30

RATE_LIMIT_PER_MINUTE=60
RATE_LIMIT_MAX_IPS=10000
WS_CONNECTIONS_PER_MINUTE=20

MESSAGE_RECALL_MINUTES=2
MAX_MESSAGE_LENGTH=5000
MAX_STORED_MESSAGES=1000
DEFAULT_ENCRYPTION_KEY=PrivateChat2025Secure!

RSA_KEY_SIZE=2048

# CORS / Host
ALLOWED_ORIGINS=$([[ $dev_mode -eq 1 ]] && echo "http://localhost:8080,http://127.0.0.1:8080" || echo "请填写你的域名，例如 https://chat.example.com")
ALLOWED_HOSTS=$([[ $dev_mode -eq 1 ]] && echo "localhost,127.0.0.1" || echo "请填写你的域名，例如 chat.example.com")
WS_ALLOWED_ORIGINS=$([[ $dev_mode -eq 1 ]] && echo "http://localhost:8080,http://127.0.0.1:8080" || echo "请填写你的域名，例如 https://chat.example.com")

LOG_LEVEL=INFO
EOF
    info ".env 已生成: $ENV_FILE"
    if [[ $dev_mode -eq 1 ]]; then
        info "开发模式已启用："
        info "  - 首次管理员密码: $admin_password"
        info "  - 访问地址: http://localhost:8080"
    else
        warn "生产模式：请编辑 .env 填写真实域名，否则启动会因配置校验失败。"
        warn "  管理员密码已写入 .env: $admin_password"
        warn "  请妥善保管 .env 文件，切勿提交到版本库。"
    fi
}

case "$MODE" in
    --dev)
        generate_env --dev
        info "构建并启动（开发模式）..."
        $COMPOSE_CMD up -d --build
        info "等待服务就绪..."
        sleep 5
        $COMPOSE_CMD ps
        ;;
    --up|"")
        [[ ! -f "$ENV_FILE" ]] && { error ".env 不存在。请先运行: ./docker/deploy.sh --dev 或复制 docker/.env.docker.example 为 .env"; exit 1; }
        info "构建并启动..."
        $COMPOSE_CMD up -d --build
        sleep 3
        $COMPOSE_CMD ps
        ;;
    --down)
        info "停止并移除容器..."
        $COMPOSE_CMD down
        ;;
    --logs)
        $COMPOSE_CMD logs -f --tail=100
        ;;
    --restart)
        $COMPOSE_CMD restart
        $COMPOSE_CMD ps
        ;;
    --status)
        $COMPOSE_CMD ps
        ;;
    *)
        cat <<EOF
${BLUE}Private Chat 部署脚本${NC}

用法:
  ./docker/deploy.sh              直接启动（需已存在 .env）
  ./docker/deploy.sh --dev        开发模式：自动生成密钥与配置并启动
  ./docker/deploy.sh --up         构建并启动
  ./docker/deploy.sh --down       停止并移除容器
  ./docker/deploy.sh --restart    重启服务
  ./docker/deploy.sh --logs       查看实时日志
  ./docker/deploy.sh --status     查看容器状态

首次部署：
  ./docker/deploy.sh --dev
  然后访问 http://localhost:8080

生产部署：
  cp docker/.env.docker.example .env
  # 编辑 .env 填写密钥与域名
  ./docker/deploy.sh --up
EOF
        ;;
esac
