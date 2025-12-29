#!/bin/bash

# ========================================
# Minimal Chat 自动部署脚本
# 适用于 Ubuntu 20.04/22.04
# GitHub: https://github.com/fangbb-coder/privatechat
# ========================================

set -e  # 遇到错误立即退出

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 配置变量
PROJECT_DIR="/root/minimal-chat"
BACKEND_DIR="$PROJECT_DIR/backend"
VENV_DIR="$BACKEND_DIR/venv"
GITHUB_REPO="https://github.com/fangbb-coder/privatechat.git"

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

# 检查是否为root用户
check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "请使用 root 用户运行此脚本，或使用 sudo"
        exit 1
    fi
}

# 更新系统
update_system() {
    log_step "正在更新系统..."
    apt update && apt upgrade -y
    log_info "系统更新完成"
}

# 安装必要软件
install_dependencies() {
    log_step "正在安装必要软件..."

    # 安装 Python
    apt install -y python3 python3-pip python3-venv

    # 安装 Nginx
    apt install -y nginx

    # 安装 Certbot (用于HTTPS)
    apt install -y certbot python3-certbot-nginx

    # 安装 Git
    apt install -y git

    log_info "软件安装完成"
}

# 获取项目代码
get_project() {
    log_step "正在获取项目代码..."

    # 检查项目目录是否已存在
    if [ -d "$PROJECT_DIR" ]; then
        log_warn "项目目录已存在: $PROJECT_DIR"
        read -p "是否更新现有项目? (y/n): " UPDATE_PROJECT
        if [[ $UPDATE_PROJECT =~ ^[Yy]$ ]]; then
            log_info "正在更新项目..."
            cd "$PROJECT_DIR"
            git pull origin main
            log_info "项目更新完成"
        else
            log_warn "跳过项目更新"
        fi
    else
        read -p "是否从 GitHub 克隆项目? (y/n): " CLONE_FROM_GITHUB
        if [[ $CLONE_FROM_GITHUB =~ ^[Yy]$ ]]; then
            log_info "正在从 GitHub 克隆项目..."
            git clone "$GITHUB_REPO" "$PROJECT_DIR"
            log_info "项目克隆完成"
        else
            log_error "请手动上传项目文件到 $PROJECT_DIR"
            exit 1
        fi
    fi
}

# 配置项目
setup_project() {
    log_step "正在配置项目..."

    # 创建虚拟环境
    log_info "创建 Python 虚拟环境..."
    cd "$BACKEND_DIR"
    python3 -m venv "$VENV_DIR"

    # 激活虚拟环境并安装依赖
    log_info "安装 Python 依赖..."
    source "$VENV_DIR/bin/activate"
    pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
    pip install gunicorn

    log_info "项目配置完成"
}

# 生成随机密钥
generate_secret_key() {
    log_step "生成随机密钥..."
    python3 -c "import secrets; print('SECRET_KEY = \"' + secrets.token_hex(32) + '\"')" > "$BACKEND_DIR/secret_key.txt"
    log_warn "请将 secret_key.txt 中的密钥添加到 main.py 中替换原有 SECRET_KEY"
    log_info "密钥已保存到: $BACKEND_DIR/secret_key.txt"
}

# 配置 Nginx
configure_nginx() {
    log_step "正在配置 Nginx..."

    # 询问域名
    read -p "请输入域名（如果没有，直接回车使用服务器IP）: " DOMAIN_NAME
    if [ -z "$DOMAIN_NAME" ]; then
        SERVER_IP=$(curl -s ifconfig.me)
        DOMAIN_NAME=$SERVER_IP
        log_warn "未配置域名，将使用IP: $SERVER_IP"
    fi

    # 创建 Nginx 配置文件
    cat > /etc/nginx/sites-available/minimal-chat <<EOF
server {
    listen 80;
    server_name $DOMAIN_NAME;

    # 静态文件路径
    location / {
        root /root/minimal-chat/frontend;
        index index.html;
        try_files \$uri \$uri/ /index.html;
    }

    # WebSocket 支持
    location /ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 86400;
    }

    # API 代理
    location /api {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
EOF

    # 启用配置
    ln -sf /etc/nginx/sites-available/minimal-chat /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default

    # 测试配置
    if nginx -t; then
        systemctl restart nginx
        systemctl enable nginx
        log_info "Nginx 配置成功"
    else
        log_error "Nginx 配置失败，请检查配置文件"
        exit 1
    fi
}

# 配置 HTTPS
configure_https() {
    read -p "是否配置 HTTPS? (y/n): " CONFIG_HTTPS
    if [[ $CONFIG_HTTPS =~ ^[Yy]$ ]]; then
        if [ -z "$DOMAIN_NAME" ] || [[ "$DOMAIN_NAME" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            log_warn "域名未配置或为IP地址，跳过 HTTPS 配置"
            return
        fi

        log_step "正在配置 HTTPS..."
        certbot --nginx -d "$DOMAIN_NAME" --non-interactive --agree-tos --email admin@$DOMAIN_NAME

        # 配置自动续期
        cat > /etc/cron.d/certbot <<EOF
0 */12 * * * root test -x /usr/bin/certbot -a \! -d /run/systemd/system && perl -e 'sleep int(rand(3600))' && certbot -q renew
EOF

        log_info "HTTPS 配置完成"
    else
        log_warn "跳过 HTTPS 配置"
    fi
}

# 配置 Systemd 服务
configure_systemd() {
    log_step "正在配置 Systemd 服务..."

    cat > /etc/systemd/system/minimal-chat.service <<EOF
[Unit]
Description=Minimal Chat Backend Service
After=network.target

[Service]
Type=notify
User=root
WorkingDirectory=/root/minimal-chat/backend
Environment="PATH=/root/minimal-chat/backend/venv/bin"
ExecStart=/root/minimal-chat/backend/venv/bin/gunicorn -w 4 -k uvicorn.workers.UvicornWorker -b 127.0.0.1:8080 main:app
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

    # 重载并启动服务
    systemctl daemon-reload
    systemctl restart minimal-chat
    systemctl enable minimal-chat

    # 检查服务状态
    if systemctl is-active --quiet minimal-chat; then
        log_info "Minimal Chat 服务启动成功"
    else
        log_error "Minimal Chat 服务启动失败"
        systemctl status minimal-chat
        exit 1
    fi
}

# 配置防火墙
configure_firewall() {
    log_step "正在配置防火墙..."

    # 检查 UFW 是否安装
    if ! command -v ufw &> /dev/null; then
        apt install -y ufw
    fi

    # 配置规则
    ufw allow ssh
    ufw allow http
    ufw allow https

    # 启用防火墙
    echo "y" | ufw enable

    log_info "防火墙配置完成"
}

# 显示部署信息
show_info() {
    echo ""
    echo "========================================"
    echo "  🎉 部署完成！"
    echo "========================================"
    echo ""
    echo "项目信息:"
    echo "  GitHub: https://github.com/fangbb-coder/privatechat"
    echo "  本地路径: $PROJECT_DIR"
    echo ""
    echo "访问地址:"
    echo "  HTTP:  http://$DOMAIN_NAME"
    echo ""
    if systemctl is-active --quiet minimal-chat; then
        echo "服务状态:"
        echo "  ✅ Minimal Chat: 运行中"
    else
        echo "服务状态:"
        echo "  ❌ Minimal Chat: 未运行"
    fi
    echo ""
    echo "常用命令:"
    echo "  查看服务状态:    systemctl status minimal-chat"
    echo "  重启服务:        systemctl restart minimal-chat"
    echo "  查看日志:        journalctl -u minimal-chat -f"
    echo "  查看 Nginx 日志:  tail -f /var/log/nginx/error.log"
    echo "  更新项目:        cd $PROJECT_DIR && git pull"
    echo ""
    echo "⚠️  重要提醒:"
    echo "  1. 修改 backend/secret_key.txt 中的密钥到 main.py"
    echo "  2. 修改默认用户密码（admin/admin234）"
    echo "  3. 定期备份数据"
    echo "  4. 生产环境必须配置 HTTPS"
    echo "========================================"
    echo ""
}

# 主函数
main() {
    echo "========================================"
    echo "  Minimal Chat 自动部署脚本"
    echo "  GitHub: https://github.com/fangbb-coder/privatechat"
    echo "========================================"
    echo ""

    check_root
    update_system
    install_dependencies
    get_project
    setup_project
    generate_secret_key
    configure_nginx
    configure_https
    configure_systemd
    configure_firewall
    show_info
}

# 执行主函数
main
