#!/bin/bash

# Private Chat 部署脚本
# 用于自动化部署到生产服务器

set -e  # 遇到错误立即退出

# 配置变量
SERVER_USER="ubuntu"
SERVER_IP="3.26.0.34"
SERVER_PATH="/root/minimal-chat"
BACKEND_PATH="$SERVER_PATH/backend"
FRONTEND_PATH="$SERVER_PATH/frontend"
NGINX_CONFIG_PATH="/etc/nginx/sites-available/minimal-chat"
SERVICE_NAME="minimal-chat"

echo "========================================="
echo "Private Chat 部署脚本"
echo "========================================="

# 1. 检查本地文件
echo ""
echo "步骤 1: 检查本地文件..."
if [ ! -d "backend" ] || [ ! -d "frontend" ]; then
    echo "错误: 找不到 backend 或 frontend 目录"
    exit 1
fi
echo "✓ 本地文件检查完成"

# 2. 创建 .env 文件（如果不存在）
echo ""
echo "步骤 2: 配置环境变量..."
if [ ! -f "backend/.env" ]; then
    echo "创建 .env 文件..."
    read -p "请输入服务器域名 (例如: 3.26.0.34): " DOMAIN
    read -p "请输入管理员用户名 (默认: admin): " ADMIN_USER
    
    DOMAIN=${DOMAIN:-"3.26.0.34"}
    ADMIN_USER=${ADMIN_USER:-"admin"}
    
    cat > backend/.env << EOF
# 环境配置
ENVIRONMENT=production

# 允许的域名列表（CORS 配置）
ALLOWED_ORIGINS='["http://$DOMAIN", "https://$DOMAIN"]'

# WebSocket 允许的域名列表
WS_ALLOWED_ORIGINS='["http://$DOMAIN", "https://$DOMAIN"]'

# 管理员用户名
ADMIN_USERNAMES=$ADMIN_USER

# 日志级别
LOG_LEVEL=INFO

# 服务器配置
HOST=0.0.0.0
PORT=8080
EOF
    echo "✓ .env 文件创建完成"
else
    echo "✓ .env 文件已存在"
fi

# 3. 上传文件到服务器
echo ""
echo "步骤 3: 上传文件到服务器..."
echo "上传后端文件..."
pscp -i e:\fang.ppk -r backend/* $SERVER_USER@$SERVER_IP:$BACKEND_PATH/
echo "上传前端文件..."
pscp -i e:\fang.ppk frontend/index.html $SERVER_USER@$SERVER_IP:$FRONTEND_PATH/
echo "✓ 文件上传完成"

# 4. 配置 Nginx
echo ""
echo "步骤 4: 配置 Nginx..."
read -p "请输入服务器域名 (例如: 3.26.0.34): " DOMAIN
DOMAIN=${DOMAIN:-"3.26.0.34"}

plink -i e:\fang.ppk $SERVER_USER@$SERVER_IP << 'ENDSSH'
sudo bash -s << 'ENDSUDO'
# 创建 Nginx 配置
cat > /tmp/nginx_config.txt << 'NGINX_EOF'
server {
    listen 80;
    server_name DOMAIN_PLACEHOLDER;

    location / {
        root /var/www/html/minimal-chat;
        index index.html;
        try_files \$uri \$uri/ /index.html;
    }

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

    location /register {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    location /token {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }

    location /api {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
    }
}
NGINX_EOF

# 替换域名
sed -i "s/DOMAIN_PLACEHOLDER/$DOMAIN/g" /tmp/nginx_config.txt

# 复制到 Nginx 配置目录
cp /tmp/nginx_config.txt $NGINX_CONFIG_PATH

# 测试 Nginx 配置
nginx -t

# 如果测试通过，重启 Nginx
if [ $? -eq 0 ]; then
    systemctl restart nginx
    echo "Nginx 配置成功并已重启"
else
    echo "Nginx 配置测试失败"
    exit 1
fi
ENDSUDO
ENDSSH
echo "✓ Nginx 配置完成"

# 5. 重启后端服务
echo ""
echo "步骤 5: 重启后端服务..."
plink -i e:\fang.ppk $SERVER_USER@$SERVER_IP "sudo systemctl restart $SERVICE_NAME"
echo "✓ 后端服务重启完成"

# 6. 检查服务状态
echo ""
echo "步骤 6: 检查服务状态..."
plink -i e:\fang.ppk $SERVER_USER@$SERVER_IP << 'ENDSSH'
echo ""
echo "=== Nginx 状态 ==="
sudo systemctl status nginx | head -5
echo ""
echo "=== Minimal Chat 状态 ==="
sudo systemctl status minimal-chat | head -5
ENDSSH

# 7. 完成
echo ""
echo "========================================="
echo "部署完成！"
echo "========================================="
echo ""
echo "访问地址: http://$DOMAIN/"
echo ""
echo "如果遇到问题，请检查："
echo "1. Nginx 日志: sudo tail -f /var/log/nginx/error.log"
echo "2. 应用日志: sudo journalctl -u minimal-chat -f"
echo "3. 服务状态: sudo systemctl status minimal-chat"
