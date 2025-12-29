# Private Chat 部署脚本 (Windows)
# 用于自动化部署到生产服务器

# 配置变量
$SERVER_USER = "ubuntu"
$SERVER_IP = "3.26.0.34"
$SERVER_PATH = "/root/minimal-chat"
$BACKEND_PATH = "$SERVER_PATH/backend"
$FRONTEND_PATH = "$SERVER_PATH/frontend"
$NGINX_CONFIG_PATH = "/etc/nginx/sites-available/minimal-chat"
$SERVICE_NAME = "minimal-chat"
$PUTTY_PATH = "C:\Program Files\PuTTY"
$KEY_PATH = "e:\fang.ppk"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Private Chat 部署脚本 (Windows)" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan

# 1. 检查本地文件
Write-Host ""
Write-Host "步骤 1: 检查本地文件..." -ForegroundColor Yellow
if (!(Test-Path "backend") -or !(Test-Path "frontend")) {
    Write-Host "错误: 找不到 backend 或 frontend 目录" -ForegroundColor Red
    exit 1
}
Write-Host "✓ 本地文件检查完成" -ForegroundColor Green

# 2. 创建 .env 文件（如果不存在）
Write-Host ""
Write-Host "步骤 2: 配置环境变量..." -ForegroundColor Yellow
if (!(Test-Path "backend\.env")) {
    Write-Host "创建 .env 文件..." -ForegroundColor Cyan
    
    $DOMAIN = Read-Host "请输入服务器域名 (例如: 3.26.0.34)"
    $ADMIN_USER = Read-Host "请输入管理员用户名 (默认: admin)"
    
    if ([string]::IsNullOrEmpty($DOMAIN)) {
        $DOMAIN = "3.26.0.34"
    }
    if ([string]::IsNullOrEmpty($ADMIN_USER)) {
        $ADMIN_USER = "admin"
    }
    
    $envContent = @"
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
"@
    
    Set-Content -Path "backend\.env" -Value $envContent -Encoding UTF8
    Write-Host "✓ .env 文件创建完成" -ForegroundColor Green
} else {
    Write-Host "✓ .env 文件已存在" -ForegroundColor Green
}

# 3. 上传文件到服务器
Write-Host ""
Write-Host "步骤 3: 上传文件到服务器..." -ForegroundColor Yellow

# 上传后端文件
Write-Host "上传后端文件..." -ForegroundColor Cyan
$backendFiles = Get-ChildItem -Path "backend\*" -File
foreach ($file in $backendFiles) {
    & "$PUTTY_PATH\pscp.exe" -i $KEY_PATH $file.FullName "$SERVER_USER@$SERVER_IP`:$BACKEND_PATH/"
}

# 上传前端文件
Write-Host "上传前端文件..." -ForegroundColor Cyan
& "$PUTTY_PATH\pscp.exe" -i $KEY_PATH "frontend\index.html" "$SERVER_USER@$SERVER_IP`:$FRONTEND_PATH/"

Write-Host "✓ 文件上传完成" -ForegroundColor Green

# 4. 配置 Nginx
Write-Host ""
Write-Host "步骤 4: 配置 Nginx..." -ForegroundColor Yellow

$DOMAIN = Read-Host "请输入服务器域名 (例如: 3.26.0.34)"
if ([string]::IsNullOrEmpty($DOMAIN)) {
    $DOMAIN = "3.26.0.34"
}

# 创建 Nginx 配置脚本
$nginxScript = @"
#!/bin/bash
# 创建 Nginx 配置
cat > /tmp/nginx_config.txt << 'NGINX_EOF'
server {
    listen 80;
    server_name $DOMAIN;

    location / {
        root /var/www/html/minimal-chat;
        index index.html;
        try_files \\\$uri \\\$uri/ /index.html;
    }

    location /ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \\\$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \\\$host;
        proxy_set_header X-Real-IP \\\$remote_addr;
        proxy_set_header X-Forwarded-For \\\$proxy_add_x_forwarded_for;
        proxy_read_timeout 86400;
    }

    location /register {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \\\$host;
        proxy_set_header X-Real-IP \\\$remote_addr;
    }

    location /token {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \\\$host;
        proxy_set_header X-Real-IP \\\$remote_addr;
    }

    location /api {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \\\$host;
        proxy_set_header X-Real-IP \\\$remote_addr;
    }
}
NGINX_EOF

# 复制到 Nginx 配置目录
sudo cp /tmp/nginx_config.txt $NGINX_CONFIG_PATH

# 测试 Nginx 配置
sudo nginx -t

# 如果测试通过，重启 Nginx
if [ \$? -eq 0 ]; then
    sudo systemctl restart nginx
    echo "Nginx 配置成功并已重启"
else
    echo "Nginx 配置测试失败"
    exit 1
fi
"@

Set-Content -Path "setup_nginx_remote.sh" -Value $nginxScript -Encoding UTF8
& "$PUTTY_PATH\pscp.exe" -i $KEY_PATH "setup_nginx_remote.sh" "$SERVER_USER@$SERVER_IP`:/tmp/"
& "$PUTTY_PATH\plink.exe" -i $KEY_PATH "$SERVER_USER@$SERVER_IP" "sudo bash /tmp/setup_nginx_remote.sh"

Write-Host "✓ Nginx 配置完成" -ForegroundColor Green

# 5. 重启后端服务
Write-Host ""
Write-Host "步骤 5: 重启后端服务..." -ForegroundColor Yellow
& "$PUTTY_PATH\plink.exe" -i $KEY_PATH "$SERVER_USER@$SERVER_IP" "sudo systemctl restart $SERVICE_NAME"
Write-Host "✓ 后端服务重启完成" -ForegroundColor Green

# 6. 检查服务状态
Write-Host ""
Write-Host "步骤 6: 检查服务状态..." -ForegroundColor Yellow
Write-Host ""
Write-Host "=== Nginx 状态 ===" -ForegroundColor Cyan
& "$PUTTY_PATH\plink.exe" -i $KEY_PATH "$SERVER_USER@$SERVER_IP" "sudo systemctl status nginx | head -5"
Write-Host ""
Write-Host "=== Minimal Chat 状态 ===" -ForegroundColor Cyan
& "$PUTTY_PATH\plink.exe" -i $KEY_PATH "$SERVER_USER@$SERVER_IP" "sudo systemctl status minimal-chat | head -5"

# 7. 完成
Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "部署完成！" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "访问地址: http://$DOMAIN/" -ForegroundColor Green
Write-Host ""
Write-Host "如果遇到问题，请检查：" -ForegroundColor Yellow
Write-Host "1. Nginx 日志: sudo tail -f /var/log/nginx/error.log" -ForegroundColor White
Write-Host "2. 应用日志: sudo journalctl -u minimal-chat -f" -ForegroundColor White
Write-Host "3. 服务状态: sudo systemctl status minimal-chat" -ForegroundColor White
