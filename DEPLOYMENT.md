# Private Chat 部署指南

## 部署前检查清单

### 1. 代码检查
- [ ] 确认 `backend/main.py` 中的 `/token` 端点支持 JSON 和表单数据格式
- [ ] 确认 `backend/.env.example` 文件存在
- [ ] 确认 `frontend/index.html` 文件存在

### 2. 环境配置
- [ ] 创建 `backend/.env` 文件（从 `.env.example` 复制）
- [ ] 配置 `ALLOWED_ORIGINS` 为生产域名
- [ ] 配置 `WS_ALLOWED_ORIGINS` 为生产域名
- [ ] 配置 `ADMIN_USERNAMES` 为管理员用户名

### 3. 服务器准备
- [ ] 服务器已安装 Python 3.8+
- [ ] 服务器已安装 Nginx
- [ ] 服务器已安装 systemd
- [ ] 防火墙已开放 80 和 443 端口

## 部署步骤

### 方法一：使用自动化部署脚本（推荐）

#### Windows 用户
```powershell
# 1. 编辑 deploy.ps1 中的配置变量
# 2. 运行部署脚本
.\deploy.ps1
```

#### Linux/Mac 用户
```bash
# 1. 编辑 deploy.sh 中的配置变量
# 2. 运行部署脚本
chmod +x deploy.sh
./deploy.sh
```

### 方法二：手动部署

#### 1. 上传文件
```bash
# 上传后端文件
pscp -i your-key.ppk -r backend/* user@server:/root/minimal-chat/backend/

# 上传前端文件
pscp -i your-key.ppk frontend/index.html user@server:/var/www/html/minimal-chat/
```

#### 2. 配置环境变量
```bash
# 创建 .env 文件
cat > /root/minimal-chat/backend/.env << 'EOF'
ENVIRONMENT=production
ALLOWED_ORIGINS='["http://your-domain.com", "https://your-domain.com"]'
WS_ALLOWED_ORIGINS='["http://your-domain.com", "https://your-domain.com"]'
ADMIN_USERNAMES=admin
LOG_LEVEL=INFO
EOF
```

#### 3. 配置 Nginx
```bash
# 创建 Nginx 配置
sudo tee /etc/nginx/sites-available/minimal-chat > /dev/null << 'EOF'
server {
    listen 80;
    server_name your-domain.com;

    location / {
        root /var/www/html/minimal-chat;
        index index.html;
        try_files $uri $uri/ /index.html;
    }

    location /ws {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 86400;
    }

    location /register {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /token {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    location /api {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
EOF

# 启用配置
sudo ln -sf /etc/nginx/sites-available/minimal-chat /etc/nginx/sites-enabled/

# 测试配置
sudo nginx -t

# 重启 Nginx
sudo systemctl restart nginx
```

#### 4. 重启后端服务
```bash
sudo systemctl restart minimal-chat
```

## 部署后验证

### 1. 检查服务状态
```bash
# 检查 Nginx
sudo systemctl status nginx

# 检查后端服务
sudo systemctl status minimal-chat
```

### 2. 检查日志
```bash
# Nginx 错误日志
sudo tail -f /var/log/nginx/error.log

# Nginx 访问日志
sudo tail -f /var/log/nginx/access.log

# 应用日志
sudo journalctl -u minimal-chat -f
```

### 3. 测试 API
```bash
# 测试健康检查
curl http://your-domain.com/health

# 测试登录
curl -X POST http://your-domain.com/token \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"Test1234!"}'
```

### 4. 测试 WebSocket
```bash
# 使用 wscat 测试 WebSocket
wscat -c ws://your-domain.com/ws
```

## 常见问题

### 1. 登录失败：Unexpected end of JSON input
**原因**：后端 `/token` 端点不支持 JSON 格式
**解决**：确保 `backend/main.py` 中的登录函数支持 JSON 和表单数据格式

### 2. WebSocket 连接失败：403 Forbidden
**原因**：WebSocket Origin 验证失败
**解决**：在 `.env` 文件中配置 `WS_ALLOWED_ORIGINS`

### 3. CORS 错误
**原因**：CORS 配置不正确
**解决**：在 `.env` 文件中配置 `ALLOWED_ORIGINS`

### 4. Nginx 502 Bad Gateway
**原因**：后端服务未运行或端口不正确
**解决**：
```bash
# 检查后端服务状态
sudo systemctl status minimal-chat

# 检查端口是否监听
sudo netstat -tlnp | grep 8080
```

### 5. 前端无法加载
**原因**：Nginx 配置错误或文件权限问题
**解决**：
```bash
# 检查文件权限
sudo chown -R www-data:www-data /var/www/html/minimal-chat

# 检查 Nginx 配置
sudo nginx -t
```

## 安全建议

1. **使用 HTTPS**：在生产环境中配置 SSL 证书
2. **设置强密码**：管理员账户密码至少 8 位，包含大小写字母、数字和特殊字符
3. **限制访问**：配置防火墙规则，只允许必要的端口
4. **定期更新**：及时更新依赖包和系统
5. **备份**：定期备份数据库和配置文件

## 维护命令

### 查看在线用户
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://your-domain.com/api/online-users
```

### 查看统计信息
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" http://your-domain.com/api/stats
```

### 重启服务
```bash
# 重启 Nginx
sudo systemctl restart nginx

# 重启后端
sudo systemctl restart minimal-chat
```

### 查看日志
```bash
# 实时查看 Nginx 日志
sudo tail -f /var/log/nginx/access.log

# 实时查看应用日志
sudo journalctl -u minimal-chat -f
```
