# Private Chat 部署修复说明

## 问题总结

在部署到生产服务器时，发现了以下关键问题：

### 1. 登录端点数据格式不匹配 ⚠️
**问题描述**：
- 后端 `/token` 端点只支持表单数据格式（`application/x-www-form-urlencoded`）
- 前端发送的是 JSON 格式（`application/json`）
- 导致登录时出现 "Unexpected end of JSON input" 错误

**影响**：
- 用户无法登录
- WebSocket 无法连接
- 整个应用无法使用

**修复方案**：
修改 `backend/main.py` 中的登录函数，使其同时支持 JSON 和表单数据两种格式：

```python
@app.post("/token", response_model=TokenResponse)
@limiter.limit("30/minute")
async def login(request: Request):
    # 根据请求头解析数据
    content_type = request.headers.get("content-type", "")
    
    if "application/json" in content_type:
        # JSON 格式
        body = await request.json()
        username = body.get("username", "")
        password = body.get("password", "")
    else:
        # 表单数据格式
        form_data = await request.form()
        username = form_data.get("username", "")
        password = form_data.get("password", "")
```

### 2. 缺少生产环境配置 ⚠️
**问题描述**：
- 服务器上没有 `.env` 文件
- CORS 和 WebSocket 允许域名未配置
- 导致跨域请求和 WebSocket 连接被拒绝

**影响**：
- CORS 错误
- WebSocket 连接失败（403 Forbidden）
- 无法从浏览器访问 API

**修复方案**：
创建 `.env` 文件并配置必要的环境变量：

```bash
ENVIRONMENT=production
ALLOWED_ORIGINS='["http://3.26.0.34", "https://3.26.0.34"]'
WS_ALLOWED_ORIGINS='["http://3.26.0.34", "https://3.26.0.34"]'
ADMIN_USERNAMES=admin
LOG_LEVEL=INFO
```

### 3. Nginx 配置不完整 ⚠️
**问题描述**：
- Nginx 配置缺少 `/register` 和 `/token` 端点的代理配置
- 导致这些 API 端点无法通过 Nginx 访问

**影响**：
- 用户注册功能不可用
- 用户登录功能不可用

**修复方案**：
在 Nginx 配置中添加必要的端点代理：

```nginx
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
```

## 修复后的改进

### 1. 代码改进
- ✅ 登录端点支持 JSON 和表单数据两种格式
- ✅ 添加 `.env.example` 模板文件
- ✅ 改进错误处理和验证

### 2. 部署改进
- ✅ 创建自动化部署脚本（`deploy.sh` 和 `deploy.ps1`）
- ✅ 添加详细的部署文档（`DEPLOYMENT.md`）
- ✅ 添加部署检查清单（`DEPLOYMENT_CHECKLIST.md`）
- ✅ 添加更新日志（`CHANGELOG.md`）

### 3. 文档改进
- ✅ 完整的部署指南
- ✅ 常见问题排查
- ✅ 维护命令说明
- ✅ 安全建议

## 部署流程

### 快速部署（推荐）

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

### 手动部署

1. **上传文件**
   ```bash
   # 上传后端文件
   pscp -i key.ppk -r backend/* user@server:/root/minimal-chat/backend/
   
   # 上传前端文件
   pscp -i key.ppk frontend/index.html user@server:/var/www/html/minimal-chat/
   ```

2. **配置环境变量**
   ```bash
   # 从 .env.example 创建 .env 文件
   cp backend/.env.example backend/.env
   
   # 编辑 .env 文件，配置生产域名
   vim backend/.env
   ```

3. **配置 Nginx**
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
   
   # 测试并重启 Nginx
   sudo nginx -t && sudo systemctl restart nginx
   ```

4. **重启后端服务**
   ```bash
   sudo systemctl restart minimal-chat
   ```

## 验证部署

### 1. 检查服务状态
```bash
# 检查 Nginx
sudo systemctl status nginx

# 检查后端服务
sudo systemctl status minimal-chat
```

### 2. 测试 API
```bash
# 测试健康检查
curl http://your-domain.com/health

# 测试登录（JSON 格式）
curl -X POST http://your-domain.com/token \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"Test1234!"}'
```

### 3. 测试 WebSocket
```bash
# 使用 wscat 测试 WebSocket
wscat -c ws://your-domain.com/ws
```

### 4. 浏览器测试
- 访问 http://your-domain.com/
- 注册新用户
- 登录
- 发送消息
- 测试管理员功能

## 常见问题

### Q1: 登录失败：Unexpected end of JSON input
**A**: 确保后端 `main.py` 中的登录函数支持 JSON 格式。参考本文档的"修复方案 1"。

### Q2: WebSocket 连接失败：403 Forbidden
**A**: 在 `.env` 文件中配置 `WS_ALLOWED_ORIGINS`，包含您的域名。

### Q3: CORS 错误
**A**: 在 `.env` 文件中配置 `ALLOWED_ORIGINS`，包含您的域名。

### Q4: Nginx 502 Bad Gateway
**A**: 检查后端服务是否运行，端口是否正确。

```bash
sudo systemctl status minimal-chat
sudo netstat -tlnp | grep 8080
```

### Q5: 前端无法加载
**A**: 检查文件权限和 Nginx 配置。

```bash
sudo chown -R www-data:www-data /var/www/html/minimal-chat
sudo nginx -t
```

## 安全建议

1. **使用 HTTPS**：在生产环境中配置 SSL 证书
2. **设置强密码**：管理员账户密码至少 8 位，包含大小写字母、数字和特殊字符
3. **限制访问**：配置防火墙规则，只允许必要的端口
4. **定期更新**：及时更新依赖包和系统
5. **备份数据**：定期备份数据库和配置文件
6. **监控日志**：定期检查错误日志和访问日志

## 维护命令

### 查看日志
```bash
# Nginx 错误日志
sudo tail -f /var/log/nginx/error.log

# Nginx 访问日志
sudo tail -f /var/log/nginx/access.log

# 应用日志
sudo journalctl -u minimal-chat -f
```

### 重启服务
```bash
# 重启 Nginx
sudo systemctl restart nginx

# 重启后端
sudo systemctl restart minimal-chat
```

### 查看在线用户
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://your-domain.com/api/online-users
```

### 查看统计信息
```bash
curl -H "Authorization: Bearer YOUR_TOKEN" \
  http://your-domain.com/api/stats
```

## 总结

通过这次部署经验，我们：

1. ✅ 修复了登录端点的数据格式问题
2. ✅ 添加了生产环境配置支持
3. ✅ 完善了 Nginx 配置
4. ✅ 创建了自动化部署脚本
5. ✅ 添加了详细的部署文档
6. ✅ 添加了部署检查清单

现在，下次部署将会更加顺利和可靠！

## 相关文档

- [部署指南](DEPLOYMENT.md)
- [部署检查清单](DEPLOYMENT_CHECKLIST.md)
- [更新日志](CHANGELOG.md)
- [项目 README](README.md)

## 联系方式

如有问题，请通过以下方式联系：

- GitHub Issues: [项目 Issues 地址]
- 邮箱: [联系邮箱]
