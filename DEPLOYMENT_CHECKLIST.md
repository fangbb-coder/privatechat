# Private Chat 部署检查清单

## 部署前检查

### 代码检查
- [ ] `backend/main.py` 中的 `/token` 端点支持 JSON 和表单数据格式
- [ ] `backend/.env.example` 文件存在且包含所有必要配置
- [ ] `frontend/index.html` 文件存在
- [ ] 所有依赖包已在 `requirements.txt` 中列出

### 环境配置
- [ ] 创建 `backend/.env` 文件（从 `.env.example` 复制）
- [ ] 配置 `ENVIRONMENT=production`
- [ ] 配置 `ALLOWED_ORIGINS` 为生产域名（包含 http 和 https）
- [ ] 配置 `WS_ALLOWED_ORIGINS` 为生产域名（包含 http 和 https）
- [ ] 配置 `ADMIN_USERNAMES` 为管理员用户名
- [ ] 配置 `LOG_LEVEL=INFO`（生产环境不建议使用 DEBUG）

### 服务器准备
- [ ] 服务器已安装 Python 3.8+
- [ ] 服务器已安装 Nginx
- [ ] 服务器已安装 systemd
- [ ] 防火墙已开放 80 端口（HTTP）
- [ ] 防火墙已开放 443 端口（HTTPS）
- [ ] SSH 密钥已配置
- [ ] 服务器时间已同步（使用 NTP）

## 部署步骤

### 1. 上传文件
- [ ] 上传后端文件到 `/root/minimal-chat/backend/`
- [ ] 上传前端文件到 `/var/www/html/minimal-chat/`
- [ ] 设置正确的文件权限（`www-data:www-data`）

### 2. 配置 Nginx
- [ ] 创建 Nginx 配置文件 `/etc/nginx/sites-available/minimal-chat`
- [ ] 配置 `location /` 指向前端静态文件
- [ ] 配置 `location /ws` 指向 WebSocket（包含必要的 proxy headers）
- [ ] 配置 `location /register` 指向后端 API
- [ ] 配置 `location /token` 指向后端 API
- [ ] 配置 `location /api` 指向后端 API
- [ ] 测试 Nginx 配置（`nginx -t`）
- [ ] 启用 Nginx 配置（创建符号链接）
- [ ] 重启 Nginx 服务

### 3. 配置后端服务
- [ ] 创建 systemd 服务文件 `/etc/systemd/system/minimal-chat.service`
- [ ] 配置服务自动启动（`enabled`）
- [ ] 配置虚拟环境路径
- [ ] 配置工作目录
- [ ] 配置用户和组
- [ ] 重载 systemd 配置（`systemctl daemon-reload`）
- [ ] 启动服务（`systemctl start minimal-chat`）
- [ ] 设置服务开机自启（`systemctl enable minimal-chat`）

### 4. 验证部署
- [ ] 检查 Nginx 服务状态（`systemctl status nginx`）
- [ ] 检查后端服务状态（`systemctl status minimal-chat`）
- [ ] 检查 Nginx 错误日志（无错误）
- [ ] 检查后端应用日志（无错误）
- [ ] 测试前端页面访问（HTTP 200）
- [ ] 测试健康检查端点（`/health`）
- [ ] 测试用户注册功能
- [ ] 测试用户登录功能
- [ ] 测试 WebSocket 连接
- [ ] 测试管理员功能

## 部署后验证

### 功能测试
- [ ] 用户注册成功
- [ ] 用户登录成功（返回 access_token 和 refresh_token）
- [ ] WebSocket 连接成功（状态码 101）
- [ ] 发送消息成功
- [ ] 接收消息成功
- [ ] 消息加密正常
- [ ] 消息撤回功能正常
- [ ] 在线用户列表正常
- [ ] 管理员功能正常

### 性能测试
- [ ] 页面加载时间 < 2 秒
- [ ] API 响应时间 < 500ms
- [ ] WebSocket 连接建立时间 < 1 秒
- [ ] 并发用户测试通过

### 安全测试
- [ ] CORS 配置正确（只允许指定域名）
- [ ] WebSocket Origin 验证正常
- [ ] 登录失败限制正常
- [ ] IP 频率限制正常
- [ ] 密码强度检查正常
- [ ] JWT Token 验证正常
- [ ] HTTPS 证书有效（如果使用 HTTPS）

## 常见问题排查

### 登录失败：Unexpected end of JSON input
**症状**：登录时返回 JSON 解析错误
**原因**：后端 `/token` 端点不支持 JSON 格式
**检查**：
- [ ] 确认 `backend/main.py` 中的登录函数支持 JSON 格式
- [ ] 确认前端发送的是 `application/json` 格式
**解决**：修改登录函数以支持 JSON 和表单数据格式

### WebSocket 连接失败：403 Forbidden
**症状**：WebSocket 连接被拒绝
**原因**：WebSocket Origin 验证失败
**检查**：
- [ ] 确认 `.env` 文件中配置了 `WS_ALLOWED_ORIGINS`
- [ ] 确认域名格式正确（包含协议和端口）
- [ ] 确认 Nginx 配置正确传递了 `Host` 和 `Origin` 头
**解决**：在 `.env` 文件中配置正确的 `WS_ALLOWED_ORIGINS`

### CORS 错误
**症状**：浏览器控制台显示 CORS 错误
**原因**：CORS 配置不正确
**检查**：
- [ ] 确认 `.env` 文件中配置了 `ALLOWED_ORIGINS`
- [ ] 确认域名格式正确
- [ ] 确认后端服务已重启
**解决**：在 `.env` 文件中配置正确的 `ALLOWED_ORIGINS`

### Nginx 502 Bad Gateway
**症状**：访问 API 时返回 502 错误
**原因**：后端服务未运行或端口不正确
**检查**：
- [ ] 确认后端服务正在运行（`systemctl status minimal-chat`）
- [ ] 确认后端服务监听在 127.0.0.1:8080
- [ ] 确认 Nginx 配置中的 proxy_pass 地址正确
**解决**：启动后端服务或修正配置

### 前端无法加载
**症状**：访问主页时显示 404 或 403
**原因**：Nginx 配置错误或文件权限问题
**检查**：
- [ ] 确认前端文件存在于 `/var/www/html/minimal-chat/`
- [ ] 确认文件权限正确（`www-data:www-data`）
- [ ] 确认 Nginx 配置中的 root 路径正确
**解决**：修正文件权限或 Nginx 配置

## 维护检查

### 日常维护
- [ ] 每日检查服务状态
- [ ] 每日检查错误日志
- [ ] 每日检查磁盘空间
- [ ] 每日检查内存使用

### 每周维护
- [ ] 每周备份数据库
- [ ] 每周检查安全更新
- [ ] 每周检查访问日志异常

### 每月维护
- [ ] 每月更新依赖包
- [ ] 每月检查 SSL 证书有效期
- [ ] 每月清理旧日志文件
- [ ] 每月检查用户账户

## 回滚计划

### 如果部署失败
1. 停止新服务
2. 恢复之前的代码版本
3. 恢复之前的配置文件
4. 重启服务
5. 验证功能正常

### 回滚命令
```bash
# 停止服务
sudo systemctl stop minimal-chat

# 恢复代码
cd /root/minimal-chat
git checkout previous_version

# 恢复配置
sudo cp /etc/nginx/sites-available/minimal-chat.backup /etc/nginx/sites-available/minimal-chat

# 重启服务
sudo systemctl start minimal-chat
sudo systemctl restart nginx
```

## 联系信息

### 技术支持
- 项目文档：[README.md](README.md)
- 部署文档：[DEPLOYMENT.md](DEPLOYMENT.md)
- 问题反馈：GitHub Issues

### 紧急联系
- 服务器管理员：[管理员邮箱]
- 开发团队：[开发团队邮箱]
