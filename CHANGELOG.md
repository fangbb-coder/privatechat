# 更新日志

## [v3.6.1] - 2025-12-29

### 修复
- 修复登录端点 `/token` 不支持 JSON 格式的问题
  - 原问题：登录端点只支持表单数据（`application/x-www-form-urlencoded`），但前端发送的是 JSON 格式（`application/json`）
  - 修复方案：修改登录函数以支持 JSON 和表单数据两种格式
  - 影响：修复了登录时出现 "Unexpected end of JSON input" 错误的问题

### 改进
- 添加 `.env.example` 文件作为环境配置模板
- 添加自动化部署脚本（`deploy.sh` 和 `deploy.ps1`）
- 添加详细的部署文档（`DEPLOYMENT.md`）
- 添加部署检查清单（`DEPLOYMENT_CHECKLIST.md`）

### 部署改进
- 改进 Nginx 配置，添加 `/register` 和 `/token` 端点的代理配置
- 添加环境变量配置说明，确保生产环境正确配置 CORS 和 WebSocket 允许域名
- 添加服务状态检查和日志查看命令

## [v3.6.0] - 2025-01-27

### 新功能
- 密码强度检查
- 登录失败限制（IP 级别锁定）
- IP 频率限制
- WebSocket Origin 验证
- 消息加密密码强制设置
- CSP 防护 XSS 攻击
- JWT 密钥自动生成
- 错误消息优化（区分账户禁用、锁定、密码错误）
- 消息撤回功能
- 在线用户列表
- 管理员功能
- 日志系统
- 健康检查
- 监控指标

### 安全增强
- RSA 2048 位密钥加密
- AES-256-CBC 消息加密
- bcrypt 密码哈希
- JWT Token 认证
- CORS 配置
- WebSocket Origin 验证
- 登录失败限制（5 次失败后锁定 15 分钟）
- IP 频率限制
- CSP 安全头
- Referrer-Policy 安全头

### 技术栈
- 后端：FastAPI + Uvicorn + Gunicorn
- 前端：原生 JavaScript + HTML5 + CSS3
- 数据库：SQLite
- 加密：RSA + AES
- 认证：JWT
- 通信：WebSocket

## 已知问题

### v3.6.1
无已知问题

### v3.6.0
- 登录端点 `/token` 不支持 JSON 格式（已在 v3.6.1 修复）

## 未来计划

### v3.7.0
- [ ] 添加 HTTPS 支持
- [ ] 添加文件上传功能
- [ ] 添加群组聊天功能
- [ ] 添加消息搜索功能
- [ ] 添加消息转发功能
- [ ] 添加语音消息功能
- [ ] 添加视频通话功能
- [ ] 添加移动端适配
- [ ] 添加多语言支持
- [ ] 添加主题切换功能

### v3.8.0
- [ ] 添加端到端加密
- [ ] 添加消息已读回执
- [ ] 添加消息输入状态
- [ ] 添加消息撤回时间限制配置
- [ ] 添加消息编辑功能
- [ ] 添加消息回复功能
- [ ] 添加消息引用功能
- [ ] 添加消息表情包
- [ ] 添加消息贴图
- [ ] 添加消息语音转文字

## 贡献者

- [你的名字] - 主要开发者

## 许可证

MIT License

## 联系方式

- 项目主页：[GitHub 仓库地址]
- 问题反馈：[GitHub Issues]
- 邮箱：[联系邮箱]
