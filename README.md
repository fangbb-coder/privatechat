# Private Chat v3.6.0 - 安全增强版加密聊天系统

## 🆕 v3.6.0 更新 (2025-12-30)

### 新增功能
- ✅ **管理员删除用户功能**：管理员可以删除用户账户（不能删除自己）
- ✅ **移动端键盘优化**：发送消息后键盘不收起，输入框保持焦点
- ✅ **在线用户数显示修复**：正确显示在线用户数量
- ✅ **RSA 加密登录**：登录密码使用 RSA-2048 加密传输，防止明文泄露

### 安全增强
- ✅ **RSA-2048 密钥交换**：登录密码使用非对称加密传输
- ✅ **PKCS#1 v1.5 兼容**：支持 JSEncrypt 前端库加密格式
- ✅ **密码传输加密**：网络抓包无法获取明文密码
- ✅ **修复密码存储问题**：bcrypt 哈希不再二次加密

### Bug 修复
- ✅ **修复新用户无法登录问题**：兼容旧数据（管理员密码哈希被加密）和新数据（新用户密码哈希未加密）
- ✅ **修复密码修改后无法登录问题**：多进程环境下缓存不一致问题已解决
- ✅ **优化密码修改提示**：
  - 新密码与现用密码相同时提示："新密码不能与现用密码相同"
  - 新密码与历史密码重复时提示："不建议使用旧密码"

### 全面安全升级
- ✅ **修复裸露的 except 语句**：所有异常捕获都使用具体异常类型
- ✅ **严格 CORS 配置**：默认禁止跨域请求，需明确配置允许的域名
- ✅ **AES-256-CBC 加密**：前后端统一使用 AES-256-CBC 模式，与 CryptoJS 完全兼容
- ✅ **修复内存泄漏**：速率限制器添加定期清理机制，防止无限增长
- ✅ **安全 HTTP 头**：添加 X-Frame-Options、CSP、HSTS 等安全响应头
- ✅ **密码历史检查**：防止用户重复使用最近的密码（默认记录5个）
- ✅ **Refresh Token 机制**：支持 token 刷新，延长会话时长（默认7天）
- ✅ **会话固定保护**：限制每用户最大活跃会话数（默认5个）
- ✅ **消除魔术数字**：所有硬编码常量移至配置文件
- ✅ **输入验证增强**：添加更严格的输入验证规则
- ✅ **数据库查询优化**：添加用户信息缓存，提升查询性能
- ✅ **日志掩码工具**：敏感信息在日志中自动掩码
- ✅ **配置验证**：启动时验证配置参数的合法性
- ✅ **修复 Logger 导入问题**：修复 encryption.py 中 logger 未定义的错误
- ✅ **WebSocket 连接修复**：修复 WebSocket 连接后立即断开的问题

### 新增 API
- ✅ **DELETE /api/admin/user/{username}**：删除用户（管理员）
- ✅ **POST /api/auth/refresh**：刷新 access token
- ✅ **密码历史表**：记录用户密码变更历史
- ✅ **Refresh Token 表**：管理长期有效的 refresh tokens

### 配置项新增
- ✅ `PASSWORD_HISTORY_COUNT`：密码历史记录数（默认：5）
- ✅ `REFRESH_TOKEN_EXPIRE_DAYS`：refresh token 有效期（默认：7天）
- ✅ `MAX_ACTIVE_SESSIONS`：每用户最大活跃会话数（默认：5）
- ✅ `IP_LOCK_MINUTES`：IP 锁定时长（默认：30分钟）
- ✅ `IP_LOCK_THRESHOLD`：触发 IP 锁定的失败次数（默认：20次）
- ✅ `RATE_LIMIT_MAX_IPS`：速率限制器最大 IP 数量（默认：10000）

## ✨ 核心特性

### 1. 用户注册与登录
- ✨ 支持用户自行注册账户
- 默认用户名: `admin`
- 默认密码: `Admin@2025`
- 基于 JWT (JSON Web Token) 的安全认证
- Token 有效期: 30 分钟
- Refresh Token 有效期: 7 天
- 加密密钥持久化存储
- 支持自动刷新 token（无需频繁登录）

### 2. 密码强度验证
- 最小长度 8 个字符
- 必须包含大小写字母、数字、特殊字符
- 前端实时验证，后端二次验证
- 使用 bcrypt 哈希存储（安全升级）
- 密码历史检查（防止重复使用最近密码）
- 默认记录最近 5 个密码

### 3. 消息加密
- 所有聊天消息使用 **AES-256-CBC** 加密（兼容 CryptoJS）
- RSA-2048 密钥交换（密钥持久化）
- 用户可自定义加密密码
- 默认加密密码: `PrivateChat2025Secure!`
- 前端使用 CryptoJS 进行加密
- 后端使用 PyCryptodome 进行解密

### 4. 实时用户状态
- 显示用户连接/断开通知
- 在线用户列表（实时更新）
- 区分自己的消息和其他用户的消息
- 加密消息自动解密显示
- 消息已读状态显示
- 按时间顺序逐行显示消息，不重叠

### 5. 消息撤回
- 2 分钟内可撤回已发送消息
- 撤回消息显示为"已撤回"
- 仅对自己发送的消息可撤回

### 6. 表情符号支持
- 内置表情选择器
- 支持常用表情快捷输入
- 表情按钮位于输入框右侧
- 点击笑脸图标弹出表情选择器
- 智能边界检测，防止超出界面

### 7. 暗黑模式
- 支持暗黑/明亮主题切换
- 主题设置持久化保存
- 自动适应系统偏好

### 8. 安全增强
- 登录失败 5 次自动锁定 15 分钟
- IP 频率限制（登录 30 次/分钟，其他 60 次/分钟）
- WebSocket 自动重连
- 心跳保活机制
- 字段级加密（用户名和密码）
- Token 存储在 sessionStorage 中，每个标签页独立（防 XSS，支持多标签页登录）
- 页面刷新后自动恢复登录状态和聊天记录
- 关闭标签页自动清除登录状态和聊天记录
- WebSocket 连接频率限制（每分钟最多 20 个连接）
- Token 过期时间验证（区分过期、无效等错误）
- 管理员敏感操作二次确认（踢出/禁用用户需密码验证）
- **Refresh Token 机制**：支持长时间会话，减少登录次数
- **密码历史检查**：防止重复使用密码
- **会话固定保护**：限制每个用户的最大活跃会话数
- **安全 HTTP 头**：CSP、HSTS、X-Frame-Options 等
- **严格 CORS 配置**：默认禁止跨域，需明确配置允许域名

### 9. 管理员功能
- 系统公告发布
- 查看在线用户统计
- 查看消息统计
- 禁用/启用用户（禁用 = 踢出 + 不能登录）
- 踢出在线用户
- 不能操作自己（踢出/禁用）
- **删除用户**：管理员可以删除用户账户（不能删除自己）
- 被踢出/禁用后自动提示并退出

### 10. 日志系统
- 结构化日志（Loguru）
- 日志文件自动轮转
- 支持不同日志级别

### 11. 移动端优化
- 响应式设计
- 移动端自适应布局
- 触摸友好界面
- 输入框固定在底部
- 消息自动滚动到最新内容
- 消息过多时显示滚动条
- **键盘保持焦点**：发送消息后输入框自动重新聚焦，防止键盘收起
- **移动端优化属性**：添加 inputmode、autocomplete、autocorrect 等属性

## 🚀 快速开始

### 安装依赖

```bash
cd backend
pip install -r requirements.txt
```

### 启动服务

**Windows:**
```bash
cd e:/minimal-chat
python backend/main.py
```

**Linux/Mac:**
```bash
cd /path/to/minimal-chat
python3 backend/main.py
```

### 访问应用
打开浏览器访问: http://localhost:8080

### 注册新用户
1. 点击"立即注册"链接
2. 填写注册信息：
   - 用户名: 3-20个字符（字母、数字、下划线）
   - 密码: 8-64个字符，必须包含大小写字母、数字、特殊字符
   - 确认密码: 必须与密码一致
3. 点击"注册"按钮
4. 注册成功后自动跳转到登录页

### 登录
- 已有账户: `admin` / `Admin@2025`
- 加密密码（可选）：留空使用默认密码 `PrivateChat2025Secure!`
- ⚠️ **重要**: 多用户聊天时，必须使用相同的加密密码才能看到彼此的消息
- ✅ **Session Storage 登录**:
  - 每个浏览器标签页独立存储登录状态
  - 支持多个标签页同时登录不同账户
  - 刷新页面自动恢复登录状态
  - 刷新页面后自动恢复聊天记录
  - 关闭标签页自动清除登录状态和聊天记录
  - 标签页之间完全隔离，互不影响
  - 聊天记录最多保存 500 条消息（sessionStorage 限制）

## 🔐 安全特性

### 已实现的安全措施

#### 1. 认证安全
- ✅ JWT Token 认证，30分钟自动过期
- ✅ Refresh Token 支持，7天有效期
- ✅ Token 存储在 sessionStorage 中（每个标签页独立，防 XSS 攻击）
- ✅ 支持多标签页同时登录不同账户
- ✅ 页面刷新后自动恢复登录状态
- ✅ 关闭标签页自动清除登录状态
- ✅ 密码使用 bcrypt 哈希存储（不可逆加密）
- ✅ 数据库字段级加密（用户名和密码）
- ✅ 登录失败 5 次自动锁定 15 分钟
- ✅ 密码历史检查（防止复用）
- ✅ 会话固定保护（限制活跃会话数）

#### 2. 传输安全
- ✅ **RSA-2048 登录密码加密**：登录密码使用非对称加密传输，防止明文泄露
- ✅ AES-256-CBC 消息加密
- ✅ RSA-2048 密钥交换
- ✅ WebSocket 连接时验证 Token
- ✅ Token 过期时间实时验证
- ✅ WebSocket 连接频率限制（每 IP 每分钟最多 20 个连接）

#### 3. 操作安全
- ✅ 管理员敏感操作二次确认
  - 踢出用户需要输入管理员密码
  - 禁用用户需要输入管理员密码
  - 删除用户需要二次确认
  - 不能删除自己
- ✅ IP 频率限制（登录 30 次/分钟，其他 60 次/分钟）
- ✅ 用户禁用 = 踢出 + 禁止登录

#### 4. 隐私保护
- ✅ 聊天消息不持久化到数据库
- ✅ 所有用户断开连接后自动清除消息
- ✅ 新用户加入看不到历史消息
- ✅ 仅在线用户能收到消息

## 📝 API 文档

### POST /register
用户注册

**请求参数:**
```json
{
  "username": "newuser",
  "password": "Password123!"
}
```

**响应:**
```json
{
  "username": "newuser",
  "message": "用户 'newuser' 注册成功"
}
```

### POST /token
用户登录，获取 JWT token

**请求参数（推荐使用加密密码）:**
```json
{
  "username": "admin",
  "encrypted_password": "RSA加密后的密码"
}
```

**响应:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "username": "admin"
}
```

### GET /api/public-key
获取 RSA 公钥（用于加密登录密码）

**响应:**
```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",
  "key_size": 2048
}
```

### POST /api/auth/refresh
刷新 access token（使用 refresh token）

**请求参数:**
```json
{
  "refresh_token": "eyJhbGciOiJIUzI1NiIs..."
}
```

### DELETE /api/admin/user/{username}
删除用户（管理员）

**请求头:**
```
Authorization: Bearer <access_token>
```

**功能:**
- 删除用户账户
- 不能删除自己
- 删除后自动刷新用户列表
- 被删除用户在线时自动踢出

### WebSocket /ws
实时聊天端点

**初始消息（认证）:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "encryption_key": "your-encryption-password"
}
```

## 🛠️ 技术栈

### 后端
- FastAPI - Web 框架
- WebSocket - 实时通信
- PyJWT - JWT 认证
- bcrypt - 密码哈希
- PyCryptodome - AES-256-CBC + RSA-2048 加密
- SQLite - 数据持久化（字段级加密）
- Pydantic - 数据验证
- Pydantic-Settings - 配置管理
- Loguru - 日志系统
- SlowAPI - 速率限制

### 前端
- 原生 HTML/CSS/JavaScript
- CryptoJS - 前端加密
- JSEncrypt - RSA 加密
- WebSocket - 实时通信
- Flexbox - 响应式布局
- SessionStorage - 会话管理（支持多标签页独立登录）

## 📂 项目结构
```
e:/minimal-chat/
├── backend/
│   ├── main.py              # 后端主程序
│   ├── requirements.txt     # Python 依赖
│   ├── .env.example         # 配置文件模板
│   ├── models/             # 数据模型
│   │   ├── __init__.py
│   │   └── user.py
│   └── utils/              # 工具模块
│       ├── __init__.py
│       ├── encryption.py    # 加密工具
│       ├── security.py       # 安全工具
│       └── log_masking.py  # 日志掩码
├── frontend/
│   └── index.html          # 前端页面
└── README.md            # 本文档
```

## 🔧 配置

### 修改配置
编辑 `backend/.env` 文件：

```bash
# JWT 密钥（必须修改）
SECRET_KEY=your-random-secret-key-change-this

# 管理员用户名
ADMIN_USERNAMES=admin

# 密码策略
MIN_PASSWORD_LENGTH=8
MAX_PASSWORD_LENGTH=64
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGITS=true
PASSWORD_REQUIRE_SPECIAL=true

# 登录安全
MAX_LOGIN_ATTEMPTS=5
LOGIN_LOCK_MINUTES=15
RATE_LIMIT_PER_MINUTE=60

# Token 有效期
ACCESS_TOKEN_EXPIRE_MINUTES=30

# 消息撤回时间
MESSAGE_RECALL_MINUTES=2

# 日志级别
LOG_LEVEL=INFO
```

## 🌐 外网访问

推荐方式：
1. **FRP** - 需要公网服务器
2. **Cloudflare Tunnel** - 免费，零配置
3. **Ngrok** - 快速测试
4. **Lighthouse** - 腾讯云轻量应用服务器

## ⚠️ 注意事项

1. **生产环境必须更改默认密码**
2. 修改 `backend/.env` 中的 `SECRET_KEY` 为随机密钥
3. 使用 HTTPS 部署
4. 定期更新依赖包
5. 保护 `backend/keys/` 目录不被未授权访问
6. **多用户聊天**：必须使用相同的加密密码才能看到彼此的消息
7. **注册流程**：注册时只需填写用户名、密码、确认密码，加密密码仅在登录时设置（可选）

## 📄 许可证
MIT License
