# Private Chat v3.4 - 安全加密聊天系统

## ✨ 核心特性

### 1. 用户注册与登录
- ✨ 支持用户自行注册账户
- 默认用户名: `admin`
- 默认密码: `Admin@2025`
- 基于 JWT (JSON Web Token) 的安全认证
- Token 有效期: 30 分钟
- 加密密钥持久化存储

### 2. 密码强度验证
- 最小长度 8 个字符
- 必须包含大小写字母、数字、特殊字符
- 前端实时验证，后端二次验证
- 使用 bcrypt 哈希存储（安全升级）

### 3. 消息加密
- 所有聊天消息使用 **AES-256-GCM** 加密
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
- IP 频率限制（每分钟 60 次）
- WebSocket 自动重连
- 心跳保活机制
- 字段级加密（用户名和密码）
- Token 存储在 sessionStorage 中，每个标签页独立（防 XSS，支持多标签页登录）
- 页面刷新后自动恢复登录状态和聊天记录
- 关闭标签页自动清除登录状态和聊天记录
- WebSocket 连接频率限制（每分钟最多 20 个连接）
- Token 过期时间验证（区分过期、无效等错误）
- 管理员敏感操作二次确认（踢出/禁用用户需密码验证）

### 9. 管理员功能
- 系统公告发布
- 查看在线用户统计
- 查看消息统计
- 禁用/启用用户（禁用 = 踢出 + 不能登录）
- 踢出在线用户
- 不能操作自己（踢出/禁用）
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
.\start.bat
```

**Linux/Mac:**
```bash
cd /path/to/minimal-chat
chmod +x deploy.sh
./deploy.sh
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
- 加密密码（可选）: 留空使用默认密码 `PrivateChat2025Secure!`
- ⚠️ **重要**: 多用户聊天时，必须使用相同的加密密码才能看到彼此的消息
- ✅ **Session Storage 登录**:
  - 每个浏览器标签页独立存储登录状态
  - 支持多个标签页同时登录不同账户
  - 刷新页面自动恢复登录状态
  - 刷新页面后自动恢复聊天记录
  - 关闭标签页自动清除登录状态

## 🔐 安全特性

### 已实现的安全措施

#### 1. 认证安全
- ✅ JWT Token 认证，30分钟自动过期
- ✅ Token 存储在 sessionStorage 中（每个标签页独立，防 XSS 攻击）
- ✅ 支持多标签页同时登录不同账户
- ✅ 页面刷新后自动恢复登录状态
- ✅ 关闭标签页自动清除登录状态
- ✅ 密码使用 bcrypt 哈希存储（不可逆加密）
- ✅ 数据库字段级加密（用户名和密码）
- ✅ 登录失败 5 次自动锁定 15 分钟

#### 2. 传输安全
- ✅ AES-256-GCM 消息加密
- ✅ RSA-2048 密钥交换
- ✅ WebSocket 连接时验证 Token
- ✅ Token 过期时间实时验证
- ✅ WebSocket 连接频率限制（每 IP 每分钟最多 5 个连接）

#### 3. 操作安全
- ✅ 管理员敏感操作二次确认
  - 踢出用户需要输入管理员密码
  - 禁用用户需要输入管理员密码
- ✅ IP 频率限制（每分钟最多 60 次请求）
- ✅ 用户禁用 = 踢出 + 禁止登录

#### 4. 隐私保护
- ✅ 聊天消息不持久化到数据库
- ✅ 所有用户断开连接后自动清除消息
- ✅ 新用户加入看不到历史消息
- ✅ 仅在线用户能收到消息

### 认证流程

### 认证流程
1. 用户输入用户名和密码
2. 密码使用 bcrypt 哈希验证
3. 登录失败次数限制（5次）
4. 验证成功返回 JWT token
5. WebSocket 连接时发送 token 进行认证
6. 只有认证用户才能加入聊天
7. 页面刷新时自动验证 token 有效性

### 消息加密流程
1. 前端使用 AES-256-GCM 加密消息
2. RSA-2048 密钥交换保护会话密钥
3. 加密后的消息通过 WebSocket 发送
4. 后端解密并重新加密（使用 RSA 保护会话密钥）
5. 前端解密并显示

### 高级加密特性
- **多重防护**：RSA-2048 + AES-256-GCM + bcrypt
- **密钥持久化**：RSA 密钥存储在 `backend/keys/` 目录
- **字段级加密**：用户名和密码在数据库中加密存储
- **认证加密**：GCM模式提供完整性和保密性
- **防暴力破解**：登录失败限制和 IP 频率限制
- **自动重连**：WebSocket 断线自动重连

### 隐私保护
- **消息不持久化**：聊天消息仅存储在内存中，不保存到数据库或文件
- **自动清除**：所有用户断开连接后，聊天记录自动从内存清除
- **无历史记录**：新用户加入时看不到之前的聊天内容
- **临时性**：消息仅在发送时存在，服务器不保留任何聊天历史

### 安全建议
1. **生产环境必须更改默认密码**
2. 修改 `backend/.env` 中的 `SECRET_KEY` 为随机密钥
3. 使用 HTTPS 部署
4. 定期更新依赖包
5. 保护 `backend/keys/` 目录不被未授权访问

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

**验证规则:**
- 用户名: 3-20 个字符，只能包含字母、数字和下划线
- 密码: 8-64 个字符，必须包含大小写字母、数字、特殊字符
- 用户名不能重复

### POST /token
用户登录，获取 JWT token

**请求参数:**
```json
{
  "username": "admin",
  "password": "Admin@2025"
}
```

**响应:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "username": "admin"
}
```

### POST /api/user/change-password
修改用户密码

**请求头:**
```
Authorization: Bearer <access_token>
```

**请求参数:**
```json
{
  "old_password": "OldPass123!",
  "new_password": "NewPass456!"
}
```

### GET /api/admin/users
获取用户列表（管理员）

**请求头:**
```
Authorization: Bearer <access_token>
```

**响应:**
```json
{
  "users": [
    {
      "username": "admin",
      "is_admin": true,
      "is_disabled": false,
      "created_at": "2025-01-01T00:00:00"
    }
  ]
}
```

### POST /api/admin/disable-user/{username}
禁用用户（管理员）

**请求头:**
```
Authorization: Bearer <access_token>
```

**功能:**
- 禁用用户会踢出在线用户
- 被禁用用户无法再次登录
- 不能禁用自己

### POST /api/admin/enable-user/{username}
启用用户（管理员）

**请求头:**
```
Authorization: Bearer <access_token>
```

### POST /api/admin/kick/{username}
踢出在线用户（管理员）

**请求头:**
```
Authorization: Bearer <access_token>
```

**功能:**
- 踢出在线用户
- 被踢出用户收到提示并自动退出
- 不能踢出自己

### POST /api/admin/announcement
发送系统公告（管理员）

**请求头:**
```
Authorization: Bearer <access_token>
```

**请求参数:**
```json
{
  "message": "系统维护通知"
}
```

### WebSocket /ws
实时聊天端点

**初始消息（认证）:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "encryption_key": "your-encryption-password"
}
```

**消息类型:**
- `connected`: 连接成功
- `message`: 聊天消息
- `announcement`: 系统公告
- `system`: 系统通知
- `online_users`: 在线用户列表
- `error`: 错误信息
- `recall`: 消息撤回

**错误处理:**
- 被踢出/禁用: 连接断开并显示原因
- Token 无效: 自动退出登录
- 网络断开: 自动重连（最多5次）

## 🛠️ 技术栈

## 🛠️ 技术栈

### 后端
- FastAPI - Web 框架
- WebSocket - 实时通信
- PyJWT - JWT 认证
- bcrypt - 密码哈希
- PyCryptodome - AES-256 + RSA-2048 加密
- SQLite - 数据持久化（字段级加密）
- Pydantic - 数据验证
- Pydantic-Settings - 配置管理
- Loguru - 日志系统
- SlowAPI - 速率限制

### 前端
- 原生 HTML/CSS/JavaScript
- CryptoJS - 前端加密
- WebSocket - 实时通信
- Flexbox - 响应式布局
- SessionStorage - 会话管理（支持多标签页独立登录）

## 📂 项目结构
```
e:/minimal-chat/
├── backend/
│   ├── main.py              # 后端主程序
│   ├── config.py            # 配置管理
│   ├── logger.py            # 日志配置
│   ├── requirements.txt     # Python 依赖
│   ├── .env.example         # 配置文件模板
│   ├── .env                # 配置文件（运行时生成）
│   ├── data/               # SQLite 数据库
│   ├── keys/               # 加密密钥存储
│   ├── logs/               # 日志文件
│   ├── models/             # 数据模型
│   │   ├── __init__.py
│   │   └── user.py
│   └── utils/              # 工具模块
│       ├── __init__.py
│       ├── encryption.py    # 加密工具
│       └── security.py       # 安全工具
├── frontend/
│   └── index.html          # 前端页面
├── frp/                  # 内外网穿透配置
├── docker/               # Docker 部署配置
├── start.bat             # Windows 启动脚本
├── deploy.sh             # Linux/Mac 部署脚本
├── stop.bat             # Windows 停止脚本
├── minimal-chat.service.template  # systemd 服务模板
├── nginx.conf.template          # Nginx 配置模板
├── README.md            # 本文档
└── DEPLOY.md            # 部署详细文档
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

详细部署指南请参考 [DEPLOY.md](DEPLOY.md)。

## ⚠️ 注意事项

1. **Session Storage 登录管理**：
   - Token 存储在 sessionStorage 中，每个标签页独立
   - ✅ 支持多标签页同时登录不同账户（Chrome 等浏览器）
   - ✅ 页面刷新后自动恢复登录状态和聊天记录
   - ✅ 关闭标签页自动清除登录状态和聊天记录（安全性更好）
   - 标签页之间完全隔离，互不影响
   - 聊天记录最多保存 500 条消息（sessionStorage 限制）
2. 所有消息在网络传输前都会加密
3. 默认密码仅用于演示，生产环境请务必修改
4. 加密密码用于消息加密，不与登录密码相同
5. WebSocket 连接需要有效的 JWT token
6. 加密密码丢失将无法查看历史消息
7. **多用户聊天**：必须使用相同的加密密码才能看到彼此的消息
   - ✅ 相同密码：能看到彼此的消息
   - ❌ 不同密码：只能看到自己的消息
8. **注册流程**：注册时只需填写用户名、密码、确认密码
   - ⚠️ 注册时不设置加密密码
   - ⚠️ 加密密码仅在登录时设置（可选）
9. 加密密码是可选的，留空使用默认值
10. 每次登录都可以设置不同的加密密码
11. **密码强度要求**：必须包含大小写字母、数字、特殊字符
12. **登录安全**：连续失败 5 次将锁定账户 15 分钟
13. **管理员操作**：
    - 禁用用户 = 踢出 + 不能登录
    - 不能操作自己
    - 被踢出/禁用后用户收到提示
    - 踢出/禁用需要二次密码确认

## 🐛 故障排查

### 登录失败
- 检查用户名和密码是否正确（密码需符合强度要求）
- 确保后端服务正在运行
- 查看浏览器控制台错误信息
- 检查是否被锁定（失败 5 次）

### 消息显示加密错误
- 检查加密密码是否正确
- 确保所有用户使用相同的加密密码
- 重新登录尝试

### WebSocket 连接失败
- 检查防火墙设置
- 确保端口 8080 开放
- 查看后端日志
- 检查浏览器控制台

### 页面刷新后丢失登录状态
- 现已支持页面刷新后自动恢复登录
- 如果出现此问题，请检查 sessionStorage 是否可用
- 部分浏览器隐私模式可能禁用 sessionStorage

### 表情选择器超出界面
- 刷新页面重置
- 检查浏览器缩放设置

## 📄 许可证
MIT License

## 📝 更新日志

### v3.4 (2025-01-27)
- ✨ **Session Storage 登录管理**
  - 使用 sessionStorage 替代 localStorage 存储 token
  - 支持多标签页同时登录不同账户
  - 页面刷新后自动恢复登录状态
  - 关闭标签页自动清除登录状态

- 📝 **聊天记录持久化**
  - 刷新页面后保持聊天记录不丢失
  - 使用 sessionStorage 存储最多 500 条消息
  - 自动恢复并显示历史消息

- 🔧 **WebSocket 连接频率限制优化**
  - 从 5 次/分钟 提高到 20 次/分钟
  - 支持更多刷新页面和网络波动重连

- 🐛 **UI 优化**
  - 输入窗口始终保持在页面底部
  - 页面右侧不出现水平滚动条
  - 消息多时消息窗口出现垂直滚动条
  - 刷新后自动滚动到最新消息

- 🛡️ **安全改进**
  - 改进 JWT token 验证错误提示
  - 区分 Token 过期、Token 无效、用户不存在等错误
  - 修改密码时自动检测 token 是否存在
  - 401 错误自动强制退出登录

- 🧹 **项目清理**
  - 删除根目录下不必要的 keys/ 文件夹
  - 统一使用 backend/keys/ 目录

## 🙏 致谢
- FastAPI
- CryptoJS
- PyCryptodome
- Loguru
- Pydantic
- bcrypt
- jose (PyJWT)

---

**版本**: v3.4
**更新日期**: 2025-01-27
**作者**: Private Chat Team
