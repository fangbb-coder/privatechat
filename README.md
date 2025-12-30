# Private Chat v3.6.0 - 安全增强版加密聊天系统

## 🆕 v3.6.0 更新 (2025-01-30)

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

### 安全改进
- 🔒 AES-256-CBC 加密算法（与 CryptoJS 兼容）
- 🔒 防止密码复用
- 🔒 会话管理和限制
- 🔒 更严格的 CORS 策略
- 🔒 完整的 HTTP 安全头
- 🔒 日志敏感信息保护
- 🔒 配置参数合法性检查
- 🔒 WebSocket 连接稳定性提升

## 🆕 v3.5.3 更新 (2025-01-27)

### 修复账户锁定问题
- ✅ **修复IP频率限制**：提高登录接口速率限制（10→30次/分钟），避免正常用户被限制
- ✅ **优化锁定时间显示**：确保锁定期间持续显示剩余锁定时间
- ✅ **修正首次锁定提示**：首次锁定时也显示剩余时间而非仅显示"已锁定"


### 安全增强
- ✅ **JWT 密钥自动生成**：首次启动时生成64位随机密钥，避免使用默认密钥
- ✅ **强制设置消息加密密码**：移除默认密码，要求用户必须设置至少8位的加密密码
- ✅ **WebSocket Origin 验证**：添加WebSocket连接的origin验证，防止跨站点攻击
- ✅ **错误消息模糊化**：统一所有认证错误消息，防止用户枚举攻击
- ✅ **增强登录失败锁定**：新增IP级别锁定，同一IP失败20次锁定30分钟
- ✅ **CSP 防护 XSS**：添加Content-Security-Policy头部，限制资源加载来源
- ✅ **前端 XSS 防护**：所有用户输入通过escapeHTML函数消毒
- ✅ **错误处理规范化**：将裸except改为具体异常捕获，使用debug级别日志
- ✅ **优化IP频率限制**：登录接口30次/分钟，避免正常用户被限制

### 代码质量
- ✅ 删除重复的全局实例定义
- ✅ 统一版本号（backend v3.5, frontend v3.5）
- ✅ 规范化日志级别（敏感信息降级为debug）

### 移除功能
- ⚠️ 移除"记住我"功能token配置（已改用sessionStorage）

### 已知限制
- ⏭️ 数据库加密仍使用统一密钥（未来版本将实现用户独立密钥）
- ⏭️ 前端文件未拆分（保持单文件架构符合极简原则）

## 🆕 v3.5.2 更新 (2025-01-27)

### 错误消息优化
- ✅ **修复账户禁用错误**：恢复"账户已被禁用"的明确错误消息
- ✅ **优化账户锁定提示**：显示剩余锁定时间（"账户已被锁定，请X分钟后重试"）
- ✅ **WebSocket增强**：WebSocket连接时也检查账户锁定状态
- ✅ **前端错误处理**：增加"锁定"关键词检测，正确显示锁定消息

### 已知限制
- ⏭️ 数据库加密仍使用统一密钥（未来版本将实现用户独立密钥）
- ⏭️ 前端文件未拆分（保持单文件架构符合极简原则）

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
9. 每次登录都可以设置不同的加密密码
10. **密码强度要求**：必须包含大小写字母、数字、特殊字符
11. **登录安全**：连续失败 5 次将锁定账户 15 分钟
12. **管理员操作**：
    - 禁用用户 = 踢出 + 不能登录
    - 不能操作自己
    - 被踢出/禁用后用户收到提示
    - 踢出/禁用需要二次密码确认
    - **删除用户**：管理员可以删除用户账户（不能删除自己）

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
1. 前端使用 AES-256-CBC 加密消息
2. RSA-2048 密钥交换保护会话密钥
3. 加密后的消息通过 WebSocket 发送
4. 后端解密并重新加密（使用 RSA 保护会话密钥）
5. 前端解密并显示

### 高级加密特性
- **多重防护**：RSA-2048 + AES-256-CBC + bcrypt
- **密钥持久化**：RSA 密钥存储在 `backend/keys/` 目录
- **字段级加密**：用户名和密码在数据库中加密存储
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

**请求参数（推荐使用加密密码）:**
```json
{
  "username": "admin",
  "encrypted_password": "RSA加密后的密码"
}
```

**请求参数（兼容明文密码）:**
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
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "username": "admin"
}
```

**说明:**
- 前端使用 JSEncrypt 库通过 RSA-2048 加密密码
- 后端使用 PKCS#1 v1.5 解密（兼容 JSEncrypt）
- 网络传输中密码为加密状态，防止抓包泄露
- 同时支持明文密码（向后兼容）

### GET /api/public-key
获取 RSA 公钥（用于加密登录密码）

**响应:**
```json
{
  "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",
  "key_size": 2048,
  "encryption_details": {
    "aes": "AES-256-CBC",
    "rsa": "RSA-2048",
    "password_hash": "bcrypt"
  }
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

**响应:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
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

### DELETE /api/admin/user/{username}
删除用户（管理员）- 新增功能

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
- PyCryptodome - AES-256-CBC + RSA-2048 加密
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
├── start.bat             # Windows 启动脚本
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
9. 每次登录都可以设置不同的加密密码
10. **密码强度要求**：必须包含大小写字母、数字、特殊字符
11. **登录安全**：连续失败 5 次将锁定账户 15 分钟
12. **管理员操作**：
    - 禁用用户 = 踢出 + 不能登录
    - 不能操作自己
    - 被踢出/禁用后用户收到提示
    - 踢出/禁用需要二次密码确认
    - **删除用户**：管理员可以删除用户账户（不能删除自己）
13. **移动端优化**：
    - 发送消息后输入框自动重新聚焦，防止键盘收起
    - 添加移动端优化属性（inputmode、autocomplete、autocorrect等）
    - 防止回车键导致输入框失去焦点
    - 优化CSS防止键盘弹出/收起时的布局跳动
14. **在线用户数显示**：使用后端发送的count字段，确保显示准确的在线用户数

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
- 部署浏览器隐私模式可能禁用 sessionStorage

### 表情选择器超出界面
- 刷新页面重置
- 检查浏览器缩放设置

## 📄 许可证
MIT License
