# Private Chat v3.2 - 加密聊天系统

## ✨ 新功能

### 1. 用户注册与登录
- ✨ 支持用户自行注册账户
- 默认用户名: `admin` / `admin2`
- 默认密码: `admin234` / `admin2345`
- 基于 JWT (JSON Web Token) 的安全认证
- Token 有效期: 30 分钟

### 2. 用户名和密码验证
- 用户名: 3-20 个字符，只能包含字母、数字和下划线
- 密码: 6-32 个字符
- 前端实时验证，后端二次验证

### 3. 消息加密
- 所有聊天消息使用 **AES-256-CBC** 加密
- 用户可自定义加密密码
- 默认加密密码: `PrivateChat2025Secure!`
- 前端使用 CryptoJS 进行加密
- 后端使用 PyCryptodome 进行解密
- **注意**：当前使用兼容模式，新加密方案（RSA-2048 + AES-256-GCM）已在代码中实现，待前端升级后启用

### 4. 实时用户状态
- 显示用户连接/断开通知
- 区分自己的消息和其他用户的消息
- 加密消息自动解密显示

### 5. 退出登录
- 点击右上角"退出"按钮退出聊天
- 确认后断开WebSocket连接
- 清理所有聊天记录和状态

## 🚀 快速开始

### 启动服务
```bash
cd e:/minimal-chat/backend
uvicorn main:app --host 0.0.0.0 --port 8080
```

或使用启动脚本：
```bash
e:/minimal-chat/quick_start.bat
```

### 访问应用
打开浏览器访问: http://localhost:8080

### 注册新用户
1. 点击"立即注册"链接
2. 填写注册信息：
   - 用户名: 3-20个字符（字母、数字、下划线）
   - 密码: 6-32个字符
   - 确认密码: 必须与密码一致
3. 点击"注册"按钮
4. 注册成功后自动跳转到登录页
5. 在登录时设置消息加密密码（可选）

### 登录
- 已有账户: `admin` / `admin234` 或 `admin2` / `admin2345`
- 加密密码（可选）: 留空使用默认密码 `PrivateChat2025Secure!`
- ⚠️ **重要**: 多用户聊天时，必须使用相同的加密密码才能看到彼此的消息

## 🔐 安全特性

### 认证流程
1. 用户输入用户名和密码
2. 后端验证并返回 JWT token
3. WebSocket 连接时发送 token 进行认证
4. 只有认证用户才能加入聊天

### 消息加密流程
1. 前端使用 AES-256-CBC 加密消息（向后兼容）
2. 加密后的消息通过 WebSocket 发送
3. 后端解密验证（支持新旧两种格式）
4. 后端使用会话密钥进行二次加密（新格式：AES-256-GCM + 随机填充）
5. 前端解密并显示

### 高级加密特性
- **多重防护**：服务器端使用 RSA-2048 + AES-256-GCM + 随机填充
- **流量混淆**：随机填充层防止流量分析
- **认证加密**：GCM模式提供完整性和保密性
- **向后兼容**：支持旧版客户端的加密格式
- **防中间人**：每会话独立密钥，防止密钥泄露影响其他会话

### ⚠️ 隐私保护
- **消息不持久化**：聊天消息仅存储在内存中，不保存到数据库或文件
- **自动清除**：所有用户断开连接后，聊天记录自动从内存清除
- **无历史记录**：新用户加入时看不到之前的聊天内容
- **临时性**：消息仅在发送时存在，服务器不保留任何聊天历史

### 安全建议
1. **生产环境必须更改默认密码**
2. 修改 `SECRET_KEY` 为随机密钥
3. 使用 HTTPS 部署
4. 定期更新依赖包

## 📝 API 文档

### POST /register
用户注册

**请求参数:**
```json
{
  "username": "newuser",
  "password": "password123"
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
- 密码: 6-32 个字符
- 用户名不能重复

### POST /token
用户登录，获取 JWT token

**请求参数:**
- `username`: 用户名
- `password`: 密码

**响应:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "bearer",
  "username": "admin"
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
- `system`: 系统通知
- `error`: 错误信息

## 🛠️ 技术栈

### 后端
- FastAPI - Web 框架
- WebSocket - 实时通信
- PyJWT - JWT 认证
- Passlib - 密码哈希
- PyCryptodome - AES-256 + RSA-2048 加密
- Scrypt - 抗ASIC/GPU密钥派生

### 前端
- 原生 HTML/CSS/JavaScript
- CryptoJS - 前端加密
- WebSocket - 实时通信

## 📂 项目结构
```
e:/minimal-chat/
├── backend/
│   ├── main.py           # 后端主程序
│   └── requirements.txt  # Python 依赖
├── frontend/
│   └── index.html        # 前端页面
├── frp/                  # 内外网穿透配置
├── docker/               # Docker 部署配置
├── start.bat            # 启动脚本
├── stop.bat             # 停止脚本
└── README.md            # 本文档
```

## 🔧 配置

### 修改默认密码
编辑 `backend/main.py`:
```python
users_db = {
    "admin": {
        "username": "admin",
        "hashed_password": pwd_context.hash("your-new-password")
    }
}
```

### 修改 JWT 密钥
编辑 `backend/main.py`:
```python
SECRET_KEY = "your-random-secret-key-here"
```

### 修改 Token 有效期
编辑 `backend/main.py`:
```python
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 60分钟
```

## 🌐 外网访问

参考 `FRP_SETUP.md` 文档配置内外网穿透。

推荐方式：
1. **FRP** - 需要公网服务器
2. **Cloudflare Tunnel** - 免费，零配置
3. **Ngrok** - 快速测试

## ⚠️ 注意事项

1. 所有消息在网络传输前都会加密
2. 默认密码仅用于演示，生产环境请务必修改
3. 加密密码用于消息加密，不与登录密码相同
4. WebSocket 连接需要有效的 JWT token
5. 加密密码丢失将无法查看历史消息
6. **多用户聊天**：必须使用相同的加密密码才能看到彼此的消息
   - ✅ 相同密码：能看到彼此的消息
   - ❌ 不同密码：只能看到自己的消息，别人的显示"加密消息：密码不同，无法解密消息"
7. **注册流程**：注册时只需填写用户名、密码、确认密码
   - ⚠️ 注册时不设置加密密码
   - ⚠️ 加密密码仅在登录时设置（可选）
8. 加密密码是可选的，留空使用默认值 `PrivateChat2025Secure!`
9. 每次登录都可以设置不同的加密密码

## 🐛 故障排查

### 登录失败
- 检查用户名和密码是否正确
- 确保后端服务正在运行
- 查看浏览器控制台错误信息

### 消息显示"加密消息：密码不同，无法解密消息"
- 检查加密密码是否正确
- 确保所有用户使用相同的加密密码
- 重新登录尝试
- 检查是否使用了兼容的加密格式（新旧格式自动兼容）

### WebSocket 连接失败
- 检查防火墙设置
- 确保端口 8080 开放
- 查看后端日志

## 📄 许可证
MIT License

## 🙏 致谢
- FastAPI
- CryptoJS
- PyCryptodome
