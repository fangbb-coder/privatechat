========================================
  Private Chat v3.2 - 阿里云服务器部署指南
  GitHub: https://github.com/fangbb-coder/privatechat
========================================

一、服务器要求
========================================

最低配置（测试/小团队）:
  CPU: 1核
  内存: 1GB
  带宽: 1Mbps
  存储: 20GB SSD
  系统: Ubuntu 20.04/22.04 或 CentOS 7/8

推荐配置（生产环境）:
  CPU: 2核+
  内存: 2-4GB
  带宽: 3-5Mbps
  存储: 40GB+ SSD
  系统: Ubuntu 22.04 LTS

安全组配置（入方向规则）:
  端口 80   - HTTP
  端口 443  - HTTPS
  端口 22   - SSH（建议限制IP）


二、快速部署（推荐）
========================================

1. 连接到服务器

   # SSH 连接到服务器
   ssh root@服务器IP

2. 下载并执行部署脚本

   # 方法一：从 GitHub 克隆项目
   git clone https://github.com/fangbb-coder/privatechat.git /root/minimal-chat
   cd /root/minimal-chat
   chmod +x deploy.sh
   sudo ./deploy.sh

   # 方法二：直接下载脚本
   wget https://raw.githubusercontent.com/fangbb-coder/privatechat/main/deploy.sh
   chmod +x deploy.sh
   sudo ./deploy.sh

3. 按照脚本提示完成配置

   脚本将自动完成:
   - 系统更新
   - 安装 Python, Nginx, Certbot, Git
   - 从 GitHub 克隆项目代码
   - 配置虚拟环境
   - 安装依赖
   - 配置 Nginx 反向代理
   - 配置 HTTPS（可选）
   - 配置 Systemd 服务
   - 配置防火墙

4. 部署后配置

   # 修改密钥
   cd /root/minimal-chat/backend
   cat secret_key.txt
   # 将生成的密钥替换 main.py 中的 SECRET_KEY

   # 修改默认密码
   # 编辑 backend/main.py，修改默认用户密码（admin/admin234）

   # 重启服务
   systemctl restart minimal-chat


三、手动部署步骤
========================================

如果自动部署失败，可按以下步骤手动部署：

1. 安装必要软件
   -----
   apt update && apt upgrade -y
   apt install -y python3 python3-pip python3-venv nginx certbot python3-certbot-nginx git

2. 克隆项目
   -----
   git clone https://github.com/fangbb-coder/privatechat.git /root/minimal-chat

3. 配置项目
   -----
   cd /root/minimal-chat/backend
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   pip install gunicorn

4. 配置 Nginx
   -----
   # 编辑配置文件
   nano /etc/nginx/sites-available/minimal-chat

   # 复制 nginx.conf.template 内容，修改 YOUR_DOMAIN 为实际域名或IP

   # 启用配置
   ln -s /etc/nginx/sites-available/minimal-chat /etc/nginx/sites-enabled/
   rm /etc/nginx/sites-enabled/default

   # 测试并重启
   nginx -t
   systemctl restart nginx

5. 配置 HTTPS（可选）
   -----
   certbot --nginx -d 你的域名

6. 配置 Systemd 服务
   -----
   # 编辑服务文件
   nano /etc/systemd/system/minimal-chat.service

   # 复制 minimal-chat.service.template 内容

   # 启动服务
   systemctl daemon-reload
   systemctl start minimal-chat
   systemctl enable minimal-chat

7. 配置防火墙
   -----
   apt install -y ufw
   ufw allow ssh
   ufw allow http
   ufw allow https
   ufw enable


四、更新项目
========================================

当 GitHub 仓库有更新时，可以快速更新服务器上的项目：

1. 拉取最新代码
   -----
   cd /root/minimal-chat
   git pull origin main

2. 重启服务
   -----
   systemctl restart minimal-chat

3. 如果有依赖更新
   -----
   cd /root/minimal-chat/backend
   source venv/bin/activate
   pip install -r requirements.txt
   systemctl restart minimal-chat


五、部署后配置
========================================

1. 修改密钥
   -----
   cd /root/minimal-chat/backend
   cat secret_key.txt

   将生成的密钥替换 main.py 中的 SECRET_KEY

2. 修改默认密码
   -----
   编辑 backend/main.py，修改默认用户密码（admin/admin234）

3. 重启服务
   -----
   systemctl restart minimal-chat


六、常用管理命令
========================================

服务管理:
  查看状态:    systemctl status minimal-chat
  启动服务:    systemctl start minimal-chat
  停止服务:    systemctl stop minimal-chat
  重启服务:    systemctl restart minimal-chat
  开机自启:    systemctl enable minimal-chat

日志查看:
  应用日志:    journalctl -u minimal-chat -f
  Nginx日志:   tail -f /var/log/nginx/error.log
  访问日志:    tail -f /var/log/nginx/access.log

Nginx管理:
  测试配置:    nginx -t
  重启服务:    systemctl restart nginx
  重新加载:    systemctl reload nginx

Git管理:
  查看状态:    git status
  拉取更新:    git pull origin main
  查看日志:    git log --oneline


七、费用参考（阿里云）
========================================

1核1GB   约 ¥30/月   个人测试
2核2GB   约 ¥100/月  小团队
2核4GB   约 ¥200/月  生产环境


八、故障排查
========================================

1. 服务无法启动
   - 检查依赖是否安装: pip list
   - 查看日志: journalctl -u minimal-chat -n 50
   - 检查端口占用: netstat -tlnp | grep 8080

2. WebSocket 连接失败
   - 检查 Nginx 配置中的 WebSocket 部分
   - 查看错误日志: tail -f /var/log/nginx/error.log
   - 确认防火墙端口开放

3. HTTPS 证书问题
   - 检查证书状态: certbot certificates
   - 手动续期: certbot renew
   - 测试续期: certbot renew --dry-run

4. 页面无法访问
   - 检查 Nginx 是否运行: systemctl status nginx
   - 检查端口监听: netstat -tlnp | grep :80
   - 检查安全组规则

5. Git 拉取失败
   - 检查网络连接: ping github.com
   - 检查 Git 配置: git remote -v
   - 手动拉取: git fetch origin


九、安全建议
========================================

1. 修改 SSH 默认端口
2. 配置 SSH 密钥登录
3. 定期更新系统和依赖
4. 配置防火墙规则
5. 使用强密码
6. 定期备份数据
7. 配置 fail2ban 防止暴力破解
8. 生产环境必须配置 HTTPS
9. 定期更新项目代码


十、访问地址
========================================

部署成功后，可通过以下地址访问:

  HTTP:  http://你的域名
  HTTPS: https://你的域名（如果配置了）

如果没有域名，直接使用服务器 IP:

  http://服务器IP

项目主页: https://github.com/fangbb-coder/privatechat


十一、技术支持
========================================

如有问题，请查看:
- GitHub 仓库: https://github.com/fangbb-coder/privatechat
- 应用日志: journalctl -u minimal-chat -f
- Nginx日志: tail -f /var/log/nginx/error.log
- README.md 文档


十二、隐私特性说明
========================================

本聊天系统采用完全隐私保护的设计：

1. 消息不持久化
   - 聊天消息仅存储在服务器内存中
   - 不保存到任何数据库、文件或日志
   - 消息仅在发送时短暂存在

2. 自动清除机制
   - 所有用户断开连接后，内存自动释放
   - 聊天记录不会残留任何痕迹
   - 新用户加入时看不到历史消息

3. 临时性特征
   - 仅支持实时消息传递
   - 不支持消息历史查询
   - 不支持离线消息

4. 适用场景
   - 临时会议讨论
   - 敏感信息即时通讯
   - 高隐私要求的场景

5. 注意事项
   - 系统重启或服务停止后，所有聊天内容丢失
   - 适合需要"阅后即焚"的沟通场景
   - 如需历史记录，需客户端自行保存


十三、功能特性
========================================

1. 用户注册与登录
   - 支持用户自行注册账户
   - 基于 JWT (JSON Web Token) 的安全认证
   - Token 有效期: 30 分钟

2. 消息加密
   - 所有聊天消息使用 AES-256-CBC 加密
   - 用户可自定义加密密码
   - 前端使用 CryptoJS 进行加密
   - 后端使用 PyCryptodome 进行解密

3. 实时用户状态
   - 显示用户连接/断开通知
   - 区分自己的消息和其他用户的消息
   - 加密消息自动解密显示

4. 多用户支持
   - 支持多用户同时在线
   - 多用户聊天时必须使用相同的加密密码
   - 实时消息同步


十四、项目结构
========================================

/root/minimal-chat/
├── backend/
│   ├── main.py           # 后端主程序
│   ├── requirements.txt  # Python 依赖
│   └── venv/            # 虚拟环境
├── frontend/
│   └── index.html        # 前端页面
├── frp/                  # 内外网穿透配置
├── docker/               # Docker 部署配置
├── deploy.sh            # 自动部署脚本
├── DEPLOY.md            # 本文档
└── README.md            # 项目说明


十五、快速参考
========================================

部署命令:
  git clone https://github.com/fangbb-coder/privatechat.git /root/minimal-chat
  cd /root/minimal-chat
  chmod +x deploy.sh
  sudo ./deploy.sh

更新命令:
  cd /root/minimal-chat
  git pull origin main
  systemctl restart minimal-chat

重启服务:
  systemctl restart minimal-chat

查看日志:
  journalctl -u minimal-chat -f

========================================
