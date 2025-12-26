@echo off
chcp 65001 >nul
echo.
echo ========================================
echo Minimal Chat v3.2 - 快速启动
echo ========================================
echo.
echo 登录账户:
echo   1. 用户名: admin,     密码: admin234
echo   2. 用户名: admin2,    密码: admin2345
echo.
echo 新功能:
echo   ✨ 支持用户自行注册账户
echo   ✨ 用户名: 3-20字符 (字母/数字/下划线)
echo   ✨ 密码: 6-32字符
echo.
echo 加密密钥: admin234 (默认)
echo 访问地址: http://localhost:8080
echo ========================================
echo.

cd /d e:\minimal-chat\backend
echo 正在启动服务器...
echo.

python -m uvicorn main:app --host 0.0.0.0 --port 8080

echo.
echo 服务器已停止
pause
