# Private Chat 容器镜像
# 多阶段构建：builder 安装依赖，runtime 仅含运行所需文件
# - 非 root 用户运行
# - 显式单 worker（应用使用进程内状态，多 worker 需配合外部状态存储）
# - 内置健康检查（/health）
# ==================== 构建阶段 ====================
FROM python:3.11-slim AS builder

WORKDIR /build

# 安装编译依赖（bcrypt/pycryptodome 通常有 wheel，保留以防万一）
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc python3-dev \
    && rm -rf /var/lib/apt/lists/*

# 仅拷贝依赖清单，利用层缓存
COPY backend/requirements.txt ./requirements.txt

RUN pip install --no-cache-dir --user -r requirements.txt

# ==================== 运行阶段 ====================
FROM python:3.11-slim

# OCI 镜像标签
LABEL org.opencontainers.image.title="Private Chat" \
      org.opencontainers.image.description="安全加密聊天系统" \
      org.opencontainers.image.version="3.6.1" \
      org.opencontainers.image.licenses="MIT"

# 创建非 root 用户
RUN groupadd -r app && useradd -r -g app -d /app -s /sbin/nologin app

WORKDIR /app

# 拷贝已安装的依赖（带正确属主）
COPY --from=builder --chown=app:app /root/.local /home/app/.local

# 拷贝后端与前端代码
COPY --chown=app:app backend ./backend
COPY --chown=app:app frontend ./frontend

# 创建数据与日志目录（运行时写入）
RUN mkdir -p /app/data /app/logs /app/backend/keys && chown -R app:app /app

USER app

ENV PATH=/home/app/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

EXPOSE 8080

# 健康检查：每 30s 探测 /health，失败 3 次或超时 5s 视为不健康
# 带 Host: localhost 头匹配 ALLOWED_HOSTS（TrustedHostMiddleware 在生产环境会校验 Host）
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; req=urllib.request.Request('http://127.0.0.1:8080/health', headers={'Host':'localhost'}); sys.exit(0 if urllib.request.urlopen(req, timeout=3).status==200 else 1)"

# 单 worker：应用使用进程内状态（clients/messages/限流计数），
# 多 worker 部署需先将状态迁移到 Redis 等外部存储。
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
