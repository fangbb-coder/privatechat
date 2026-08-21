# M4: 修复 Dockerfile
# - 拷贝前端（原仅拷贝 backend，导致 frontend_dir 不存在）
# - 非 root 用户运行
# - 显式单 worker（应用使用进程内状态，多 worker 需配合外部状态存储）
FROM python:3.11-slim AS builder

WORKDIR /build

# 仅拷贝依赖清单，利用层缓存
COPY backend/requirements.txt ./requirements.txt

RUN pip install --no-cache-dir --user -r requirements.txt

# ==================== 运行阶段 ====================
FROM python:3.11-slim

# 创建非 root 用户
RUN groupadd -r app && useradd -r -g app -d /app -s /sbin/nologin app

WORKDIR /app

# 拷贝已安装的依赖
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
    ENVIRONMENT=production

EXPOSE 8080

# 单 worker：应用使用进程内状态（clients/messages/限流计数），
# 多 worker 部署需先将状态迁移到 Redis 等外部存储。
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
