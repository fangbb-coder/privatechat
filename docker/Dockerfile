# Private Chat 容器镜像
FROM python:3.11-slim AS builder

RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
        sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources; \
    fi; \
    if [ -f /etc/apt/sources.list ]; then \
        sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list; \
    fi

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc python3-dev \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --target=/install -r requirements.txt

# ==================== 运行阶段 ====================
FROM python:3.11-slim

LABEL org.opencontainers.image.title="Private Chat" \
      org.opencontainers.image.description="安全加密聊天系统" \
      org.opencontainers.image.version="3.6.1" \
      org.opencontainers.image.licenses="MIT"

RUN groupadd -r app && useradd -r -g app -d /app -s /sbin/nologin app

RUN set -eux; \
    if [ -f /etc/apt/sources.list.d/debian.sources ]; then \
        sed -i 's|deb.debian.org|mirrors.aliyun.com|g; s|security.debian.org|mirrors.aliyun.com|g' /etc/apt/sources.list.d/debian.sources; \
    fi

WORKDIR /app

COPY --from=builder --chown=app:app /install /home/app/.local
COPY --chown=app:app backend ./backend
COPY --chown=app:app frontend ./frontend

RUN mkdir -p /app/data /app/logs /app/backend/keys && chown -R app:app /app

USER app

ENV PATH=/home/app/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # 让 backend/main.py 的 from utils.config import settings 找到 /app/backend/utils
    PYTHONPATH=/home/app/.local:/app:/app/backend

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; req=urllib.request.Request('http://127.0.0.1:8080/health', headers={'Host':'localhost'}); sys.exit(0 if urllib.request.urlopen(req, timeout=3).status==200 else 1)"

CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
