# Private Chat 容器镜像
#
# 常用构建参数(可按需覆盖):
#   --build-arg PIP_INDEX_URL=https://pypi.tuna.tsinghua.edu.cn/simple
#       → 切换到国内 PyPI 镜像,中国节点构建速度提 3-10 倍
#   默认启用 pip 层缓存,后续 build 可直接命中,几秒完成。
#   需要完全无缓存构建:请用 `docker build --no-cache ...` (不要在这里硬 --no-cache-dir)。

FROM python:3.11-slim AS builder

# 可通过 build-arg 覆盖 PyPI 源(默认官方源)
ARG PIP_INDEX_URL=https://pypi.org/simple
ARG PIP_TRUSTED_HOST=pypi.org

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
RUN pip install \
        --index-url "${PIP_INDEX_URL}" \
        --trusted-host "${PIP_TRUSTED_HOST}" \
        --target=/install \
        -r requirements.txt

# ==================== 运行阶段 ====================
FROM python:3.11-slim

ARG APP_VERSION=3.7.0
LABEL org.opencontainers.image.title="Private Chat" \
      org.opencontainers.image.description="HTTPS 安全加固版加密聊天系统" \
      org.opencontainers.image.version="${APP_VERSION}" \
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

# 不注入 Host 头:避免 ALLOWED_HOSTS 严格模式下 TrustedHostMiddleware 拒绝 Host=localhost 导致健康检查永远失败
# (Starlette 自动回落到 127.0.0.1,而生产 ALLOWED_HOSTS 一般不会包含字符串 localhost)
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3).status==200 else 1)"

CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
