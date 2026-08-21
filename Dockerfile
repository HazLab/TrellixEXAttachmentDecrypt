# Trellix EX Attachment Decrypt — container image.
# Multi-stage: build a wheel + deps, then a slim runtime with a non-root user.

FROM python:3.12-slim AS build
WORKDIR /app
# Build deps for any wheels that need compiling (cryptography ships wheels, but be safe).
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim AS runtime
# Non-root runtime user; DATA_DIR is a mounted volume it must be able to write.
RUN useradd --create-home --uid 10001 appuser
COPY --from=build /install /usr/local
WORKDIR /app
COPY trellix_decrypt ./trellix_decrypt
COPY pyproject.toml README.md ./
# Persistent state (secret.key + SQLite by default) lives here — mount a volume.
ENV DATA_DIR=/data \
    WEB_HOST=0.0.0.0 \
    WEB_PORT=8080 \
    PYTHONUNBUFFERED=1
RUN mkdir -p /data && chown appuser:appuser /data
VOLUME ["/data"]
USER appuser
EXPOSE 8080
# Healthcheck honours WEB_PORT / HTTPS_ENABLED / HTTPS_PORT so it follows the listen
# port and scheme (self-signed certs are accepted).
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import os,ssl,urllib.request,sys; https=os.environ.get('HTTPS_ENABLED','').lower() in ('1','true','yes','on'); port=os.environ.get('HTTPS_PORT','8443') if https else os.environ.get('WEB_PORT','8080'); url=('https' if https else 'http')+f'://127.0.0.1:{port}/healthz'; ctx=ssl._create_unverified_context() if https else None; sys.exit(0 if urllib.request.urlopen(url,timeout=3,context=ctx).status==200 else 1)"
CMD ["python", "-m", "trellix_decrypt"]
