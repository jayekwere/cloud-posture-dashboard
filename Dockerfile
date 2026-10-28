# Pinned multi-platform Python Alpine image; update deliberately with an image scan.
FROM python:3.14.6-alpine@sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /app
COPY requirements.lock ./requirements.lock
RUN apk upgrade --no-cache \
    && python -m pip install --require-hashes -r requirements.lock \
    && addgroup -S -g 10001 posture \
    && adduser -S -D -H -u 10001 -G posture -s /sbin/nologin posture \
    && python -m pip uninstall --yes pip
COPY posture/ ./posture/
COPY LICENSE ./LICENSE
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]
# One worker keeps the ephemeral session key and temporary workspace consistent.
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "1", "--threads", "4", "--worker-tmp-dir", "/tmp", "--timeout", "30", "posture:create_app()"]
