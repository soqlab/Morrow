# Hosted Morrow on one Render service (see render.yaml, service morrow-app).
#
# docker-compose.prod.yml runs the API, the Celery worker, Celery beat and Redis as four
# containers. Render bills per service and a disk cannot be shared between services, so this
# image runs all four in one container instead: start.sh starts Redis on localhost, the worker
# with beat embedded, and the API. Data is SQLite on the Render disk at /data; setting
# MORROW_MAIN_DB_BACKEND=postgres and DATABASE_URL moves it to Postgres instead.
#
# Build context is the repository root.
FROM python:3.11-slim

WORKDIR /app

ARG OPENTOFU_VERSION=1.8.6

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    APP_COMPONENT=api \
    MORROW_MAIN_DB_BACKEND=sqlite \
    ENABLE_INPROCESS_SCHEDULER=0 \
    PER_TARGET_TIMEOUT=20

COPY backend/requirements.txt /app/
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip ca-certificates redis-server \
    && curl -fsSL "https://github.com/opentofu/opentofu/releases/download/v${OPENTOFU_VERSION}/tofu_${OPENTOFU_VERSION}_linux_amd64.zip" -o /tmp/tofu.zip \
    && unzip /tmp/tofu.zip tofu -d /usr/local/bin \
    && rm -f /tmp/tofu.zip \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --upgrade pip==26.2 setuptools==83.0.0 wheel==0.48.0 \
    && pip install --no-cache-dir -r /app/requirements.txt \
    && adduser --disabled-password --gecos "" --uid 1001 appuser

COPY --chown=appuser:appuser backend/ /app/
COPY --chown=appuser:appuser deploy/render-hosted/start.sh /app/render-start.sh
RUN chmod +x /app/entrypoint.sh /app/render-start.sh \
    && mkdir -p /data \
    && chown appuser:appuser /data

# No USER line: start.sh runs as root only to hand the Render disk at /data to appuser, then
# drops to appuser for every process it starts.
EXPOSE 8000
ENTRYPOINT ["/app/render-start.sh"]
