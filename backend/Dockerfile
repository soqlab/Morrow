FROM python:3.11-slim

WORKDIR /app

# OpenTofu, not Terraform: Terraform moved to the BUSL-1.1 licence, which is not open source and
# cannot be redistributed in a published image. OpenTofu is the MPL-2.0 fork and is CLI-compatible.
ARG OPENTOFU_VERSION=1.8.6
ARG INSTALL_DEV_DEPS=false

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    APP_COMPONENT=api \
    PQC_MAIN_DB_BACKEND=postgres \
    ENABLE_INPROCESS_SCHEDULER=0 \
    PER_TARGET_TIMEOUT=20

COPY requirements.txt requirements-dev.txt /app/

RUN apt-get update \
    && apt-get install -y --no-install-recommends curl unzip ca-certificates \
    && curl -fsSL "https://github.com/opentofu/opentofu/releases/download/v${OPENTOFU_VERSION}/tofu_${OPENTOFU_VERSION}_linux_amd64.zip" -o /tmp/tofu.zip \
    && unzip /tmp/tofu.zip tofu -d /usr/local/bin \
    && rm -f /tmp/tofu.zip \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --upgrade pip==26.2 setuptools==83.0.0 wheel==0.48.0 \
    && pip install --no-cache-dir -r /app/requirements.txt \
    && if [ "$INSTALL_DEV_DEPS" = "true" ]; then pip install --no-cache-dir -r /app/requirements-dev.txt; fi \
    && adduser --disabled-password --gecos "" --uid 1001 appuser

COPY --chown=appuser:appuser . /app

# /data holds the SQLite file for the features that are not yet on Postgres
# (db._default_db_path() prefers /data/pqc_scanner.db when the directory exists), and
# docker-compose.prod.yml mounts a volume there.
#
# It has to exist in the image and be owned by appuser: Docker initialises a fresh named volume from
# the image's directory, ownership included, but a volume mounted over a path that does not exist in
# the image is created root-owned. The container runs as appuser, so in that case it cannot write the
# database and the process exits during startup with "unable to open database file" -- the container
# never serves at all.
RUN chmod +x /app/entrypoint.sh \
    && mkdir -p /data \
    && chown appuser:appuser /data

USER appuser

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
