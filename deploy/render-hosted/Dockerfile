# Hosted Morrow on one Render service (see render.yaml, service morrow-app).
#
# docker-compose.prod.yml runs the API, the Celery worker, Celery beat and Redis as four
# containers. Render bills per service and a disk cannot be shared between services, so this
# image runs all four in one container instead: start.sh starts Redis on localhost, the worker
# with beat embedded, and the API. Data is SQLite on the Render disk at /data; setting
# MORROW_MAIN_DB_BACKEND=postgres and DATABASE_URL moves it to Postgres instead.
#
# Build context is the repository root.
#
# Reproducible: two builds of the same commit with scripts/release/build-image.sh give the same
# image digest (docs/REPRODUCIBLE_BUILDS.md). The pins below (base image digest, Debian snapshot,
# OpenTofu checksum, hashed Python locks) are the same as in backend/Dockerfile; bump them together.
#
# The digest is python:3.11.18-slim-trixie (the multi-platform index; amd64 is what we build).
FROM python:3.11-slim@sha256:65bd3d9f1d7fa268dd1909973ba7eb4bdf41f6dcf2cfbe76ba9528b170f3fd79

WORKDIR /app

ARG OPENTOFU_VERSION=1.8.6
# sha256 of tofu_<version>_linux_amd64.zip, from the release's tofu_<version>_SHA256SUMS.
ARG OPENTOFU_SHA256=4714768d1c502cd3a67ad8925cea44280e1c732ff005fcf1ee006530441cf667
# apt installs the packages as they were in the Debian archive at this moment
# (snapshot.debian.org), so their versions do not drift between builds.
ARG DEBIAN_SNAPSHOT=20261105T000000Z
# See backend/Dockerfile: set to the commit time by scripts/release/build-image.sh.
ARG SOURCE_DATE_EPOCH

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    APP_COMPONENT=api \
    MORROW_MAIN_DB_BACKEND=sqlite \
    ENABLE_INPROCESS_SCHEDULER=0 \
    PER_TARGET_TIMEOUT=20

COPY backend/requirements-bootstrap.lock backend/requirements.lock /app/
# Hash-locked installs and the cleanup of apt/dpkg build records: see backend/Dockerfile.
RUN apt-get -o APT::Snapshot="$DEBIAN_SNAPSHOT" update \
    && apt-get -o APT::Snapshot="$DEBIAN_SNAPSHOT" install -y --no-install-recommends curl unzip ca-certificates redis-server \
    && curl -fsSL "https://github.com/opentofu/opentofu/releases/download/v${OPENTOFU_VERSION}/tofu_${OPENTOFU_VERSION}_linux_amd64.zip" -o /tmp/tofu.zip \
    && echo "${OPENTOFU_SHA256}  /tmp/tofu.zip" | sha256sum -c - \
    && unzip /tmp/tofu.zip tofu -d /usr/local/bin \
    && rm -f /tmp/tofu.zip \
    && pip install --no-cache-dir --require-hashes --only-binary :all: --no-deps -r /app/requirements-bootstrap.lock \
    && pip install --no-cache-dir --require-hashes --only-binary :all: --no-deps -r /app/requirements.lock \
    && adduser --disabled-password --gecos "" --uid 1001 appuser \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*.bin /var/log/* /var/cache/ldconfig/aux-cache \
              /var/cache/debconf/*-old /var/lib/dpkg/*-old /etc/*-

COPY --chown=appuser:appuser backend/ /app/
COPY --chown=appuser:appuser deploy/render-hosted/start.sh /app/render-start.sh
# sed: a bundle built from a Windows checkout may carry CRLF line endings, which break sh.
RUN sed -i 's/\r$//' /app/entrypoint.sh /app/render-start.sh \
    && chmod +x /app/entrypoint.sh /app/render-start.sh \
    && mkdir -p /data \
    && chown appuser:appuser /data

# No USER line: start.sh runs as root only to hand the Render disk at /data to appuser, then
# drops to appuser for every process it starts.
# Trivy's DS-0002 (no USER line) is ignored for this file in .trivyignore.yaml for that reason.
EXPOSE 8000
ENTRYPOINT ["/app/render-start.sh"]
