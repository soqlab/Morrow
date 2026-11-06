# API image: ghcr.io/soqlab/morrow:<version>-api (docker-compose.prod.yml).
#
# Reproducible: two builds of the same commit with scripts/release/build-image.sh give the same
# image digest (docs/REPRODUCIBLE_BUILDS.md). Everything that would otherwise change between
# builds is pinned here: the base image by digest, Debian packages through a fixed
# snapshot.debian.org timestamp, OpenTofu by checksum, and every Python package by hash
# (requirements*.lock). Bump them together with deploy/render-hosted/Dockerfile.
#
# The digest is python:3.11.18-slim-trixie (the multi-platform index; amd64 is what we build).
FROM python:3.11-slim@sha256:65bd3d9f1d7fa268dd1909973ba7eb4bdf41f6dcf2cfbe76ba9528b170f3fd79

WORKDIR /app

# OpenTofu, not Terraform: Terraform moved to the BUSL-1.1 licence, which is not open source and
# cannot be redistributed in a published image. OpenTofu is the MPL-2.0 fork and is CLI-compatible.
ARG OPENTOFU_VERSION=1.8.6
# sha256 of tofu_<version>_linux_amd64.zip, from the release's tofu_<version>_SHA256SUMS.
ARG OPENTOFU_SHA256=4714768d1c502cd3a67ad8925cea44280e1c732ff005fcf1ee006530441cf667
# apt installs the packages as they were in the Debian archive at this moment
# (snapshot.debian.org), so their versions do not drift between builds. Move it forward to pick
# up Debian security fixes.
ARG DEBIAN_SNAPSHOT=20261105T000000Z
ARG INSTALL_DEV_DEPS=false
# Set by scripts/release/build-image.sh to the commit time. useradd takes /etc/shadow's
# "last changed" day from it, and pip writes hash-based .pyc files instead of ones stamped with
# the build time. Unset (a plain `docker build`), both behave as they always did.
ARG SOURCE_DATE_EPOCH

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    APP_COMPONENT=api \
    MORROW_MAIN_DB_BACKEND=postgres \
    ENABLE_INPROCESS_SCHEDULER=0 \
    PER_TARGET_TIMEOUT=20

COPY requirements-bootstrap.lock requirements.lock requirements-dev.lock /app/

# --require-hashes --no-deps: pip installs exactly the files the lock names, nothing resolved at
# build time. --only-binary: no source builds, whose output depends on the build machine.
# The final rm removes what apt and dpkg record about the build itself (logs, caches, *-old
# backups); those carry the build time and would differ between two builds.
RUN apt-get -o APT::Snapshot="$DEBIAN_SNAPSHOT" update \
    && apt-get -o APT::Snapshot="$DEBIAN_SNAPSHOT" install -y --no-install-recommends curl unzip ca-certificates \
    && curl -fsSL "https://github.com/opentofu/opentofu/releases/download/v${OPENTOFU_VERSION}/tofu_${OPENTOFU_VERSION}_linux_amd64.zip" -o /tmp/tofu.zip \
    && echo "${OPENTOFU_SHA256}  /tmp/tofu.zip" | sha256sum -c - \
    && unzip /tmp/tofu.zip tofu -d /usr/local/bin \
    && rm -f /tmp/tofu.zip \
    && pip install --no-cache-dir --require-hashes --only-binary :all: --no-deps -r /app/requirements-bootstrap.lock \
    && pip install --no-cache-dir --require-hashes --only-binary :all: --no-deps -r /app/requirements.lock \
    && if [ "$INSTALL_DEV_DEPS" = "true" ]; then pip install --no-cache-dir --require-hashes --only-binary :all: --no-deps -r /app/requirements-dev.lock; fi \
    && adduser --disabled-password --gecos "" --uid 1001 appuser \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*.bin /var/log/* /var/cache/ldconfig/aux-cache \
              /var/cache/debconf/*-old /var/lib/dpkg/*-old /etc/*-

COPY --chown=appuser:appuser . /app

# /data holds the SQLite file for the features that are not yet on Postgres
# (db._default_db_path() prefers /data/morrow.db when the directory exists), and
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
