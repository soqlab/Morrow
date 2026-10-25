#!/bin/sh
set -eu

# Helper: abort with a clear error if a required env var is missing
_require_env() {
  var_name="$1"
  eval "var_val=\${${var_name}:-}"
  if [ -z "$var_val" ]; then
    echo "FATAL: Required environment variable ${var_name} is not set." >&2
    exit 1
  fi
}

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

component="${APP_COMPONENT:-api}"
is_production=0
case "${MORROW_ENVIRONMENT:-}" in
  production|prod) is_production=1 ;;
esac
if [ "${PRODUCTION_ENVIRONMENT:-false}" = "true" ]; then is_production=1; fi

# Optional auto-migration before starting the API.
#
# The Alembic revisions target Postgres, and alembic/env.py falls back to the
# placeholder URL in alembic.ini (postgresql://unused:unused@localhost/unused) when
# neither MORROW_PRODUCT_DATABASE_URL nor DATABASE_URL is set. On a SQLite deployment
# that fallback means AUTO_MIGRATE=1 tried to reach Postgres on localhost:5432 and
# the container died in a restart loop before serving once -- which is exactly what
# a newcomer hit running the quick-start compose file. SQLite needs no migrations:
# db.init_db() creates the schema at import time. So skip rather than fail.
if [ "${AUTO_MIGRATE:-0}" = "1" ]; then
  if [ -z "${MORROW_PRODUCT_DATABASE_URL:-}" ] && [ -z "${DATABASE_URL:-}" ]; then
    echo "[entrypoint] AUTO_MIGRATE=1 but no database URL is set; the application bootstraps its own SQLite schema, so skipping Alembic." >&2
  else
    echo "[entrypoint] Running database migrations..."
    alembic -c "${ALEMBIC_CONFIG:-/app/alembic.ini}" upgrade "${ALEMBIC_REVISION:-head}"
    echo "[entrypoint] Migrations complete."
  fi
fi

case "$component" in
api)
  if [ -z "${MORROW_AUTH_JWT_SECRET:-}" ]; then
    if [ "$is_production" = "1" ]; then
      export MORROW_AUTH_ISSUER_ENABLED="${MORROW_AUTH_ISSUER_ENABLED:-0}"
      case "${MORROW_AUTH_ISSUER_ENABLED}" in
        1|true|yes|on)
          echo "FATAL: MORROW_AUTH_JWT_SECRET is required when MORROW_AUTH_ISSUER_ENABLED=1 in production." >&2
          exit 1
          ;;
      esac
      echo "[entrypoint] Production mode with external JWT verification; built-in password issuer is disabled." >&2
    else
      _generated_secret=$(python3 -c "import secrets; print(secrets.token_hex(32))")
      export MORROW_AUTH_JWT_SECRET="$_generated_secret"
      echo "[entrypoint] WARNING: MORROW_AUTH_JWT_SECRET not set; generated an ephemeral key. Tokens will not survive restarts." >&2
    fi
  fi

  # Production pre-flight: abort on missing critical secrets.
  #
  # Gate on MORROW_ENVIRONMENT, which is what app.py actually reads. This block previously tested
  # PRODUCTION_ENVIRONMENT=true, a name nothing in the application sets, so the pre-flight checks
  # never ran on any deployment. The legacy name is still accepted so an existing environment that
  # sets it does not silently lose the checks.
  if [ "$is_production" = "1" ]; then
    echo "[entrypoint] Production mode — running pre-flight checks..."
    _require_env DATABASE_URL
    _require_env CELERY_BROKER_URL
    _require_env CELERY_RESULT_BACKEND
    _require_env MORROW_VAULT_MASTER_KEY
    _require_env MORROW_PLATFORM_ADMIN_KEY
    _require_env MORROW_CORS_ORIGINS
    _require_env MORROW_ALLOWED_HOSTS
    _require_env MORROW_AIRLOCK_SIGNING_KEY
    _require_env MORROW_AIRLOCK_REQUIRE_AGENT_SIGNATURE
    case "${MORROW_AIRLOCK_REQUIRE_AGENT_SIGNATURE}" in
      1|true|yes|on) ;;
      *)
        echo "FATAL: MORROW_AIRLOCK_REQUIRE_AGENT_SIGNATURE must be 1 in production." >&2
        exit 1
        ;;
    esac
    # MORROW_-prefixed: the unprefixed AUTH_JWT_* names are not read by the application, so requiring
    # them rejected correctly-configured deployments and admitted misconfigured ones.
    _require_env MORROW_AUTH_JWT_ISSUER
    _require_env MORROW_AUTH_JWT_AUDIENCE
    _require_env MORROW_AUTH_JWT_JWKS_URL
    # No external AI credential is required: AI-off is a supported deployment.
    # Per-tenant approval and destination validation happen at model dispatch.
    echo "[entrypoint] Pre-flight checks passed."
  fi
  exec uvicorn app:app --host "${HOST:-0.0.0.0}" --port "${PORT:-8000}"
  ;;
worker)
  exec celery -A tasks.celery_app worker \
    --loglevel "${CELERY_LOGLEVEL:-INFO}" \
    --concurrency "${CELERY_CONCURRENCY:-4}"
  ;;
beat)
  exec celery -A tasks.celery_app beat \
    --loglevel "${CELERY_LOGLEVEL:-INFO}" \
    --schedule "${BEAT_SCHEDULE_PATH:-/tmp/celerybeat-schedule}"
  ;;
migrate)
  # Run with the Postgres owner/migration role, not the least-privilege runtime role.
  #
  # Order matters. 0001_baseline is only a stamp -- the application owns schema bootstrap -- so the
  # later revisions assume the tables already exist. Running alembic first against an empty database
  # fails with `relation "collections" does not exist`.
  echo "[entrypoint] Bootstrapping core schema..."
  python3 -c "import db; db.init_db()"
  echo "[entrypoint] Applying Alembic revisions..."
  alembic -c "${ALEMBIC_CONFIG:-/app/alembic.ini}" upgrade "${ALEMBIC_REVISION:-head}"
  # Some features create their Postgres tables on first request instead of at startup. Create them
  # here too: a runtime role hardened for row-level security has no DDL rights, so otherwise those
  # tables would never come into existence and the endpoints would fail.
  echo "[entrypoint] Applying deferred feature schemas..."
  exec python3 -c "import json, sys, app, db_postgres; result = db_postgres.apply_deferred_schemas(); print('[entrypoint] deferred schemas: ' + json.dumps(result)); sys.exit(1 if result['failed'] else 0)"
  ;;
*)
  echo "Unknown APP_COMPONENT: $component" >&2
  exit 1
  ;;
esac
