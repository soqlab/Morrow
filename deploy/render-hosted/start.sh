#!/bin/sh
# Starts Redis, the Celery worker (with beat embedded) and the API in one container.
# See deploy/render-hosted/Dockerfile for why they share a container.
set -eu

# Render mounts the disk owned by root; everything below runs as appuser.
chown -R appuser:appuser /data
AS_APP="setpriv --reuid=appuser --regid=appuser --init-groups"

# Redis is the Celery queue only and listens on localhost. Nothing durable lives in it: scan
# results are written to the database, so a restart loses at most the jobs still queued.
# Its password is generated here on every start, as hex: it goes into redis:// URLs, where a
# "/" or "+" (as in Render's generated values) breaks parsing, and nothing outside needs it.
REDIS_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export REDIS_PASSWORD
$AS_APP redis-server --bind 127.0.0.1 --port 6379 --requirepass "$REDIS_PASSWORD" \
  --dir /tmp --save "" --appendonly no --maxmemory 64mb --maxmemory-policy noeviction \
  --daemonize yes --logfile /tmp/redis.log
export CELERY_BROKER_URL="redis://:${REDIS_PASSWORD}@127.0.0.1:6379/0"
export CELERY_RESULT_BACKEND="redis://:${REDIS_PASSWORD}@127.0.0.1:6379/1"

# On Postgres, schema first, as its own step: a failed migration stops the deploy before the API
# serves. SQLite needs no step: the application creates and upgrades its own schema at start.
if [ "${MORROW_MAIN_DB_BACKEND:-sqlite}" = "postgres" ]; then
  $AS_APP env APP_COMPONENT=migrate /app/entrypoint.sh
fi

# One worker process (solo pool) with beat embedded keeps memory inside the 512 MB plan.
# Restarted if it exits, so a crashed worker does not silently leave the queue undrained.
(
  while :; do
    $AS_APP celery -A tasks.celery_app worker -B --pool=solo \
      --loglevel "${CELERY_LOGLEVEL:-INFO}" --schedule /data/celerybeat-schedule || true
    echo "[render-start] Celery worker exited; restarting in 5 s" >&2
    sleep 5
  done
) &

exec $AS_APP env APP_COMPONENT=api /app/entrypoint.sh
