#!/usr/bin/env bash
# Nightly backup of everything that cannot be rebuilt from the repository.
#
#   pg-<stamp>.sql.gz        the Postgres database: tenants, scans, findings, evidence, billing
#   sqlite-<stamp>.db.gz     the feature store, for the features not yet on Postgres -- which
#                            includes the public registry, trial requests and the opt-out list
#   env-<stamp>.gpg          .env.prod, encrypted, only when BACKUP_GPG_RECIPIENT is set
#
# Schedule it:
#   ( crontab -l 2>/dev/null; echo "15 3 * * * cd /srv/morrow && ./deploy/single-host/backup.sh >> backups/backup.log 2>&1" ) | crontab -
#
# Then restore it once, onto a scratch host, before anything depends on it.
set -euo pipefail

cd "$(dirname "$0")/../.."
ENV_FILE="${ENV_FILE:-.env.prod}"
[ -f "$ENV_FILE" ] && set -a && . "./$ENV_FILE" && set +a

COMPOSE="docker compose -f docker-compose.prod.yml -f deploy/single-host/compose.yml --env-file $ENV_FILE"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${PWD}/backups"
KEEP_DAYS="${BACKUP_KEEP_DAYS:-14}"
mkdir -p "$OUT"

echo "[$(date -u +%FT%TZ)] backup $STAMP starting"

# --clean --if-exists so the dump can be restored over an existing database without hand-editing.
$COMPOSE exec -T db pg_dump -U "${POSTGRES_USER:-pqc}" -d "${POSTGRES_DB:-pqc}" --clean --if-exists \
	| gzip -9 > "${OUT}/pg-${STAMP}.sql.gz"
gzip -t "${OUT}/pg-${STAMP}.sql.gz"

# The SQLite feature store is a live file, so it is copied with sqlite3's own backup rather than
# cp: copying the file while a write is in flight produces an archive that restores to a corrupt
# database, and you find out at the worst possible moment.
if $COMPOSE exec -T api sh -c 'test -f /data/pqc_scanner.db'; then
	$COMPOSE exec -T api sh -c \
		'sqlite3 /data/pqc_scanner.db ".backup /tmp/backup.db" && gzip -9 -c /tmp/backup.db && rm -f /tmp/backup.db' \
		> "${OUT}/sqlite-${STAMP}.db.gz"
	gzip -t "${OUT}/sqlite-${STAMP}.db.gz"
else
	echo "note: no /data/pqc_scanner.db in the api container -- nothing to back up there"
fi

# .env.prod holds the keys that decrypt everything else, so a backup of the database without it is
# a backup of ciphertext. Encrypted, because an unencrypted copy of it in a backup directory is
# worse than no copy.
if [ -n "${BACKUP_GPG_RECIPIENT:-}" ] && [ -f "$ENV_FILE" ]; then
	gpg --batch --yes --encrypt --recipient "$BACKUP_GPG_RECIPIENT" \
		--output "${OUT}/env-${STAMP}.gpg" "$ENV_FILE"
else
	echo "WARNING: BACKUP_GPG_RECIPIENT is not set, so $ENV_FILE is not in this backup."
	echo "         PQC_VAULT_MASTER_KEY is in that file. Without it a restored database"
	echo "         cannot decrypt stored credentials. Keep a copy somewhere else, by hand."
fi

sha256sum "${OUT}"/*-"${STAMP}".* > "${OUT}/sha256-${STAMP}.txt"

if [ -n "${BACKUP_REMOTE:-}" ]; then
	# Offsite matters more than local: a local backup dies with the disk it sits on.
	rclone copy "$OUT" "${BACKUP_REMOTE}/" --include "*-${STAMP}.*"
	rclone delete "${BACKUP_REMOTE}/" --min-age "${KEEP_DAYS}d"
fi

# Only after the new copy exists and verified, so a failed run never leaves you with nothing.
find "$OUT" -maxdepth 1 -type f \( -name 'pg-*.sql.gz' -o -name 'sqlite-*.db.gz' \
	-o -name 'env-*.gpg' -o -name 'sha256-*.txt' \) -mtime "+${KEEP_DAYS}" -delete

echo "[$(date -u +%FT%TZ)] backup $STAMP done: $(du -sh "$OUT" | cut -f1) on disk"
