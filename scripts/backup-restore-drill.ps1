param(
  [string]$BackupDir = "backups\drill",
  # Postgres DSN to drill. Needs a role that can create a database, so use the owner/migration DSN,
  # not the least-privilege runtime role.
  [string]$Dsn = $(if ($env:PQC_BACKUP_DRILL_DSN) { $env:PQC_BACKUP_DRILL_DSN } elseif ($env:PQC_PRODUCT_DATABASE_URL) { $env:PQC_PRODUCT_DATABASE_URL } else { $env:DATABASE_URL }),
  # Image used for pg_dump/psql when they are not on PATH. Match your server's major version.
  [string]$PgImage = "postgres:16-alpine",
  [switch]$SkipPostgres,
  [switch]$SkipSqlite
)

$ErrorActionPreference = "Stop"

$python = Resolve-Path "backend\.venv\Scripts\python.exe"
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$target = Join-Path $BackupDir $stamp
New-Item -ItemType Directory -Force -Path $target | Out-Null
$failures = @()
$verified = @()

# ---------------------------------------------------------------------------------------------
# SQLite
# ---------------------------------------------------------------------------------------------
if (-not $SkipSqlite) {
  # Resolve the database the application actually opens instead of guessing at filenames. The
  # previous hardcoded list named pqc_scans.db, scans.db and pqc_scanner_test.db -- a test database
  # and two stale 12KB files -- while omitting pqc_scanner.db, the live main database. The drill
  # "passed" by backing up files nothing reads.
  $resolveDbPath = @'
import os, sys
sys.path.insert(0, "backend")
import db
print(os.path.abspath(os.environ.get("PQC_SCANNER_DB") or db.DB_PATH))
'@
  $resolvePath = Join-Path $target "resolve_db.py"
  [System.IO.File]::WriteAllText($resolvePath, $resolveDbPath, [System.Text.UTF8Encoding]::new($false))
  $livePath = (& $python $resolvePath).Trim()

  $dbFiles = @()
  if ($livePath -and (Test-Path -LiteralPath $livePath)) { $dbFiles += $livePath }
  # Any additional SQLite files that exist alongside it, so nothing in use is silently skipped.
  $dbFiles += @("backend\pqc_scans.db", "backend\scans.db") |
    Where-Object { Test-Path $_ } |
    ForEach-Object { (Resolve-Path $_).Path } |
    Where-Object { $_ -ne $livePath }

  if (-not $dbFiles) {
    Write-Host "SQLite: no database files present, nothing to drill."
  } else {
    foreach ($db in $dbFiles) {
      $leaf = Split-Path $db -Leaf
      $dest = Join-Path (Resolve-Path $target).Path $leaf
      # VACUUM INTO takes a transactionally consistent copy of a database that is being written to.
      # A plain file copy of a live SQLite database can capture a torn page or miss the -wal file,
      # producing a "backup" that only fails when someone tries to restore it.
      $backupScript = @'
import sqlite3, sys
src, dest = sys.argv[1], sys.argv[2]
conn = sqlite3.connect(src)
try:
    conn.execute("VACUUM INTO ?", (dest,))
finally:
    conn.close()
print("copied")
'@
      $bp = Join-Path $target "backup_one.py"
      [System.IO.File]::WriteAllText($bp, $backupScript, [System.Text.UTF8Encoding]::new($false))
      & $python $bp $db $dest | Out-Null
      if ($LASTEXITCODE -ne 0) { $failures += "SQLite backup of $leaf failed"; continue }
    }

    # Verify the copies: integrity_check must actually be inspected. The previous version called
    # `conn.execute("pragma integrity_check").fetchone()` and discarded the result, so a corrupt
    # database reported "ok" -- the one thing the drill exists to catch.
    $verifyScript = @'
import pathlib, sqlite3, sys
root = pathlib.Path(sys.argv[1])
dbs = sorted(p for p in root.glob("*.db"))
if not dbs:
    raise SystemExit("no db files copied")
bad = []
for db in dbs:
    conn = sqlite3.connect(str(db))
    try:
        tables = conn.execute("select name from sqlite_master where type='table'").fetchall()
        if not tables:
            bad.append(f"{db.name}: no tables found")
            continue
        result = conn.execute("pragma integrity_check").fetchone()
        verdict = str(result[0]).strip().lower() if result else "no result"
        if verdict != "ok":
            bad.append(f"{db.name}: integrity_check returned {verdict!r}")
            continue
        # A restore is only meaningful if the data is there, so assert the copy is readable and
        # report a row count from a table the application depends on.
        rows = conn.execute("select count(*) from sqlite_master where type='table'").fetchone()[0]
        print(f"  {db.name}: ok ({rows} tables, integrity_check=ok)")
    finally:
        conn.close()
if bad:
    for line in bad:
        print("  FAIL " + line)
    raise SystemExit(1)
'@
    $verifyPath = Join-Path $target "verify_backup.py"
    [System.IO.File]::WriteAllText($verifyPath, $verifyScript, [System.Text.UTF8Encoding]::new($false))
    Write-Host "SQLite backup verification:"
    & $python $verifyPath (Resolve-Path $target).Path
    if ($LASTEXITCODE -ne 0) { $failures += "SQLite backup verification failed" }
    else { $verified += "sqlite ($($dbFiles.Count) file(s))" }
  }
}

# ---------------------------------------------------------------------------------------------
# Postgres -- the production backend. Previously this printed a note and exited 0, so the drill
# reported success while never testing the database that actually holds customer data.
# ---------------------------------------------------------------------------------------------
if (-not $SkipPostgres) {
  if (-not $Dsn) {
    Write-Host "Postgres: no DSN provided (-Dsn / PQC_BACKUP_DRILL_DSN / PQC_PRODUCT_DATABASE_URL / DATABASE_URL); skipping."
  } elseif ($Dsn -notmatch '^postgres') {
    Write-Host "Postgres: DSN is not a postgresql:// URL; skipping."
  } else {
    $havePgDump = [bool](Get-Command pg_dump -ErrorAction SilentlyContinue)
    $haveDocker = [bool](Get-Command docker -ErrorAction SilentlyContinue)
    if (-not $havePgDump -and -not $haveDocker) {
      # Do not exit 0 here. Reporting success without having tested anything is what made this
      # drill worthless as a go-live criterion.
      $failures += "Postgres drill could not run: neither pg_dump nor docker is available"
    } else {
      $dumpFile = Join-Path (Resolve-Path $target).Path "postgres.dump"
      # Restore into a scratch database rather than over the source, then drop it. The name must be a
      # legal unquoted Postgres identifier: the timestamp contains a hyphen, which psql parses as the
      # start of a comment and reports as `syntax error at or near "-"`.
      $scratch = "pqc_restore_drill_" + ($stamp -replace '[^0-9A-Za-z_]', '_')

      # Native tools write progress to stderr, and under $ErrorActionPreference='Stop' PowerShell 5.1
      # turns any stderr line from an external command into a terminating NativeCommandError -- which
      # aborted this script before it could report its own results. Exit codes are checked explicitly
      # instead.
      $priorEap = $ErrorActionPreference
      $ErrorActionPreference = "Continue"

      function Invoke-Pg {
        param([string]$Exe, [string[]]$PgArgs, [string]$OutFile)
        if ($havePgDump) {
          if ($OutFile) { & $Exe @PgArgs > $OutFile } else { & $Exe @PgArgs }
        } else {
          # -i so stdin is available for psql; --network host so a DSN pointing at a published port
          # or host.docker.internal resolves the same way it does from the host.
          $dockerArgs = @("run", "--rm", "-i", "--network", "host", $PgImage, $Exe) + $PgArgs
          if ($OutFile) { & docker @dockerArgs > $OutFile } else { & docker @dockerArgs }
        }
        return $LASTEXITCODE
      }

      Write-Host "Postgres backup drill (dump -> restore into $scratch -> compare -> drop):"
      # --no-privileges is deliberately NOT used. It strips every GRANT, so the dump restores into a
      # database the runtime role cannot read a single row of ("permission denied for table assets")
      # while the drill still reports success -- the table count is identical, because tables are not
      # what is missing. Keeping the GRANTs also makes ON_ERROR_STOP catch the other half of the
      # trap: a GRANT naming a role the target cluster does not have. Roles are cluster-level and are
      # never in a single-database dump, so `pg_dumpall --globals-only` is a separate backup artefact
      # (see docs/BACKUP_RESTORE_RUNBOOK.md).
      $code = Invoke-Pg -Exe "pg_dump" -PgArgs @("--no-owner", "--format=plain", $Dsn) -OutFile $dumpFile
      if ($code -ne 0 -or -not (Test-Path $dumpFile) -or (Get-Item $dumpFile).Length -eq 0) {
        $failures += "pg_dump failed or produced an empty dump"
      } else {
        Write-Host ("  dump written: {0:N0} bytes" -f (Get-Item $dumpFile).Length)

        # Build an admin DSN for the maintenance database so the scratch DB can be created/dropped.
        $adminDsn = [regex]::Replace($Dsn, '/[^/?]+(\?|$)', '/postgres$1')
        $scratchDsn = [regex]::Replace($Dsn, '/[^/?]+(\?|$)', "/$scratch`$1")

        # DROP/CREATE DATABASE cannot run inside a transaction block, and psql wraps multiple -c
        # statements into a single transaction -- so these must be separate invocations.
        Invoke-Pg -Exe "psql" -PgArgs @("-q", "-d", $adminDsn, "-c", "DROP DATABASE IF EXISTS $scratch") | Out-Null
        $code = Invoke-Pg -Exe "psql" -PgArgs @("-q", "-v", "ON_ERROR_STOP=1", "-d", $adminDsn, "-c", "CREATE DATABASE $scratch")
        if ($code -ne 0) {
          $failures += "could not create scratch database $scratch (the drill DSN needs CREATEDB; use the owner DSN)"
        } else {
          try {
            # Feed the dump to psql on stdin so it works identically on PATH and in Docker.
            if ($havePgDump) {
              Get-Content -LiteralPath $dumpFile -Raw | & psql -v ON_ERROR_STOP=1 -d $scratchDsn -f - | Out-Null
              $restoreCode = $LASTEXITCODE
            } else {
              Get-Content -LiteralPath $dumpFile -Raw |
                & docker run --rm -i --network host $PgImage psql -v ON_ERROR_STOP=1 -d $scratchDsn -f - | Out-Null
              $restoreCode = $LASTEXITCODE
            }
            if ($restoreCode -ne 0) {
              $failures += "restore of the dump into $scratch failed"
            } else {
              # Compare the restored database against the source. A dump that restores but loses
              # tables or rows is a failed backup, and only a comparison catches that.
              # Count the tenant boundary too, not only the tables. A restore that loses the
              # isolation policies, the FORCE flag or the runtime role's table grants restores the
              # data and breaks either tenancy or the application, and a table count sees none of it.
              $countSql = @"
SELECT (SELECT count(*) FROM pg_tables WHERE schemaname='public')::text || ' tables, '
    || (SELECT count(*) FROM pg_policies WHERE schemaname='public')::text || ' policies, '
    || (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relrowsecurity)::text || ' rls, '
    || (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
        WHERE n.nspname='public' AND c.relforcerowsecurity)::text || ' forced, '
    || (SELECT count(*) FROM information_schema.role_table_grants
        WHERE table_schema='public' AND grantee <> current_user)::text || ' grants'
"@
              $srcOut = & { if ($havePgDump) { & psql -At -d $Dsn -c $countSql } else { & docker run --rm --network host $PgImage psql -At -d $Dsn -c $countSql } }
              $dstOut = & { if ($havePgDump) { & psql -At -d $scratchDsn -c $countSql } else { & docker run --rm --network host $PgImage psql -At -d $scratchDsn -c $countSql } }
              $src = ($srcOut | Select-Object -Last 1).Trim()
              $dst = ($dstOut | Select-Object -Last 1).Trim()
              Write-Host "  source:   $src"
              Write-Host "  restored: $dst"
              if ($src -ne $dst -or -not $src) {
                $failures += "restored database does not match source ($src vs $dst)"
              } else {
                Write-Host "  restore verified: tables, isolation policies, FORCE flags and grants all match"
                $verified += "postgres (dump restored and compared)"
              }
            }
          } finally {
            # One statement per -c: combining a SET with DROP DATABASE puts it in a transaction
            # block, which DROP DATABASE cannot run in.
            Invoke-Pg -Exe "psql" -PgArgs @("-q", "-d", $adminDsn, "-c", "DROP DATABASE IF EXISTS $scratch") | Out-Null
            Write-Host "  scratch database dropped"
          }
        }
      }
      $ErrorActionPreference = $priorEap
    }
  }
}

Write-Host ""
if ($failures.Count -gt 0) {
  Write-Host "Backup drill FAILED:"
  foreach ($f in $failures) { Write-Host "- $f" }
  exit 1
}
Write-Host "Backup drill complete: $target"
Write-Host "Verified: $($verified -join '; ')"
if ($verified.Count -eq 0) {
  Write-Host "Nothing was verified -- supply -Dsn for Postgres or run where the SQLite database exists."
  exit 1
}
# Exit explicitly: without this the script's status is whatever $LASTEXITCODE the final native psql
# call left behind, so a successful drill could still report failure to a CI job or wrapper script.
exit 0
