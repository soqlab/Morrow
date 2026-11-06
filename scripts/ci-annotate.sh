#!/usr/bin/env bash
# Run one CI command and, if it fails, repeat the end of its output as ::error annotations.
#
# A job log on GitHub is readable only when signed in; annotations show on the public checks
# list. Usage: scripts/ci-annotate.sh <title> <command> [args...]
set -u
title="$1"; shift
log="$(mktemp)"
"$@" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
if [ "$status" -ne 0 ]; then
  # The last lines that look like an error, else simply the last lines.
  lines="$(grep -E 'Error|error|FAIL|assert|Timeout|timed out' "$log" | tail -n 8)"
  [ -n "$lines" ] || lines="$(tail -n 8 "$log")"
  printf '%s\n' "$lines" | cut -c1-900 | sed "s/^/::error title=${title}::/"
  echo "::error title=${title}::exited with status ${status}"
fi
rm -f "$log"
exit "$status"
