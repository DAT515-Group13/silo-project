#!/usr/bin/env bash
# Usage: scripts/run-db-tests.sh [namespace] [extra pytest args]
# Runs the db-marked tests against the PostgreSQL of a namespace (default: dev) through a
# quiet port-forward. The tests DROP the public schema of the database in TEST_DATABASE_URL,
# so this script only ever uses the database "silo_test", never "silo".
set -euo pipefail

NS="${1:-dev}"
shift || true
PORT="${PORT:-15432}"
LOG="$(mktemp)"

kubectl -n "$NS" port-forward pod/postgres-0 "${PORT}:5432" >"$LOG" 2>&1 &
PF_PID=$!
trap 'kill "$PF_PID" 2>/dev/null || true; rm -f "$LOG"' EXIT

for _ in $(seq 1 20); do
  grep -q "Forwarding from" "$LOG" && break
  sleep 0.5
done
grep -q "Forwarding from" "$LOG" || { echo "port-forward failed:" >&2; cat "$LOG" >&2; exit 1; }

PW="$(kubectl -n "$NS" get secret silo-db -o jsonpath='{.data.POSTGRES_PASSWORD}' | base64 -d)"
export TEST_DATABASE_URL="postgresql+asyncpg://silo:${PW}@127.0.0.1:${PORT}/silo_test"
unset PW

case "$TEST_DATABASE_URL" in
  */silo_test) ;;
  *) echo "refusing: database must be silo_test" >&2; exit 1 ;;
esac

# MARKERS unset: db tests only. MARKERS="": no marker filter (everything). Or any marker expression.
ARGS=()
if [ -n "${MARKERS-db and not azure}" ]; then
  ARGS=(-m "${MARKERS-db and not azure}")
fi
uv run pytest -q ${ARGS[@]+"${ARGS[@]}"} "$@"
