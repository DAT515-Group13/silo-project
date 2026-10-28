#!/usr/bin/env bash
# Usage: scripts/restore-test.sh <dev|prod>
set -euo pipefail
NS="${1:?Usage: $0 <dev|prod>}"
command -v az >/dev/null || { echo "az CLI is missing" >&2; exit 1; }

CS="$(kubectl -n "$NS" get secret silo-azure -o jsonpath='{.data.AZURE_STORAGE_CONNECTION_STRING}' | base64 -d)"
LATEST="$(az storage blob list -c backups --connection-string "$CS" --query 'sort_by([], &properties.lastModified)[-1].name' -o tsv)"
echo "Restoring $LATEST"
az storage blob download -c backups -n "$LATEST" -f silo.dump --connection-string "$CS" --only-show-errors >/dev/null
unset CS

kubectl -n "$NS" cp silo.dump postgres-0:/tmp/silo.dump
kubectl -n "$NS" exec postgres-0 -- sh -c 'createdb -U "$POSTGRES_USER" silo_restore && pg_restore -U "$POSTGRES_USER" -d silo_restore --no-owner /tmp/silo.dump'

for t in users teams files share_links audit_log; do
  live=$(kubectl -n "$NS" exec postgres-0 -- sh -c "psql -U \"\$POSTGRES_USER\" -d \"\$POSTGRES_DB\" -tAc 'select count(*) from $t'")
  restored=$(kubectl -n "$NS" exec postgres-0 -- sh -c "psql -U \"\$POSTGRES_USER\" -d silo_restore -tAc 'select count(*) from $t'")
  echo "$t live=$live restored=$restored"
done

kubectl -n "$NS" exec postgres-0 -- sh -c 'dropdb -U "$POSTGRES_USER" silo_restore; rm /tmp/silo.dump'
rm silo.dump
