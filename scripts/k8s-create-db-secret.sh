#!/usr/bin/env bash
# Usage: scripts/k8s-create-db-secret.sh <dev|staging|prod>
# Creates the silo-db Secret with a random password. Skips if it already exists,
# so a re-run never changes the password under a running database.
set -euo pipefail

ENV_NAME="${1:?Usage: $0 <dev|staging|prod>}"

case "$ENV_NAME" in
  dev|staging|prod) ;;
  *)
    echo "Environment must be dev, staging, or prod." >&2
    exit 1
    ;;
esac

if kubectl -n "$ENV_NAME" get secret silo-db >/dev/null 2>&1; then
  echo "silo-db already exists in $ENV_NAME, skipping."
  exit 0
fi

kubectl -n "$ENV_NAME" create secret generic silo-db \
  --from-literal=POSTGRES_USER=silo \
  --from-literal=POSTGRES_DB=silo \
  --from-literal=POSTGRES_PASSWORD="$(openssl rand -base64 24 | tr -d '/+=\n')"
echo "Created silo-db in $ENV_NAME."