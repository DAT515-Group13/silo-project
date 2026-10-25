#!/usr/bin/env bash
# Usage: scripts/k8s-create-app-secret.sh <dev|staging|prod>
# Creates silo-app (DATABASE_URL, JWT_SECRET, CSRF_SECRET, INITIAL_ADMIN_PASSWORD).
# Skips if it exists, so a re-run never logs users out or changes the admin password.
# The admin password is written to $SECRETS_DIR/admin-<env>.txt (mode 600), never printed.
set -euo pipefail

ENV_NAME="${1:?Usage: $0 <dev|staging|prod>}"
case "$ENV_NAME" in
  dev|staging|prod) ;;
  *) echo "Environment must be dev, staging, or prod." >&2; exit 1 ;;
esac

SECRETS_DIR="${SECRETS_DIR:-$HOME/silo-secrets}"

if kubectl -n "$ENV_NAME" get secret silo-app >/dev/null 2>&1; then
  echo "silo-app already exists in $ENV_NAME, skipping."
  exit 0
fi
kubectl -n "$ENV_NAME" get secret silo-db >/dev/null 2>&1 || {
  echo "silo-db is missing in $ENV_NAME. Run scripts/k8s-create-db-secret.sh first." >&2
  exit 1
}

db_get() { kubectl -n "$ENV_NAME" get secret silo-db -o "jsonpath={.data.$1}" | base64 -d; }
DB_USER="$(db_get POSTGRES_USER)"
DB_NAME="$(db_get POSTGRES_DB)"
DB_PASS="$(db_get POSTGRES_PASSWORD)"

ADMIN_PASSWORD="$(openssl rand -base64 24 | tr -d '/+=\n')"

umask 077
mkdir -p "$SECRETS_DIR"
printf '%s\n' "$ADMIN_PASSWORD" > "$SECRETS_DIR/admin-$ENV_NAME.txt"

TMP_FILE="$(mktemp)"
trap 'rm -f "$TMP_FILE"' EXIT
{
  printf 'DATABASE_URL=postgresql+asyncpg://%s:%s@postgres:5432/%s\n' "$DB_USER" "$DB_PASS" "$DB_NAME"
  printf 'JWT_SECRET=%s\n' "$(openssl rand -base64 48 | tr -d '\n')"
  printf 'CSRF_SECRET=%s\n' "$(openssl rand -base64 48 | tr -d '\n')"
  printf 'INITIAL_ADMIN_PASSWORD=%s\n' "$ADMIN_PASSWORD"
} > "$TMP_FILE"

kubectl -n "$ENV_NAME" create secret generic silo-app --from-env-file="$TMP_FILE"
echo "Created silo-app in $ENV_NAME. Admin password: $SECRETS_DIR/admin-$ENV_NAME.txt"
