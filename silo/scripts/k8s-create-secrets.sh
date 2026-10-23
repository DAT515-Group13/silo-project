#!/usr/bin/env bash
set -euo pipefail

ENV_NAME="${1:?Usage: $0 <dev|staging|prod>}"

case "$ENV_NAME" in
  dev|staging|prod) ;;
  *)
    echo "Environment must be dev, staging, or prod." >&2
    exit 1
    ;;
esac

SECRETS_DIR="${SECRETS_DIR:-$HOME/silo-secrets}"
FILE="$SECRETS_DIR/azure-$ENV_NAME.env"

if [[ ! -f "$FILE" ]]; then
  echo "Missing secret file: $FILE" >&2
  exit 1
fi

# Load the shell-escaped connection string created by azure-setup.sh.
set -a
source "$FILE"
set +a

if [[ -z "${AZURE_STORAGE_CONNECTION_STRING:-}" ]]; then
  echo "Connection string is missing from $FILE" >&2
  exit 1
fi

# Kubernetes dotenv files require the literal value, not shell escapes.
TMP_FILE="$(mktemp)"
chmod 600 "$TMP_FILE"
trap 'rm -f "$TMP_FILE"; unset AZURE_STORAGE_CONNECTION_STRING' EXIT

printf 'AZURE_STORAGE_CONNECTION_STRING=%s\n' \
  "$AZURE_STORAGE_CONNECTION_STRING" > "$TMP_FILE"

kubectl -n "$ENV_NAME" create secret generic silo-azure \
  --from-env-file="$TMP_FILE" \
  --dry-run=client -o yaml |
  kubectl apply -f -

unset AZURE_STORAGE_CONNECTION_STRING