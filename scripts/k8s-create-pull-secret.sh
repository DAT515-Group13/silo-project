#!/usr/bin/env bash
# Usage: scripts/k8s-create-pull-secret.sh <github-user>
# Creates or updates ghcr-pull in dev, staging and prod. The token (read:packages)
# is typed in and never stored. Alternative: make the GHCR package public.
set -euo pipefail

GH_USER="${1:?Usage: $0 <github-user>}"
read -rs -p "GitHub token (read:packages): " GHCR_TOKEN; echo
trap 'unset GHCR_TOKEN' EXIT

for e in dev staging prod; do
  kubectl -n "$e" create secret docker-registry ghcr-pull \
    --docker-server=ghcr.io --docker-username="$GH_USER" \
    --docker-password="$GHCR_TOKEN" --dry-run=client -o yaml | kubectl apply -f -
done
