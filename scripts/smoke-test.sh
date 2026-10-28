#!/usr/bin/env bash
# Usage: scripts/smoke-test.sh <dev|staging|prod>
# End-to-end check of a deployed environment through Traefik, PostgreSQL and Azure Blob:
# health, admin login, register + approve a throwaway user, team, upload, download (same bytes),
# share, public link (works without login, stops after revoke). The throwaway user and
# everything it owns is deleted at the end, also when a step fails.
#
# Reads BASE_URL from the silo-config ConfigMap and the admin password from the silo-app
# Secret, so it needs kubectl access (the self-hosted runner or the admin box).
# Needs: kubectl, curl, jq, openssl, sha256sum.
set -euo pipefail

ENV_NAME="${1:?Usage: $0 <dev|staging|prod>}"
case "$ENV_NAME" in
  dev|staging|prod) ;;
  *) echo "Environment must be dev, staging, or prod." >&2; exit 1 ;;
esac

# The floating IP is not always reachable from inside the cloud network, so the request goes
# to a worker's internal IP while the host name (which Traefik routes on) stays the same.
NODE_IP="${NODE_IP:-172.16.0.248}"

BASE_URL="$(kubectl -n "$ENV_NAME" get configmap silo-config -o jsonpath='{.data.BASE_URL}')"
ADMIN_USER="$(kubectl -n "$ENV_NAME" get configmap silo-config -o jsonpath='{.data.INITIAL_ADMIN_USERNAME}')"
ADMIN_PASSWORD="$(kubectl -n "$ENV_NAME" get secret silo-app -o jsonpath='{.data.INITIAL_ADMIN_PASSWORD}' | base64 -d)"

hostport="${BASE_URL#https://}"; hostport="${hostport%%/*}"
host="${hostport%%:*}"; port="${hostport##*:}"
# -k: the certificate is self-signed. --resolve: see NODE_IP above.
CURL=(curl -sS -k --max-time 60 --resolve "$host:$port:$NODE_IP")

WORK="$(mktemp -d)"
USERNAME="smoke-$(date +%s)"
PASSWORD="$(openssl rand -hex 16)"
ADMIN_TOKEN=""
USER_ID=""

step() { printf '\n== %s\n' "$*"; }
fail() { echo "FAIL: $*" >&2; exit 1; }

# call METHOD PATH TOKEN [curl args...]: prints the body, stores the status in $WORK/status.
call() {
  local method="$1" path="$2" token="$3"; shift 3
  local auth=()
  [ -n "$token" ] && auth=(-H "Authorization: Bearer $token")
  "${CURL[@]}" -X "$method" "${auth[@]}" -o "$WORK/body" -w '%{http_code}' "$@" \
    "$BASE_URL$path" > "$WORK/status"
  cat "$WORK/body"
}
expect() {
  local want="$1" got; got="$(cat "$WORK/status")"
  [ "$got" = "$want" ] || fail "expected HTTP $want, got $got: $(head -c 300 "$WORK/body")"
}

cleanup() {
  local code=$?
  if [ -n "$USER_ID" ] && [ -n "$ADMIN_TOKEN" ]; then
    step "Cleanup: delete $USERNAME and everything it owns"
    call DELETE "/api/v1/admin/users/$USER_ID" "$ADMIN_TOKEN" >/dev/null || true
    echo "HTTP $(cat "$WORK/status")"
  fi
  rm -rf "$WORK"
  if [ "$code" -eq 0 ]; then echo; echo "SMOKE TEST PASSED ($ENV_NAME)"; else echo; echo "SMOKE TEST FAILED ($ENV_NAME)"; fi
}
trap cleanup EXIT

echo "Target: $BASE_URL (via $NODE_IP)"

step "1. Health and readiness"
call GET /healthz "" >/dev/null; expect 200
call GET /readyz "" >/dev/null; expect 200

step "2. Admin login"
ADMIN_TOKEN="$(call POST /api/v1/auth/login "" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg u "$ADMIN_USER" --arg p "$ADMIN_PASSWORD" '{username:$u,password:$p}')" \
  | jq -r .access_token)"
expect 200

step "3. Register $USERNAME (pending until approved)"
call POST /api/v1/auth/register "" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg u "$USERNAME" --arg p "$PASSWORD" '{username:$u,password:$p}')" >/dev/null
case "$(cat "$WORK/status")" in 201|202) ;; *) expect 202 ;; esac
USER_ID="$(call GET '/api/v1/admin/users?status=pending&size=100' "$ADMIN_TOKEN" \
  | jq -r --arg u "$USERNAME" '.items[] | select(.username==$u) | .id')"
expect 200
[ -n "$USER_ID" ] || fail "$USERNAME not found among pending users"

step "4. Admin approves and makes the user team_lead"
call POST "/api/v1/admin/users/$USER_ID/approve" "$ADMIN_TOKEN" >/dev/null; expect 204
call PATCH "/api/v1/admin/users/$USER_ID" "$ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"role":"team_lead"}' >/dev/null; expect 200

step "5. User login"
TOKEN="$(call POST /api/v1/auth/login "" -H 'Content-Type: application/json' \
  -d "$(jq -n --arg u "$USERNAME" --arg p "$PASSWORD" '{username:$u,password:$p}')" \
  | jq -r .access_token)"
expect 200

step "6. Create a team"
TEAM_ID="$(call POST /api/v1/teams "$TOKEN" -H 'Content-Type: application/json' \
  -d "{\"name\":\"$USERNAME-team\"}" | jq -r .id)"
expect 201

step "7. Upload a 1 MiB random file"
head -c 1048576 /dev/urandom > "$WORK/upload.bin"
want_sum="$(sha256sum < "$WORK/upload.bin" | cut -d' ' -f1)"
FILE_ID="$(call POST /api/v1/files "$TOKEN" -F "file=@$WORK/upload.bin;filename=smoke.bin" | jq -r .id)"
expect 201

step "8. Download (redirect to Azure) returns the same bytes"
call GET "/api/v1/files/$FILE_ID/download" "$TOKEN" >/dev/null; expect 302
sas_url="$("${CURL[@]}" -H "Authorization: Bearer $TOKEN" -o /dev/null -w '%{redirect_url}' \
  "$BASE_URL/api/v1/files/$FILE_ID/download")"
curl -sS --max-time 60 -o "$WORK/download.bin" "$sas_url"
[ "$(sha256sum < "$WORK/download.bin" | cut -d' ' -f1)" = "$want_sum" ] || fail "downloaded bytes differ"
echo "sha256 matches"

step "9. Share with the team"
call PUT "/api/v1/files/$FILE_ID/teams/$TEAM_ID" "$TOKEN" >/dev/null; expect 204
call GET "/api/v1/files/$FILE_ID/teams" "$TOKEN" | jq -e --argjson t "$TEAM_ID" 'any(.[]; .id==$t)' >/dev/null \
  || fail "team $TEAM_ID not listed on the file"

step "10. Public link works without login"
link_json="$(call POST "/api/v1/files/$FILE_ID/links" "$TOKEN" -H 'Content-Type: application/json' \
  -d '{"expires_in_hours":1}')"
expect 201
LINK_ID="$(jq -r .id <<<"$link_json")"; LINK_URL="$(jq -r .url <<<"$link_json")"
code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$LINK_URL")"
[ "$code" = 302 ] || fail "public link gave HTTP $code, expected 302"

step "11. Revoked link stops working"
call DELETE "/api/v1/links/$LINK_ID" "$TOKEN" >/dev/null; expect 204
code="$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$LINK_URL")"
[ "$code" = 404 ] || fail "revoked link gave HTTP $code, expected 404"
