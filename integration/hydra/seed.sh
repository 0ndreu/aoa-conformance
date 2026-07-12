#!/bin/sh
# Seeds OAuth2 clients into Ory Hydra via the admin REST API.
# Run by the hydra-init one-shot container after Hydra is up.
set -eu

ADMIN="${HYDRA_ADMIN_URL:-http://hydra:4445}"

echo "waiting for hydra admin at $ADMIN ..."
until curl -fsS "$ADMIN/health/ready" >/dev/null 2>&1; do
  sleep 1
done
echo "hydra admin ready"

# create_client BODY: idempotent, skips if the client_id already exists.
create_client() {
  body="$1"
  cid=$(printf '%s' "$body" | sed -n 's/.*"client_id"[ ]*:[ ]*"\([^"]*\)".*/\1/p')
  [ -n "$cid" ] || { echo "ERROR: could not extract client_id from body" >&2; exit 1; }
  if curl -fsS "$ADMIN/admin/clients/$cid" >/dev/null 2>&1; then
    echo "client $cid already exists, skipping"
    return 0
  fi
  curl -fsS -X POST "$ADMIN/admin/clients" \
    -H 'Content-Type: application/json' \
    -d "$body" >/dev/null
  echo "created client $cid"
}

# confidential client used for --client-id/--client-secret runs and --auth-code.
# loopback redirect URIs use the IP literal so Hydra (RFC 8252) accepts aoa-conform's
# dynamic callback port (http://127.0.0.1:<random>/callback).
create_client '{
  "client_id": "mcp-conform",
  "client_secret": "conform-secret",
  "grant_types": ["authorization_code", "client_credentials", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid offline_access mcp:read",
  "audience": ["mcp-api"],
  "redirect_uris": ["http://127.0.0.1/callback", "http://[::1]/callback"],
  "token_endpoint_auth_method": "client_secret_post"
}'

echo "seeding complete"
