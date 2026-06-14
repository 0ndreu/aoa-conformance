# aoa-guarded MCP server (conformance target)

A real MCP server (two tools) behind `aoa` OAuth middleware, delegating to a
configurable provider. Use it as a live `aoa-conform` target.

## Layout
- `config.yaml` — server + provider profiles (Keycloak active by default).
- `main.go` — loads config, discovers AS endpoints, serves https on `:8444`.
- Tools: `add` (local), `call_downstream` (RFC 8693 gateway → `/data`).

The server runs on the **host** (not in docker-compose) so it, `aoa-conform`,
and Keycloak all share the `https://localhost` issuer and avoid a docker-network
hostname/issuer mismatch. It listens on **:8444** so it does not collide with
Keycloak on **:8443**.

## Run the full loop (Keycloak)
```sh
# 1. Bring up Keycloak (https, seeded realm) — from ../:
cd .. && docker compose up -d && cd mcpserver

# 2. Start the MCP server (host, so it shares the https://localhost issuer):
export KC_GATEWAY_SECRET=gateway-secret
go run .

# 3. Point aoa-conform at it (new shell):
TLS="--cacert ../keycloak/tls/ca.pem"
go run ../../cmd/aoa-conform --issuer https://localhost:8443/realms/mcp $TLS \
  --client-id mcp-conform --client-secret conform-secret
go run ../../cmd/aoa-conform --target https://localhost:8444/mcp $TLS \
  --client-id mcp-conform --client-secret conform-secret
```

### What a green run looks like
- `--target` run: all four **RFC 9728** checks pass — `challenge.resource_metadata`,
  `prm.fetchable`, `prm.authorization_servers_present`
  (`https://localhost:8443/realms/mcp`), `prm.as_resolvable`. This is the point:
  the aoa-guarded server is a conformant protected resource.
- An unauthenticated `GET /mcp` returns **401** with two `WWW-Authenticate`
  challenges (Bearer + DPoP, since `dpop: optional`), each carrying a
  `resource_metadata=` pointer.
- `GET /.well-known/oauth-protected-resource/mcp` (unguarded) returns the PRM JSON.

## Grant flows
- **client_credentials** (machine-to-machine) — the quick smoke above; exercises
  Tier-1 checks. RFC 8693 checks report ⚪ (precondition not met): a
  client_credentials token has no user subject to exchange, so the gateway path
  is only exercised by the Tier-2 flow below.
- **authorization_code + PKCE** (the realistic user-delegated flow) — add
  `--auth-code` and log in as `alice` / `alice`; exercises Tier-2 (user-token)
  checks:
  ```sh
  go run ../../cmd/aoa-conform --target https://localhost:8444/mcp $TLS \
    --client-id mcp-conform --client-secret conform-secret --auth-code
  ```
  Requires the realm `alice` user and the `http://127.0.0.1:*` redirect URI (both
  seeded). The `--auth-code` token exchange honors `--cacert` (so it works against
  the self-signed Keycloak).

## Switching providers
Set `active_provider: hydra|okta` in `config.yaml` (or `--provider`/`$MCP_PROVIDER`)
and point that profile's `issuer` at your own Hydra/Okta instance. One active
provider per run (`aoa` binds one issuer per guard). Only Keycloak is shipped in
docker-compose; Hydra/Okta you supply.

## Expected non-bugs
These `skip`/`fail` results are the provider's behavior, not defects in the server:
- `rfc8707.token.reflects_audience` (SHOULD) — Keycloak does not reflect the
  `resource` indicator into `aud`.
- `dpop.token.nonce_challenge` (SHOULD) — Keycloak issues a DPoP-bound token
  without a `use_dpop_nonce` challenge on first contact.
- Keycloak rejects DPoP-bound *subject* tokens in RFC 8693 exchange; Okta RFC 8707
  / DPoP support varies.

## Token-exchange setup notes (RFC 8693 / `call_downstream`)
Keycloak 26 "standard token exchange" (v2) is enabled via the compose flag
`--features=token-exchange,dpop` plus `standard.token.exchange.enabled` on the
`mcp-gateway` client. Two realm details are required for the exchange to succeed,
and **both are already baked into `../keycloak/realm-export.json`** (no admin-console
steps needed — they survive a fresh `--import-realm`):

1. **`downstream-api` must be a registered client.** Keycloak resolves the
   `audience` exchange parameter to a client; without a `downstream-api` client the
   exchange fails with `invalid_client: "Audience not found"`.
2. **The exchanging client must be in the subject token's audience.** The
   `mcp-conform` client has an audience mapper adding `mcp-gateway` to its access
   token; without it the exchange fails with
   `access_denied: "Client is not within the token audience"`.

Verified working directly against the token endpoint — exchanging an
`mcp-conform` token via `mcp-gateway` for `audience=downstream-api` yields a token
with `aud=downstream-api`, `azp=mcp-gateway`, `scope=mcp:read`:
```sh
TOK=https://localhost:8443/realms/mcp/protocol/openid-connect/token
SUBJ=$(curl -s --cacert ../keycloak/tls/ca.pem \
  -d grant_type=client_credentials -d client_id=mcp-conform -d client_secret=conform-secret \
  "$TOK" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
curl -s --cacert ../keycloak/tls/ca.pem \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id=mcp-gateway -d client_secret=gateway-secret \
  -d subject_token="$SUBJ" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience=downstream-api "$TOK"
```
