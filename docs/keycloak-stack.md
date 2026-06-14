# Running the full stack: Keycloak → MCP server → aoa-conform

This is a step-by-step guide to stand up a complete, conformant MCP-authorization
environment on your machine and run `aoa-conform` against it. By the end you'll have:

1. **Keycloak**: a real OAuth 2.1 authorization server (HTTPS, seeded `mcp` realm,
   `token-exchange` + `dpop` features on).
2. **The aoa-guarded MCP server**: a real MCP server with two tools behind `aoa`
   OAuth middleware, acting as your conformance target.
3. **aoa-conform**: the diagnostic, pointed at both the issuer and the MCP target.

Everything shares the `https://localhost` issuer so there is no docker-network
hostname/issuer mismatch. Keycloak runs in Docker on `:8443`; the MCP server runs
on the **host** on `:8444`.

## Prerequisites

- Docker (with `docker compose`)
- Go (the version in `go.mod`)
- `curl`, `openssl` (for TLS cert generation / sanity checks)
- Three terminals (Keycloak runs detached, but you'll want one for the MCP server
  and one for `aoa-conform`)

All paths below are relative to the repo root.

## What's already seeded for you

The realm import (`integration/keycloak/realm-export.json`) ships these, so you do
**not** touch the admin console:

| Thing | Value |
|---|---|
| Realm | `mcp` → issuer `https://localhost:8443/realms/mcp` |
| Confidential client (the one you authenticate as) | `mcp-conform` / `conform-secret` |
| Token-exchange gateway client | `mcp-gateway` / `gateway-secret` |
| Downstream API client (exchange audience) | `downstream-api` / `downstream-secret` |
| PAR-required client (RFC 9126) | `mcp-par` / `par-secret` (its authorize requests must go through the PAR endpoint) |
| Test user (for `--auth-code`) | `alice` / `alice` |
| Redirect URIs on `mcp-conform` and `mcp-par` | `http://localhost:*`, `https://localhost:*`, `http://127.0.0.1:*` |
| Resource scope | `mcp:read` (an **optional** client scope; advertised in the PRM and requested automatically in `--target` mode) |
| Anonymous dynamic registration | enabled (the import omits Keycloak's default Trusted Hosts policy), so you can run with no `--client-id` and let the tool register a throwaway client |

The two realm details RFC 8693 token exchange needs (`downstream-api` registered
as a client, and `mcp-gateway` in `mcp-conform`'s token audience) are baked into
the import and survive a fresh `--import-realm`.

---

## Step 0: Generate the dev TLS cert (first time only)

Keycloak and the MCP server share one self-signed cert/CA. If
`integration/keycloak/tls/server.crt` already exists, skip this.

```sh
cd integration/keycloak/tls && ./gen.sh && cd ../../..
```

This produces `server.crt`, `server.key`, and `ca.pem`. `ca.pem` is what you pass
to clients via `--cacert` so they trust the self-signed chain.

---

## Step 1: Bring up Keycloak

From `integration/`:

```sh
cd integration
docker compose up -d
```

This starts `quay.io/keycloak/keycloak:26.2` with:

- `start-dev --features=token-exchange,dpop --import-realm`
- HTTPS on `:8443` using the dev cert mounted from `keycloak/tls/`
- admin / admin (admin console at `https://localhost:8443`)
- the `mcp` realm imported on boot

Wait for it to be ready, then sanity-check discovery:

```sh
curl -s --cacert keycloak/tls/ca.pem \
  https://localhost:8443/realms/mcp/.well-known/openid-configuration | head -c 200
```

You should see JSON with `"issuer":"https://localhost:8443/realms/mcp"`.

> **Quick standalone option:** if you only want to scorecard the *issuer* (Tier 0/1,
> no MCP server), skip Step 2 and run only Step 3a below, which points
> `aoa-conform` straight at the issuer. To run the *full agent loop* against a
> real MCP target, continue with Step 2.

---

## Step 2: Start the aoa-guarded MCP server (on the host)

In a second terminal, from `integration/mcpserver/`. The server reads
`config.yaml` (Keycloak is the active provider by default) and needs the gateway
client secret in the environment for the RFC 8693 exchange path:

```sh
cd integration/mcpserver
export KC_GATEWAY_SECRET=gateway-secret
go run .
```

It discovers Keycloak's endpoints, pre-fetches the provider JWKS with a
CA-trusting client, and serves HTTPS on `:8444`. You'll see:

```
mcpserver listening addr=:8444 provider=keycloak issuer=https://localhost:8443/realms/mcp
```

Leave it running. It exposes:

- `GET /mcp`: the MCP endpoint (401 + `WWW-Authenticate` challenges when unauthenticated)
- `GET /.well-known/oauth-protected-resource/mcp`: RFC 9728 PRM (unguarded)
- Tools: `add` (local) and `call_downstream` (RFC 8693 gateway → `/data`)

Optional smoke check (in another shell). An unauthenticated request should 401
with a `resource_metadata=` pointer:

```sh
curl -si --cacert ../keycloak/tls/ca.pem https://localhost:8444/mcp | grep -i www-authenticate
```

---

## Step 3: Run aoa-conform against the stack

In a third terminal, from `integration/mcpserver/`. The dev cert is self-signed,
so every invocation passes `--cacert`.

```sh
TLS="--cacert ../keycloak/tls/ca.pem"
```

### 3a. Point at the issuer directly (probes the AS, skips resource discovery)

```sh
go run ../../cmd/aoa-conform --issuer https://localhost:8443/realms/mcp $TLS \
  --client-id mcp-conform --client-secret conform-secret
```

### 3b. Point at the MCP target (walks the full agent loop from the 401 challenge)

```sh
go run ../../cmd/aoa-conform --target https://localhost:8444/mcp $TLS \
  --client-id mcp-conform --client-secret conform-secret
```

This is the realistic run: discovery → PRM → AS metadata → PKCE → resource
indicators → token exchange → DPoP, ending in a capability matrix.

### 3c. Unlock the Tier-2 (user-delegated) RFC 8693 checks with `--auth-code`

`client_credentials` (3a/3b) has no user subject to exchange, so the RFC 8693
checks report ⚪ skip. To exercise the real delegation path, add `--auth-code`.
It runs `authorization_code` + PKCE, opens your browser; log in as **alice / alice**:

```sh
go run ../../cmd/aoa-conform --target https://localhost:8444/mcp $TLS \
  --client-id mcp-conform --client-secret conform-secret --auth-code
```

`--auth-code` honors `--cacert`, so the token exchange works against the
self-signed Keycloak. Alternatively, supply a pre-obtained user JWT with
`--subject-token <jwt>`.

### 3d. Let the tool register its own client (RFC 7591 DCR)

Drop `--client-id` and `--client-secret`. This realm allows anonymous dynamic
registration, so the tool registers a temporary client, runs the
client-dependent checks with it, and deletes it when the run ends:

```sh
go run ../../cmd/aoa-conform --issuer https://localhost:8443/realms/mcp $TLS
```

You should see the resource-indicator and DPoP checks run rather than skip. If
you later lock the realm down to token-gated registration, pass the initial
access token with `--registration-token <token>`.

### 3e. Exercise PAR (RFC 9126)

The `mcp-par` client requires pushed authorization requests. Point `--auth-code`
at it and the tool pushes the request to Keycloak's PAR endpoint before opening
the browser. Log in as **alice / alice**:

```sh
go run ../../cmd/aoa-conform --issuer https://localhost:8443/realms/mcp $TLS \
  --client-id mcp-par --client-secret par-secret --auth-code
```

A plain authorize request for `mcp-par` (one without a `request_uri`) is rejected
by Keycloak with `invalid_request`, which is the behavior PAR is meant to enforce.

### 3f. Force the client-auth method

Keycloak advertises both `client_secret_post` and `client_secret_basic`, and the
tool picks post by default. Pass `--token-auth-method client_secret_basic` to
send the client credentials in an HTTP Basic header instead:

```sh
go run ../../cmd/aoa-conform --issuer https://localhost:8443/realms/mcp $TLS \
  --client-id mcp-conform --client-secret conform-secret \
  --token-auth-method client_secret_basic
```

### Useful flags

- `--profile core|extended`: limit to one profile (default: both)
- `--format md|json`: scorecard (default) or machine-readable JSON for CI
- `--present`: complete the loop by presenting the obtained token to the resource server
- `--scope "mcp:read"`: space-separated scopes to request when obtaining a token (override)
- `--token-auth-method client_secret_post|client_secret_basic`: force the token-endpoint client auth method (default: read from metadata)
- `--registration-token <token>`: initial access token for dynamic registration, if the realm requires one
- `--strict`: treat SHOULD-level violations as failures (changes exit code)
- `--insecure-skip-verify`: skip TLS verification instead of `--cacert` (dev only)

`mcp:read` is an optional client scope, so a token only carries it when it is
requested. In `--target` mode you usually do **not** pass `--scope`: the server
advertises its required scopes in the RFC 9728 PRM (`scopes_supported`), and the
tool requests exactly those when it obtains a token. So `--present` works on its
own:

```sh
go run ../../cmd/aoa-conform --target https://localhost:8444/mcp $TLS \
  --client-id mcp-conform --client-secret conform-secret --present
```

Pass `--scope` to override that, or in `--issuer` mode, where there is no PRM to
read scopes from.

---

## What a healthy run looks like

- **`--target` run:** all four **RFC 9728** checks pass:
  `challenge.resource_metadata`, `prm.fetchable`,
  `prm.authorization_servers_present` (= `https://localhost:8443/realms/mcp`),
  `prm.as_resolvable`. That's the point: the aoa-guarded server is a conformant
  protected resource.
- Unauthenticated `GET /mcp` → **401** with two `WWW-Authenticate` challenges
  (Bearer + DPoP, since `dpop: optional`), each carrying `resource_metadata=`.

### Expected non-bugs (Keycloak behavior, not defects)

These show as skip/fail and are correct:

- `rfc8707.token.reflects_audience` (SHOULD): Keycloak doesn't reflect the
  `resource` indicator into `aud`, and you can't fix that from realm config.
  Audience mappers are configured per client (the `oidc-audience-mapper`
  entries in `realm-export.json`) and they don't read the RFC 8707 `resource`
  parameter on the token request. No realm setting makes Keycloak echo a
  requested `resource` into `aud`. The neighboring
  `rfc8707.token.accepts_resource` check passes only because Keycloak accepts
  the unknown parameter instead of erroring on it. The only way to make the check
  go green would be to hardcode `https://tool.example` as a static audience, which
  games the check rather than implementing resource indicators.
- `dpop.token.nonce_challenge` (SHOULD): Keycloak issues a DPoP-bound token with
  no `use_dpop_nonce` challenge on first contact. Keycloak 26.2 has no
  server-issued DPoP nonce feature, so there is nothing to toggle in the realm.
- Keycloak rejects DPoP-bound *subject* tokens in RFC 8693 exchange (it still
  issues bound *output* tokens).

`rfc8693.downscope.scope_honored` used to fail here and now passes: `mcp:read` is
an optional client scope, so a token-exchange that requests a narrower scope no
longer comes back widened. Because the scope is now optional, the tool requests it
from the PRM's `scopes_supported` when it needs an accepted token (see
[Useful flags](#useful-flags)).

A **skip** is never a failure. It means a precondition (an advertised capability
or a credential you didn't supply) wasn't met. `aoa-conform` exits non-zero only
on **fail** or **error** (and SHOULD-fails under `--strict`).

---

## Verifying token exchange directly (optional)

To confirm RFC 8693 works at the token endpoint independent of the tool:

```sh
cd integration/mcpserver
TOK=https://localhost:8443/realms/mcp/protocol/openid-connect/token
SUBJ=$(curl -s --cacert ../keycloak/tls/ca.pem \
  -d grant_type=client_credentials -d client_id=mcp-conform -d client_secret=conform-secret \
  "$TOK" | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
curl -s --cacert ../keycloak/tls/ca.pem \
  -d grant_type=urn:ietf:params:oauth:grant-type:token-exchange \
  -d client_id=mcp-gateway -d client_secret=gateway-secret \
  -d subject_token="$SUBJ" \
  -d subject_token_type=urn:ietf:params:oauth:token-type:access_token \
  -d audience=downstream-api -d scope=mcp:read "$TOK"
```

Expected: a token with `aud=downstream-api`, `azp=mcp-gateway`, `scope=mcp:read`.
`mcp:read` is optional now, so drop the `-d scope=mcp:read` and the issued token
comes back with an empty `scope` instead. That opt-in is what lets a narrower
exchange request actually narrow the result.

---

## Switching providers (Hydra / Okta)

`config.yaml` ships `keycloak` (active), `hydra`, and `okta` profiles. Set
`active_provider:` in the file, or pass `--provider` / `$MCP_PROVIDER`, and point
that profile's `issuer` at your own instance. Only Keycloak is in docker-compose;
you supply Hydra/Okta. One active provider per run: `aoa` binds one issuer per guard.

---

## Teardown

```sh
# stop the MCP server: Ctrl-C in its terminal
cd integration && docker compose down       # add -v to drop volumes
```
