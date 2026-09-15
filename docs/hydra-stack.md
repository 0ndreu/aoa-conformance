# Running the full stack: Ory Hydra → MCP server → aoa-conform

This is a step-by-step guide to stand up a complete MCP-authorization environment
on your machine with Ory Hydra as the authorization server and run `aoa-conform`
against it. By the end you'll have:

1. **Ory Hydra**: a headless OAuth 2.1 authorization server (HTTPS public API on
   `:4444`, HTTP admin API on `:4445`).
2. **The example consent app**: a minimal login/consent UI on `:5555` that Hydra
   delegates the authentication step to. Hydra has no built-in login UI, so this is
   required for the `authorization_code` flow.
3. **The aoa-guarded MCP server**: the same server used in the Keycloak stack,
   switched to the `hydra` provider profile, listening on `:8444`.
4. **aoa-conform**: the diagnostic, pointed at both the issuer
   (`https://localhost:4444/`) and the MCP target.

Everything shares the `https://localhost:4444/` issuer. Hydra and the MCP server
share the same self-signed dev cert from `integration/keycloak/tls/`, so there is
no hostname/issuer mismatch.

## Prerequisites

- Docker (with `docker compose`)
- Go (the version in `go.mod`)
- `curl`, `openssl` (for TLS cert generation / sanity checks)
- Three terminals (Hydra and the consent app run detached, but you'll want one for
  the MCP server and one for `aoa-conform`)

All paths below are relative to the repo root.

## What's already seeded for you

The `hydra-init` container runs `integration/hydra/seed.sh` automatically once Hydra
is up, so you do **not** touch the admin API by hand. It creates one client:

| Thing | Value |
|---|---|
| Issuer | `https://localhost:4444/` (public API on `:4444`, admin API on `:4445`) |
| Confidential client (the one you authenticate as) | `mcp-conform` / `conform-secret` |
| Grant types | `authorization_code`, `client_credentials`, `refresh_token` |
| Response types | `code` |
| Resource scope | `mcp:read` (requested with `openid` and `offline_access`) |
| Audience | `mcp-api` |
| Redirect URIs on `mcp-conform` | `http://127.0.0.1/callback`, `http://[::1]/callback` |
| Login UI for `--auth-code` | the example consent app on `:5555` (accepts any username/password) |
| Dynamic client registration | enabled, so you can run with no `--client-id` and let the tool register a throwaway client |

The seed script is idempotent, so re-running the stack does not duplicate the
client. The redirect URIs use the loopback IP literal without a port
(`http://127.0.0.1/callback`) so Hydra accepts `aoa-conform`'s dynamic callback port
under RFC 8252.

DCR works here because `hydra.yml` sets
`webfinger.oidc_discovery.client_registration_url: https://localhost:4444/oauth2/register`,
which makes Hydra advertise `registration_endpoint` in its discovery document.
Hydra's `/oauth2/register` endpoint works but is not advertised by default.

---

## Step 0: Generate the dev TLS cert (first time only)

Hydra mounts the same self-signed cert/CA that Keycloak uses. If
`integration/keycloak/tls/server.crt` already exists, skip this.

```sh
cd integration/keycloak/tls && ./gen.sh && cd ../../..
```

This produces `server.crt`, `server.key`, and `ca.pem`. `ca.pem` is what you pass
to clients via `--cacert` so they trust the self-signed chain.

---

## Step 1: Bring up Hydra

From `integration/`:

```sh
cd integration
docker compose --profile hydra up -d
```

This starts three containers: `hydra` (the authorization server), `consent` (the
login/consent UI), and `hydra-init` (a one-shot seeder that exits after creating the
`mcp-conform` client). Wait a few seconds, then sanity-check discovery:

```sh
curl -s --cacert keycloak/tls/ca.pem \
  https://localhost:4444/.well-known/openid-configuration | head -c 200
```

You should see JSON with `"issuer":"https://localhost:4444/"`.

Confirm the client was seeded:

```sh
docker compose logs hydra-init
```

You should see `hydra admin ready` followed by `created client mcp-conform` (or
`already exists, skipping` on a second run).

> **Quick standalone option:** if you only want to scorecard the *issuer* (Tier 0/1,
> no MCP server), skip Step 2 and run only Step 3a below, which points
> `aoa-conform` straight at the issuer. To run the *full agent loop* against a real
> MCP target, continue with Step 2.

---

## Step 2: Start the aoa-guarded MCP server (on the host)

In a second terminal, from `integration/mcpserver/`. Switch to the `hydra` provider
profile with `MCP_PROVIDER`:

```sh
cd integration/mcpserver
MCP_PROVIDER=hydra go run .
```

It reads `config.yaml`, discovers Hydra's endpoints, pre-fetches the provider JWKS
with a CA-trusting client, and serves HTTPS on `:8444`. You'll see:

```
mcpserver listening addr=:8444 provider=hydra issuer=https://localhost:4444/
```

Leave it running. It exposes:

- `GET /mcp`: the MCP endpoint (401 + `WWW-Authenticate` challenge when unauthenticated)
- `GET /.well-known/oauth-protected-resource/mcp`: RFC 9728 PRM (unguarded)
- Tool: `add` (local). The `call_downstream` tool depends on RFC 8693 token
  exchange, which Hydra does not support, so it is not exercised here.

Optional smoke check (in another shell). An unauthenticated request should 401 with
a `resource_metadata=` pointer:

```sh
curl -si --cacert ../keycloak/tls/ca.pem https://localhost:8444/mcp | grep -i www-authenticate
```

---

## Step 3: Run aoa-conform against the stack

In a third terminal, from `integration/mcpserver/`. The dev cert is self-signed, so
every invocation passes `--cacert`.

```sh
TLS="--cacert ../keycloak/tls/ca.pem"
```

### 3a. Point at the issuer directly (probes the AS, skips resource discovery)

```sh
go run ../../cmd/aoa-conform --issuer https://localhost:4444/ $TLS \
  --client-id mcp-conform --client-secret conform-secret
```

The 2026-07-28 checks run by default; the suffix-path discovery check skips in
`--issuer` mode.

### 3b. Point at the MCP target (walks the full agent loop from the 401 challenge)

```sh
go run ../../cmd/aoa-conform --target https://localhost:8444/mcp $TLS \
  --client-id mcp-conform --client-secret conform-secret
```

This is the realistic run: discovery → PRM → AS metadata → PKCE → resource
indicators → token presentation, ending in a capability matrix. Hydra does not
support token exchange, so the RFC 8693 checks report ➖ `not supported`.

### 3c. Unlock the authorization-code flow with `--auth-code`

`client_credentials` (3a/3b) has no user subject. To exercise the
`authorization_code` path, add `--auth-code`. It opens your browser, and the example
consent app on `:5555` handles the login. Use any username and password (the example
app accepts anything):

```sh
go run ../../cmd/aoa-conform --target https://localhost:8444/mcp $TLS \
  --client-id mcp-conform --client-secret conform-secret --auth-code
```

The loopback redirect (`http://127.0.0.1:<port>/callback`) works because Hydra
honors RFC 8252 variable loopback-port matching by default. The client only needs to
register the loopback IP-literal redirect URI, which `mcp-conform` does.

### 3d. Let the tool register its own client (RFC 7591 DCR)

Drop `--client-id` and `--client-secret`. The stack advertises the registration
endpoint, so the tool registers a temporary client (POST `/oauth2/register` → 201),
runs the client-dependent checks with it, and deletes it when the run ends
(DELETE → 204). The request asks only for grants Hydra advertises in
`grant_types_supported`, always sends `redirect_uris`, and sets
`application_type: native` for the loopback redirect (SEP-837). Hydra answers with
a relative `registration_client_uri` (`/register/<id>`), which the tool resolves
against the registration endpoint so cleanup and the SEP-2352 issuer-binding check
both see the real URL — the check confirms that URL sits on the issuer's origin.
An AS that returns no `registration_client_uri` at all passes it instead: RFC 7591
makes the field optional, and a credential that was never handed back cannot be
replayed at another issuer. If registration is refused, that shows up as a named
`error` entry quoting Hydra's response rather than as a wall of skips:

```sh
go run ../../cmd/aoa-conform --issuer https://localhost:4444/ $TLS
```

You should see the resource-indicator checks run rather than skip.

### 3e. Force the client-auth method

Unlike Keycloak, which advertises and accepts both `client_secret_basic` and
`client_secret_post` for the same client, Hydra binds a single token-endpoint auth
method per client. The seeded `mcp-conform` client uses `client_secret_post`, which
is also the method `aoa-conform` picks by default, so the runs above work as-is.

Passing `--token-auth-method client_secret_basic` against `mcp-conform` is rejected
by Hydra with an `invalid_client`-style error, because that client is registered for
`post` only:

```sh
# rejected for the post-only mcp-conform client:
go run ../../cmd/aoa-conform --issuer https://localhost:4444/ $TLS \
  --client-id mcp-conform --client-secret conform-secret \
  --token-auth-method client_secret_basic
```

To exercise basic auth, register a separate client with
`"token_endpoint_auth_method": "client_secret_basic"` (or let DCR register one) and
point `--client-id` at it.

### Useful flags

- `--profile <list>`: comma-separated list of profiles to run — `core`, `extended`, `2026-07` (default: all three)
- `--format md|json`: scorecard (default) or machine-readable JSON for CI
- `--present`: complete the loop by presenting the obtained token to the resource server, on the `Authorization` header. Against Hydra this does not complete; see [What a healthy run looks like](#what-a-healthy-run-looks-like).
- `--scope "mcp:read"`: space-separated scopes to request when obtaining a token (override)
- `--token-auth-method client_secret_post|client_secret_basic`: force the token-endpoint client auth method (default: read from metadata)
- `--strict`: treat SHOULD-level violations as fatal (changes the exit code; without it only a MUST-level fail or error exits non-zero)
- `--insecure-skip-verify`: skip TLS verification instead of `--cacert` (dev only)

In `--target` mode you usually do **not** pass `--scope`: the server advertises its
required scopes in the RFC 9728 PRM (`scopes_supported`), and the tool requests
exactly those when it obtains a token. Pass `--scope` to override that, or in
`--issuer` mode, where there is no PRM to read scopes from.

---

## What a healthy run looks like

- **`--issuer` run with client creds:** one fail —
  `rfc8707.token.reflects_audience` (see Known quirks) — no errors, and the rest
  split between pass and ➖ `not supported` for the features OSS Hydra lacks.
- **`--target` run:** all four **RFC 9728** checks pass:
  `challenge.resource_metadata`, `prm.fetchable`,
  `prm.authorization_servers_present` (= `https://localhost:4444/`),
  `prm.as_resolvable`. That's the point: the aoa-guarded server is a conformant
  protected resource. The zero-credential `mcp.*` checks pass too: the guard
  rejects an unissued token and a foreign-audience token with a 401, the PRM
  `resource` is canonical, and `query` is not offered as a bearer method.
- The capability matrix reports ✅ for PRM discovery, AS metadata, PKCE S256,
  resource indicators, revocation and dynamic client registration; ➖ for DPoP,
  introspection, mTLS and CIMD, none of which OSS Hydra offers; and ⚪ only where
  a flag you did not pass would have unlocked the check — refresh-token scope
  needs `--auth-code`, step-up needs `--auth-code --stepup`.
- An unauthenticated MCP POST → **401** with a `WWW-Authenticate: Bearer`
  challenge carrying `resource_metadata=`.

### Expected non-bugs (Hydra behavior, not defects)

#### Conformance checks

The discovery-driven checks resolve cleanly here. Each is pass or skip, never
error; the skips below are ➖ `not supported`, since they are Hydra's answer rather
than a missing credential:

- `pkce.advertise.s256` (MUST): **pass**. Hydra advertises `S256` in
  `code_challenge_methods_supported`.
- `oauth21.authorize.response_type_code` (SHOULD): **pass**. Hydra advertises `code`
  in `response_types_supported`.
- `rfc8707.token.accepts_resource` and `rfc8707.token.multiple_resources`: **pass**.
  Hydra accepts the `resource` parameter at the token endpoint.
- `rfc7662.introspect.active` (MAY): ➖ **not supported**. Hydra's introspection
  endpoint is on the admin API, which the public discovery document does not
  advertise.
- `rfc7009.advertise.revocation_endpoint`: **pass**. Hydra advertises a
  `revocation_endpoint` and the URL answers, so revocation reports as supported.
- `rfc7009.revoke.honored` (MAY): ⚪ **not tested**. The check verifies revocation
  by introspecting the revoked token, and there is no advertised
  `introspection_endpoint` for it to read the answer from. That is a missing
  verification path, not Hydra declining to revoke.
- `pkce.enforce.reject_plain` (MUST): ⚪ **not tested**, with or without
  `--auth-code`. A genuine plain-downgrade probe needs a dedicated,
  never-redeemed authorization code that the shared `--auth-code` exchange
  doesn't provide, so the check always reports its own limitation rather than
  a real verdict; this is not something Hydra's configuration affects.
- `rfc9207.authorize.iss_present` (MUST): ➖ **not supported**. Hydra does not
  advertise `authorization_response_iss_parameter_supported`.
- `rfc8414.metadata.signed_metadata_valid` (SHOULD): ➖ **not supported**. Hydra does
  not emit `signed_metadata`. The fake AS covers the pass/fail behavior.
- `rfc8705.advertise.mtls_bound` (MAY): ➖ **not supported**. OSS Hydra has no
  mTLS-bound tokens, so `tls_client_certificate_bound_access_tokens` is absent.
- `rfc8693.*` (token exchange) and `dpop.*`: ➖ **not supported**. Neither is
  implemented in OSS Hydra, so the grant type and the DPoP algorithms are absent
  from discovery.

The env-gated `integration/hydra_test.go` asserts none of these error and logs each
one's status.

#### Known quirks

These show as skip/fail and are correct:

- `rfc8707.token.reflects_audience` (SHOULD): **fail**. Hydra accepts the RFC 8707
  `resource` parameter but does not reflect it into the token `aud`, returning an
  empty `aud`. This is the same limitation Keycloak has. The neighboring
  `rfc8707.token.accepts_resource` passes only because Hydra accepts the parameter
  instead of erroring on it. Hydra populates `aud` only from its non-standard
  `audience` request parameter, which the tool does not send.
- `--present` does not complete against Hydra as a consequence: the empty-`aud` token
  is rejected by the MCP server, which requires the `mcp-api` audience, with a 401. A
  `--present` run (or `--strict`) therefore exits non-zero, which is expected here.

A skip is never a failure, and the report splits it in two: ➖ `not supported`
means Hydra does not offer the capability (an answer), ⚪ `not tested` means you
did not supply a credential or flag (no answer yet, and the message names the one
that would unlock it). `aoa-conform` exits non-zero only on a MUST-level **fail**
or **error** — and on SHOULD-level ones under `--strict`.

---

## Verifying a JWT access token directly (optional)

Hydra issues opaque tokens by default; this stack sets `strategies.access_token: jwt`
so the MCP server can validate tokens via JWKS. To confirm a token comes back as a
signed JWT with the right `iss` and `aud`:

```sh
cd integration/mcpserver
AT=$(curl -s --cacert ../keycloak/tls/ca.pem \
  -d grant_type=client_credentials -d client_id=mcp-conform -d client_secret=conform-secret \
  -d audience=mcp-api https://localhost:4444/oauth2/token \
  | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
echo "$AT" | cut -d. -f2 | base64 -d 2>/dev/null
```

Expected: three dot-separated JWT segments, with `iss` of `https://localhost:4444/`
and `aud` of `["mcp-api"]`. If the token has no dots, it is opaque, which means
`strategies.access_token: jwt` is not taking effect. Check `docker compose logs
hydra` (debug logging is on) to confirm the config loaded.

---

## Switching providers (Keycloak / Okta)

`config.yaml` ships `keycloak` (active by default), `keycloak-dpop`, `hydra`, and
`okta` profiles. Set `active_provider:` in the file, or pass `--provider` /
`$MCP_PROVIDER`. The Keycloak stack is documented in `docs/keycloak-stack.md`; it
adds RFC 8693 token exchange and DPoP coverage that Hydra does not support. Okta is a
config-only profile you point at your own org. One active provider per run: `aoa`
binds one issuer per guard.

---

## Teardown

```sh
# stop the MCP server: Ctrl-C in its terminal
cd integration && docker compose --profile hydra down    # add -v to drop volumes
```
