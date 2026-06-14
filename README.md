# aoa-conformance

`aoa-conform` is a point-at-your-own-issuer diagnostic for MCP authorization. You
give it the URL of your MCP server or your OAuth issuer, and it walks the agent
authorization loop the way a real MCP client would — discovery, PKCE, resource
indicators, token exchange, DPoP — and prints a capability matrix telling you
exactly which parts of the spec your setup honors.

It is **not** a vendor leaderboard. It is a diagnostic of *your* deployment:
your issuer, your client, your resource server. Two runs against two providers
are not comparable scores; they are two independent reports of what each setup
actually does.

The checks are grouped into two profiles:

- **MCP Core** — the baseline every MCP deployment needs: RFC 9728 protected
  resource metadata discovery, RFC 8414 authorization server metadata, PKCE
  (RFC 7636), resource indicators (RFC 8707), and OAuth 2.1 baseline behavior.
- **MCP Agent-Auth Extended** — the agent-delegation surface: OAuth token
  exchange (RFC 8693) and DPoP sender-constrained tokens (RFC 9449).

## Install

```sh
go install github.com/0ndreu/aoa-conformance/cmd/aoa-conform@latest
```

## Usage

Point at an MCP server (walks the full agent loop, starting from the 401
challenge and the RFC 9728 metadata pointer):

```sh
aoa-conform --target https://mcp.example.com/mcp
```

Or point straight at an OAuth issuer (probes the authorization server directly,
skipping the resource-server discovery hop):

```sh
aoa-conform --issuer https://issuer.example.com
```

Exactly one of `--target` or `--issuer` is required.

### Credential tiers

Many checks only apply once you give the tool credentials — without them, those
checks **skip** (see below), they do not fail.

- **Tier 0 (no creds):** discovery and metadata checks only.
- **Tier 1 (client):** `--client-id` / `--client-secret` unlock
  `client_credentials`-based checks (resource indicators, the present-a-token
  smoke check).
- **Tier 2 (user token):** `--subject-token <jwt>` supplies a user token to
  exchange, unlocking the RFC 8693 token-exchange / delegation checks. Or obtain
  one interactively with `--auth-code` (runs an `authorization_code` + PKCE flow:
  opens your browser, captures the redirect, and uses the resulting token as the
  subject token).

### Other flags

- `--present` — complete the loop: take a token obtained from the AS and present
  it to the resource server, asserting it is accepted.
- `--profile core|extended` — limit the run to a single profile (default: all).
- `--format md|json` — human-readable scorecard (default) or machine-readable
  JSON for CI / offline audit.
- `--strict` — treat SHOULD-level violations as failures (changes the exit code,
  not the report).

### Exit code

`aoa-conform` exits non-zero if any check **fails** or **errors**. With
`--strict`, a SHOULD-severity failure also forces a non-zero exit. Skips never
affect the exit code.

## Three-state semantics: pass / fail / skip

Every check resolves to one of:

- **pass** ✅ — the behavior is present and correct.
- **fail** ❌ — the behavior is required (or expected at this severity) and the
  server got it wrong. This is a real finding.
- **skip** ⚪ — the check's precondition was not met: a capability the server
  never advertised, or a credential you did not supply. A skip is **not** a
  failure. If your issuer does not advertise token exchange, the RFC 8693 checks
  skip — that is the tool correctly reporting "not applicable to this setup,"
  not a defect.

(A fourth state, **error** 🟠, means the probe itself could not complete —
a transport error or malformed response — and is treated like a failure for the
exit code.)

This distinction is the whole point: the tool tells you what your setup *does*,
gates the rest behind preconditions, and never penalizes you for a capability
you legitimately don't offer.

## Testing

Hermetic tests run entirely against an in-process fake authorization server and
a real `aoa`-guarded resource server (the dogfood test) — no network, no Docker:

```sh
make test
```

The real-provider scorecard runs the full suite against a live OAuth provider.
A Keycloak setup is provided under `integration/`; it is gated behind the
`integration` build tag and skips unless `KEYCLOAK_ISSUER` is set:

```sh
make integration
```

`make integration` brings up Keycloak (`integration/docker-compose.yml`, with
`token-exchange` and `dpop` features enabled) and runs the tagged test. Seed a
realm and export `KEYCLOAK_ISSUER` (and optionally `CLIENT_ID`,
`CLIENT_SECRET`, `SUBJECT_TOKEN`) before running.
