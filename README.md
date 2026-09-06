# aoa-conformance

`aoa-conform` is a command-line tool that checks whether your MCP server (or the
OAuth issuer behind it) implements the authorization spec correctly. You point
it at a URL, it runs the same authorization steps a real MCP client would
(discovery, PKCE, resource indicators, token exchange, DPoP), and it prints a
capability matrix saying which parts of the spec that deployment supports, which
it does not, and which could not be tested.

It does not rank vendors against each other. Each run is a report about one
deployment: your issuer, your client, your resource server. Running it against
two different providers gives you two separate reports, not comparable scores.

## What it checks

Checks are grouped into three profiles. A run includes all three by default.

**MCP Core** is the baseline every MCP deployment needs. Its resource-server
checks need no credential from you at all, so they run on a stranger's server:

- MCP authorization requirements on the MCP server itself:
  - `mcp.challenge.scope_present` (SHOULD): the `401` `WWW-Authenticate` challenge
    names the scopes a client should ask for
  - `mcp.challenge.no_offline_access` (SHOULD): neither the challenge nor the PRM
    asks agents to hold a long-lived `offline_access` grant
  - `mcp.prm.resource_canonical` (MUST): the PRM `resource` is this server's
    canonical URI — no fragment, lowercase scheme and host
  - `mcp.token.query_not_advertised` (MUST): `bearer_methods_supported` does not
    offer `query`; an access token must never travel in a URI
  - `mcp.token.invalid_rejected` (MUST): a well-formed but unissued bearer token
    gets a `401`, not a `200`, `403` or `500`
  - `mcp.token.foreign_audience_rejected` (MUST): a token signed by a different
    issuer for a different audience gets a `401`. Accepting it is a
    confused-deputy finding, and this check needs nothing from you to find it
- RFC 9728 protected resource metadata discovery (the `401` challenge and the
  metadata pointer)
- RFC 8414 authorization server metadata, including `signed_metadata` signature
  verification against the issuer JWKS when advertised
- PKCE, RFC 7636 (S256 advertised, `plain` rejected)
- Resource indicators, RFC 8707 (audience reflected, multiple resources)
- OAuth 2.1 baseline behavior (token endpoint reachable, correct error shapes,
  unknown grants rejected, `code` response type advertised)
- Authorization server issuer identification, RFC 9207 (the callback carries an
  `iss` matching the issuer when advertised; needs `--auth-code`)

**MCP Agent-Auth Extended** covers the agent-delegation surface:

- OAuth token exchange, RFC 8693 (impersonation, delegation, downscoping,
  `act` claim handling)
- DPoP sender-constrained tokens, RFC 9449 (proof accepted, `cnf.jkt` bound,
  nonce challenge, wrong `htu` rejected)
- Token introspection, RFC 7662 (an issued token introspects as `active`)
- Token revocation, RFC 7009 (the endpoint is advertised, and a revoked token
  becomes inactive — confirmed via introspection, so the second check needs an
  introspection endpoint the first one does not)
- mTLS-bound access tokens, RFC 8705 (the advertisement is coherent: the bound
  flag is accompanied by `mtls_endpoint_aliases`)

**MCP 2026-07-28** carries the authorization SEPs the MCP `2026-07-28`
specification made final:

- Client ID Metadata Documents, `cimd.*` — the URL-as-client-id registration path
  the spec now prefers over dynamic client registration, which it deprecates
- Well-known suffix paths, SEP-2351: the PRM is served at
  `/.well-known/oauth-protected-resource/<path>` for a server on a sub-path
- Issuer-bound registration credentials, SEP-2352 (MUST): what registration hands
  back stays on the issuer that handed it back
- Authorization-response `iss`, SEP-2468: the server advertises
  `authorization_response_iss_parameter_supported` (SHOULD — the spec notes a
  future revision raises this to MUST) and returns `iss` on the callback
- `application_type` on dynamic registration, SEP-837 (MUST for clients)
- Refresh-token scope semantics, SEP-2207: runs once `--auth-code` has captured a
  refresh token
- Step-up authorization, SEP-2350: needs `--auth-code --stepup` and at least two
  PRM-advertised scopes

## Install

```sh
go install github.com/0ndreu/aoa-conformance/cmd/aoa-conform@latest
```

## Quick start

Point at an MCP server. This walks the full agent loop, starting from the `401`
challenge and the RFC 9728 metadata pointer:

```sh
aoa-conform --target https://mcp.example.com/mcp
```

Or point straight at an OAuth issuer. This probes the authorization server
directly and skips the resource-server discovery hop:

```sh
aoa-conform --issuer https://issuer.example.com
```

You must pass exactly one of `--target` or `--issuer`.

## How it talks to your server

In `--target` mode the tool speaks MCP rather than issuing a bare `GET`. It POSTs
a JSON-RPC `tools/list` with `Accept: application/json, text/event-stream` and
`MCP-Protocol-Version: 2026-07-28`, which is what triggers the `401` a modern
server answers with — a bare `GET` gets a `405` or a `406` from a server that
gates on `Accept`, and neither carries a challenge. If the server rejects that
version, the tool retries against the versions the error advertises, and failing
that falls back to a `2025-06-18` `initialize` handshake. The negotiated protocol
era is recorded in the report. `--present` uses the same call, so a token is
presented to a real MCP endpoint rather than to an arbitrary URL.

## Credential tiers

Many checks only run once you give the tool credentials. Without them those
checks report ⚪ `not tested`, naming the flag that would unlock them — never
`fail`, and never `not supported`, which is reserved for an answer about the
server.

- **Tier 0, no credentials:** discovery, metadata and the resource-server checks
  that need nothing from you.
- **Tier 1, a client identity:** pass `--client-id`, plus `--client-secret` only
  if your client is confidential. A public client — a client id with no secret,
  which is what most MCP authorization servers issue — is enough for the checks
  that only need an identity to act as. Checks that drive the
  `client_credentials` grant additionally need an authorization server that
  offers it; when it does not, they report `not tested` rather than failing —
  the server never got a chance to answer the question.
- **Tier 2, a token you already have:** pass `--subject-token <jwt>`. This is the
  paste-a-token path, and it is the most direct way to unlock the credentialed
  checks against a third-party server: presenting a token to the resource,
  introspection, revocation and the RFC 8693 token-exchange and delegation
  checks all prefer it over asking the authorization server for a token of their
  own. If you don't have one handy, use `--auth-code` instead: it runs an
  `authorization_code` plus PKCE flow that opens your browser, captures the
  redirect, and uses the resulting token the same way. The RFC 8707 and DPoP
  checks are the exception: they test what happens *while a token is being
  requested* (whether `resource` is honored, whether a DPoP proof is verified),
  so a token obtained some other way can't stand in — they still need Tier 1's
  `client_credentials` grant.

## How the tool gets a client

You do not always have to bring your own client. After discovery, `aoa-conform`
works out how to authenticate against the token endpoint and, when it can,
registers a client for you.

- **Dynamic registration (RFC 7591).** If you skip `--client-id` and the issuer
  advertises a `registration_endpoint`, the tool registers a temporary client,
  runs the Tier 1 checks with it, and deletes it when the run ends. Servers that
  gate registration behind an initial access token accept one via
  `--registration-token`.
- **What it registers.** The registration asks for the grants the run can
  actually exercise, intersected with the server's `grant_types_supported`, so
  one grant the server does not offer no longer costs the run its whole client.
  It always sends `redirect_uris`, and sets `application_type` from the redirect:
  `native` for a loopback or private-scheme URI, `web` otherwise (SEP-837).
- **When registration is refused.** The failure is reported as its own `error`
  entry quoting what the server said, so "we could not register" is visible
  instead of being inferred from a wall of skipped checks.
- **Auth method.** The tool reads `token_endpoint_auth_methods_supported`. With
  no secret in hand it uses `none` when the server advertises it — the public
  client case — otherwise `client_secret_post`, falling back to
  `client_secret_basic`. Force a method with `--token-auth-method`.
- **Pushed authorization requests (RFC 9126).** When you run `--auth-code`
  against a server that requires PAR, the tool pushes the request to the PAR
  endpoint first, then opens the browser with the returned `request_uri`.

An explicit `--client-id` always wins: the tool uses your client and does not
register one.

Example with a token you already hold:

```sh
aoa-conform --target https://mcp.example.com/mcp \
  --subject-token "$MCP_ACCESS_TOKEN" --present
```

Example with Tier 1 credentials and JSON output:

```sh
aoa-conform --target https://mcp.example.com/mcp \
  --client-id myclient --client-secret mysecret \
  --format json
```

Example obtaining a user token interactively:

```sh
aoa-conform --issuer https://issuer.example.com \
  --client-id myclient --client-secret mysecret \
  --auth-code
```

## Flags

| Flag | Description |
| --- | --- |
| `--target <url>` | MCP server URL. Walks the full agent loop. |
| `--issuer <url>` | OAuth issuer URL. Probes the authorization server directly. |
| `--client-id <id>` | Client id (Tier 1). Works on its own for a public client. |
| `--client-secret <secret>` | Client secret, for a confidential client (Tier 1). |
| `--subject-token <jwt>` | A token you already hold, used wherever a check needs to present or exchange one (Tier 2). |
| `--token-auth-method <method>` | Force the token-endpoint client auth method: `none`, `client_secret_post` or `client_secret_basic`. Default is read from server metadata. |
| `--registration-token <token>` | Initial access token for dynamic client registration, for servers that require one. |
| `--scope "<scopes>"` | Space-separated scopes to request when obtaining a token. In `--target` mode the tool defaults to the scopes the resource advertises in its PRM. |
| `--auth-code` | Obtain a user token interactively via `authorization_code` plus PKCE. Uses PAR when the server requires it. |
| `--stepup` | With `--auth-code`, also run the SEP-2350 step-up probe: two extra interactive authorization rounds against the first two PRM-advertised scopes, checking that the second round's token accumulates the first round's scope rather than dropping it. |
| `--present` | Complete the loop: take a token from the AS and present it to the resource server on a real MCP call, asserting it is accepted. The token is presented by the method the resource advertises in its PRM `bearer_methods_supported` (`header`, `body`, or `query`; default `header`), and is DPoP-bound when the PRM sets `dpop_bound_access_tokens_required`. A `403` (the token authenticates but lacks the required scope) counts as a failure. |
| `--profile <list>` | Limit the run to a comma-separated list of profiles: `core`, `extended`, `2026-07`. Default is all three. The `2026-07` profile (`mcp-2026-07-28`) covers the authorization SEPs the MCP 2026-07-28 specification made final. Two of its checks exercise deeper flows: SEP-2207 (refresh-scope narrowing) runs once `--auth-code` has captured a refresh token, and SEP-2350 (step-up scope accumulation) needs `--auth-code --stepup` plus at least two PRM-advertised scopes, skipping otherwise. |
| `--format md\|json` | Report format. `md` is the human-readable scorecard (default), `json` is for CI and offline audit. |
| `--strict` | Treat SHOULD-level violations as fatal. Changes the exit code, not the report: without it only a MUST-level fail or error exits non-zero. |
| `--cacert <file>` | PEM file of CA certificates to trust for TLS, for example a dev self-signed cert. |
| `--insecure-skip-verify` | Skip TLS certificate verification. Dev only. |
| `--model <list>` | Narrow the agent-compatibility section to a comma-separated list of client surfaces (for example `claude-web,chatgpt`), or `all`. `--target` scores every surface by default; in `--issuer` mode the section is off unless you ask for it. An unknown surface name is a usage error. |
| `--cimd-client-url <url>` | Operator-hosted CIMD client-metadata document URL, for the CIMD behavioral check when running against a remote AS with `--target`/`--issuer`. |

## Agent compatibility

In `--target` mode the report scores the run against a curated corpus of known
client requirements, so you do not have to read the raw check list yourself. Every
surface is scored by default; `--model <list>` narrows it to a comma-separated set
of names (for example `claude-web,chatgpt`) or the single token `all`, and an
unrecognized name is a usage error. In `--issuer` mode there is no resource server
to score, so the section stays off unless `--model` asks for it.

Each verdict is one of four states:

- **aligned:** every requirement the surface treats as mandatory passed, or
  the surface (for example a bring-your-own-bearer client) has none. A
  SHOULD- or MAY-level shortfall does not cost a surface its alignment; it is
  listed as a **caveat** on the verdict instead. Only a MUST-level failure is
  disqualifying — a missing `jwks_uri` is a note, not a broken connector.
- **not-aligned:** a mandatory requirement failed at MUST severity, or the
  server genuinely does not offer a capability the surface requires.
- **inconclusive:** nothing failed, but a mandatory requirement's check never
  ran for want of a credential, so there isn't enough evidence either way. A
  `not tested` check never produces `not-aligned`.
- **n/a:** the surface authenticates outside MCP OAuth discovery entirely
  (Google Cloud IAM, for instance), so no check in this tool maps onto it.

A generated verdict is a prediction based on public documentation and source
review, not a live observation of that client. Before any report goes to a
prospect, its verdict is confirmed against a real sign-in: an actual client
for that surface connects to a real server and the result it gets matches
what the tool predicted. A mismatch holds the report back until the
underlying corpus entry is corrected.

## The report

The report opens with a **capability matrix**: one row per capability a developer
wiring this server into an agent has to decide about — PRM discovery, AS metadata,
PKCE S256, resource indicators, CIMD, dynamic client registration, DPoP,
introspection, revocation, refresh-token scope, step-up, mTLS. Each row is one of
three values, with a reason naming the check that decided it:

- **✅ supported:** a check exercised the capability and it worked.
- **➖ not supported:** the answer is no — either the server never advertised the
  capability, or it advertised it and got a MUST-level requirement wrong. The
  reason line names the deciding check, so you can tell those two apart in the
  tables underneath. For a server operator, a `not supported` row is the report's
  actual finding: an agent that requires that capability will not work against
  this deployment as it stands.
- **⚪ not tested:** no check could run, because a credential or flag was not
  supplied. This says nothing about the server. The reason names what would
  unlock it — `--subject-token`, `--auth-code`, `--stepup`, a client id, or a
  grant the authorization server does not offer.

Underneath the matrix, the per-RFC tables carry every individual check. Each
resolves to one of:

- **pass:** the behavior is present and correct.
- **fail:** the behavior is required at this severity and the server got it
  wrong. This is a real finding.
- **not supported (➖):** the server does not advertise or offer the capability
  the check needs. This is an answer, not an absence of one.
- **not tested (⚪):** you did not supply a credential or flag the check needs.
  The message names the one that would unlock it.
- **error:** the probe itself could not complete, for example a transport error
  or a malformed response. For the exit code, an error counts the same as a fail.

Both ➖ and ⚪ are skips: neither is a failure, and neither affects the exit code.
The distinction is the point of the report. "Your server does not do resource
indicators" and "we never got to check whether your server does resource
indicators" are different sentences, and the tool no longer collapses them into
one.

In `--target` mode the report also carries an **agent compatibility** section by
default, since "can my server be used from these agents" is the question the run
was started to answer. `--model` narrows it to named surfaces.

## Exit code

`aoa-conform` exits non-zero when a **MUST**-severity check fails or errors.
SHOULD- and MAY-severity failures are reported but do not change the exit code
unless you pass `--strict`, which promotes SHOULD to fatal. Skips — both `not
supported` and `not tested` — never affect the exit code.

## Provider stacks

Two self-contained stacks are included in `integration/` for running the full
end-to-end loop locally:

- **Keycloak** (`docker compose up`): supports the full feature set including token
  exchange (RFC 8693), DPoP (RFC 9449), PAR (RFC 9126), and mTLS advertisement
  (RFC 8705). See `docs/keycloak-stack.md`.
- **Ory Hydra** (`docker compose --profile hydra up`): a second self-contained
  provider stack that exercises PKCE (S256), the `--target`/PRM loop, dynamic
  client registration, and PKCE auth-code via the example consent app. Token
  exchange, DPoP, PAR, mTLS and introspection are not exercisable on OSS Hydra
  and report `not supported`; RFC 8707 audience reflection fails (so `--present`
  does not complete). See `docs/hydra-stack.md`.
