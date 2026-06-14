# aoa-conformance

`aoa-conform` is a command-line tool that checks whether your MCP server (or the
OAuth issuer behind it) implements the authorization spec correctly. You point
it at a URL, it runs the same authorization steps a real MCP client would
(discovery, PKCE, resource indicators, token exchange, DPoP), and it prints a
scorecard of which checks passed, failed, or were skipped.

It does not rank vendors against each other. Each run is a report about one
deployment: your issuer, your client, your resource server. Running it against
two different providers gives you two separate reports, not comparable scores.

## What it checks

Checks are grouped into two profiles. By default a run includes both.

**MCP Core** is the baseline every MCP deployment needs:

- RFC 9728 protected resource metadata discovery (the `401` challenge and the
  metadata pointer)
- RFC 8414 authorization server metadata
- PKCE, RFC 7636 (S256 advertised, `plain` rejected)
- Resource indicators, RFC 8707 (audience reflected, multiple resources)
- OAuth 2.1 baseline behavior (token endpoint reachable, correct error shapes,
  unknown grants rejected)

**MCP Agent-Auth Extended** covers the agent-delegation surface:

- OAuth token exchange, RFC 8693 (impersonation, delegation, downscoping,
  `act` claim handling)
- DPoP sender-constrained tokens, RFC 9449 (proof accepted, `cnf.jkt` bound,
  nonce challenge, wrong `htu` rejected)

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

## Credential tiers

Many checks only run once you give the tool credentials. Without them, those
checks skip rather than fail.

- **Tier 0, no credentials:** discovery and metadata checks only.
- **Tier 1, client credentials:** pass `--client-id` and `--client-secret` to
  unlock the `client_credentials` checks (resource indicators and the
  present-a-token smoke check).
- **Tier 2, user token:** pass `--subject-token <jwt>` to supply a user token to
  exchange, which unlocks the RFC 8693 token-exchange and delegation checks. If
  you don't have a token handy, use `--auth-code` instead: it runs an
  `authorization_code` plus PKCE flow that opens your browser, captures the
  redirect, and uses the resulting token as the subject token.

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
| `--client-id <id>` | Client id (Tier 1). |
| `--client-secret <secret>` | Client secret (Tier 1). |
| `--subject-token <jwt>` | User token to exchange (Tier 2). |
| `--auth-code` | Obtain a user token interactively via `authorization_code` plus PKCE. |
| `--present` | Complete the loop: take a token from the AS and present it to the resource server, asserting it is accepted. |
| `--profile core\|extended` | Limit the run to one profile. Default is both. |
| `--format md\|json` | Report format. `md` is the human-readable scorecard (default), `json` is for CI and offline audit. |
| `--strict` | Treat SHOULD-level violations as failures. Changes the exit code, not the report. |
| `--cacert <file>` | PEM file of CA certificates to trust for TLS, for example a dev self-signed cert. |
| `--insecure-skip-verify` | Skip TLS certificate verification. Dev only. |

## Pass, fail, and skip

Every check resolves to one of these states:

- **pass:** the behavior is present and correct.
- **fail:** the behavior is required at this severity and the server got it
  wrong. This is a real finding.
- **skip:** the check's precondition was not met, either because the server
  never advertised the capability or because you did not supply the credential
  it needs. A skip is not a failure. If your issuer does not advertise token
  exchange, the RFC 8693 checks skip, which means the tool is reporting "not
  applicable to this setup," not a defect.
- **error:** the probe itself could not complete, for example a transport error
  or a malformed response. For the exit code, an error counts the same as a
  fail.

This is the point of the tool: it reports what your setup actually does, gates
the rest behind preconditions, and never penalizes you for a capability you
legitimately don't offer.

## Exit code

`aoa-conform` exits non-zero if any check fails or errors. With `--strict`, a
SHOULD-severity failure also forces a non-zero exit. Skips never affect the exit
code.
