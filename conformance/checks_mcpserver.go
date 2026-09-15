package conformance

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/0ndreu/aoa-conformance/probe"
)

// The requirements the MCP authorization specification places on the resource
// server itself. Every one of them is observable without a credential: the
// server's own 401, its PRM document, and how it answers a token it should
// never accept. This is the part of the report a stranger's developer gets for
// free.

// foreignIssuer / foreignAudience name a namespace we control and that no real
// deployment can legitimately trust. RFC 6761 reserves .invalid for exactly
// this.
const (
	foreignIssuer   = "https://issuer.aoa-conform.invalid"
	foreignAudience = "https://resource.aoa-conform.invalid"
)

func registerMCPServer(r *Registry) {
	mk := func(id, section string, sev Severity, desc string, pre func(*Target) (bool, SkipReason), run func(*Target) Result) Check {
		return Check{ID: CheckID(id), Profile: ProfileCore, RFC: "MCP Authorization", Section: section,
			Severity: sev, Description: desc, Precondition: pre, Run: run}
	}

	// challengeObserved gates the checks that read the 401 challenge. A server
	// that never issued one is already failing rfc9728.challenge.resource_metadata;
	// repeating that verdict here would double-count one defect.
	challengeObserved := func(t *Target) SkipReason {
		if t.Hints["www_authenticate"] == "" {
			return Unsupported("the resource server issued no WWW-Authenticate challenge")
		}
		return satisfied
	}
	prmFetched := func(t *Target) SkipReason {
		if len(t.Discovered.RawPRM) == 0 {
			return Unsupported("no protected resource metadata document was fetched")
		}
		return satisfied
	}

	r.Add(
		mk("mcp.challenge.scope_present", "§2.4", SeveritySHOULD,
			"the 401 WWW-Authenticate challenge names the scopes the client should request",
			needs(mcpTarget, challengeObserved),
			func(t *Target) Result {
				challenge := t.Hints["www_authenticate"]
				scope := challengeParam(challenge, "scope")
				if scope == "" {
					return Result{Status: StatusFail,
						Message:  "challenge carries no scope parameter, so a client cannot tell what to request: " + challenge,
						Evidence: []byte(challenge)}
				}
				return Result{Status: StatusPass, Message: "challenge advertises scope: " + scope, Evidence: []byte(challenge)}
			}),

		mk("mcp.challenge.no_offline_access", "§2.4", SeveritySHOULD,
			"neither the challenge nor PRM scopes_supported offers offline_access",
			needs(mcpTarget, func(t *Target) SkipReason {
				if t.Hints["www_authenticate"] == "" && len(t.Discovered.RawPRM) == 0 {
					return Unsupported("the resource server advertises no scopes, in a challenge or in PRM")
				}
				return satisfied
			}),
			func(t *Target) Result {
				challenge := t.Hints["www_authenticate"]
				var where []string
				if containsScope(strings.Fields(challengeParam(challenge, "scope")), "offline_access") {
					where = append(where, "the WWW-Authenticate challenge")
				}
				if containsScope(t.Discovered.PRMScopesSupported, "offline_access") {
					where = append(where, "PRM scopes_supported")
				}
				if len(where) > 0 {
					return Result{Status: StatusFail,
						Message:  "offline_access is advertised in " + strings.Join(where, " and ") + "; a resource server should not ask agents to hold long-lived grants",
						Evidence: t.Discovered.RawPRM}
				}
				return Result{Status: StatusPass, Message: "offline_access is not advertised", Evidence: t.Discovered.RawPRM}
			}),

		mk("mcp.prm.resource_canonical", "§2.2", SeverityMUST,
			"PRM resource is the canonical URI of this MCP server",
			needs(mcpTarget, prmFetched),
			func(t *Target) Result {
				if problem := canonicalResourceProblem(t.Discovered.PRMResource, t.MCPURL); problem != "" {
					return Result{Status: StatusFail, Message: problem, Evidence: t.Discovered.RawPRM}
				}
				return Result{Status: StatusPass,
					Message:  "PRM resource is the canonical server URI: " + t.Discovered.PRMResource,
					Evidence: t.Discovered.RawPRM}
			}),

		mk("mcp.token.query_not_advertised", "§2.3", SeverityMUST,
			"the resource does not offer the URI query string as a bearer method",
			needs(mcpTarget, prmFetched),
			func(t *Target) Result {
				for _, m := range t.Discovered.PRMBearerMethodsSupported {
					if strings.EqualFold(m, "query") {
						return Result{Status: StatusFail,
							Message:  "PRM bearer_methods_supported offers \"query\"; access tokens must never travel in the URI",
							Evidence: t.Discovered.RawPRM}
					}
				}
				if len(t.Discovered.PRMBearerMethodsSupported) == 0 {
					return Result{Status: StatusPass, Message: "PRM advertises no bearer_methods_supported, so query is not offered", Evidence: t.Discovered.RawPRM}
				}
				return Result{Status: StatusPass,
					Message:  "bearer methods offered: " + strings.Join(t.Discovered.PRMBearerMethodsSupported, ", "),
					Evidence: t.Discovered.RawPRM}
			}),

		mk("mcp.token.header_method_advertised", "§2.3", SeverityMUST,
			"the resource offers the Authorization header, the only bearer method MCP clients use",
			needs(mcpTarget, prmFetched),
			func(t *Target) Result {
				methods := t.Discovered.PRMBearerMethodsSupported
				if len(methods) == 0 {
					return Result{Status: StatusPass,
						Message:  "PRM advertises no bearer_methods_supported, so the RFC 6750 §2.1 default — the Authorization header — stands",
						Evidence: t.Discovered.RawPRM}
				}
				for _, m := range methods {
					if strings.EqualFold(m, "header") {
						return Result{Status: StatusPass,
							Message:  "bearer methods offered include header: " + strings.Join(methods, ", "),
							Evidence: t.Discovered.RawPRM}
					}
				}
				return Result{Status: StatusFail,
					Message: "PRM advertises bearer_methods_supported " + strings.Join(methods, ", ") +
						" and omits \"header\"; MCP clients send the token in the Authorization header, so a client that honours this list will be rejected — add \"header\" to the advertised methods",
					Evidence: t.Discovered.RawPRM}
			}),

		mk("mcp.token.invalid_rejected", "§2.3", SeverityMUST,
			"a syntactically valid but unissued bearer token is rejected with 401",
			needs(mcpTarget),
			func(t *Target) Result {
				token := "aoaconform." + probe.RandToken()
				resp, err := probe.PresentToken(t.Context(), t.httpClient(),
					probe.PresentInput{ResourceURL: t.MCPURL, Token: token})
				if err != nil {
					return Result{Status: StatusError, Message: "presenting an invalid token failed: " + err.Error()}
				}
				return judgeRejection(resp, "an unissued token")
			}),

		mk("mcp.token.foreign_audience_rejected", "§2.3", SeverityMUST,
			"a forged token claiming an iss/aud it was never issued for is rejected with 401",
			needs(mcpTarget),
			func(t *Target) Result {
				signer, err := probe.NewSigner()
				if err != nil {
					return Result{Status: StatusError, Message: "mint probe key: " + err.Error()}
				}
				now := time.Now()
				token, err := signer.SignJWT(map[string]any{
					"iss": foreignIssuer,
					"aud": foreignAudience,
					"sub": "aoa-conform-probe",
					"iat": now.Unix(),
					"exp": now.Add(5 * time.Minute).Unix(),
				})
				if err != nil {
					return Result{Status: StatusError, Message: "sign foreign token: " + err.Error()}
				}
				resp, err := probe.PresentToken(t.Context(), t.httpClient(),
					probe.PresentInput{ResourceURL: t.MCPURL, Token: token})
				if err != nil {
					return Result{Status: StatusError, Message: "presenting a foreign token failed: " + err.Error()}
				}
				return judgeRejection(resp, "a forged token claiming iss "+foreignIssuer+" and aud "+foreignAudience)
			}),
	)
}

// judgeRejection reads the resource server's answer to a token it must not
// accept. Only 401 is conformant: 200 means the token passed, and 403 means it
// authenticated and merely lacked scope — both are the confused-deputy failure
// the specification calls out.
func judgeRejection(resp *probe.Response, what string) Result {
	switch {
	case resp.StatusCode == 401:
		return Result{Status: StatusPass, Message: "rejected " + what + " with 401", Evidence: resp.Evidence}
	case resp.StatusCode == 403:
		return Result{Status: StatusFail,
			Message:  "accepted " + what + " as authenticated and answered 403 (scope), not 401",
			Evidence: resp.Evidence}
	case resp.StatusCode < 300:
		return Result{Status: StatusFail,
			Message:  fmt.Sprintf("served the call with %s (HTTP %d)", what, resp.StatusCode),
			Evidence: resp.Evidence}
	default:
		return Result{Status: StatusFail,
			Message:  fmt.Sprintf("answered HTTP %d to %s; the specification requires 401", resp.StatusCode, what),
			Evidence: resp.Evidence}
	}
}

// canonicalResourceProblem returns a sentence describing how the PRM resource
// value departs from the canonical URI of the MCP server under test, or "" when
// it is correct. Canonical means: present, no fragment, lowercase scheme and
// host, and the same URI the client is talking to.
func canonicalResourceProblem(resource, mcpURL string) string {
	if resource == "" {
		return "PRM omits the required resource field, so a client cannot confirm which resource the metadata describes"
	}
	u, err := url.Parse(resource)
	if err != nil {
		return "PRM resource is not a URI: " + resource
	}
	if u.Fragment != "" || strings.Contains(resource, "#") {
		return "PRM resource carries a fragment, which a resource identifier must not have: " + resource
	}
	if u.Scheme != strings.ToLower(u.Scheme) || u.Host != strings.ToLower(u.Host) {
		return "PRM resource is not lowercase in scheme/host: " + resource
	}
	if normalizeResource(resource) != normalizeResource(mcpURL) {
		return fmt.Sprintf("PRM resource %q is not the canonical URI of the server under test (%s)", resource, mcpURL)
	}
	return ""
}

// normalizeResource trims the one difference RFC 8707 §2 tolerates between two
// spellings of the same resource identifier: a trailing slash.
func normalizeResource(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	u.RawQuery = ""
	return u.String()
}

var challengeParamRE = regexp.MustCompile(`([A-Za-z_-]+)="([^"]*)"`)

// challengeParam pulls one auth-param out of a WWW-Authenticate header.
func challengeParam(challenge, name string) string {
	for _, m := range challengeParamRE.FindAllStringSubmatch(challenge, -1) {
		if strings.EqualFold(m[1], name) {
			return m[2]
		}
	}
	return ""
}

func containsScope(scopes []string, want string) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}
