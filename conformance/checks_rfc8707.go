package conformance

import (
	"fmt"

	"github.com/0ndreu/aoa-conformance/probe"
)

const rfc8707ProbeResource = "https://tool.example"

func registerRFC8707(r *Registry) {
	mk := func(id, section, desc string, sev Severity, run func(*Target) Result) Check {
		return Check{ID: CheckID(id), Profile: ProfileCore, RFC: "RFC 8707", Section: section,
			Severity: sev, Description: desc,
			Precondition: needs(tokenEndpoint, clientCredentialsGrant, planClient),
			Run:          run}
	}

	ccForm := func(t *Target, resources ...string) (*probe.Response, error) {
		form := probe.FormString("grant_type", "client_credentials")
		h := t.clientAuth(form)
		for _, res := range resources {
			form.Add("resource", res)
		}
		return probe.PostForm(t.Context(), t.httpClient(), t.Discovered.TokenEndpoint, form, h)
	}

	r.Add(
		mk("rfc8707.token.accepts_resource", "§2", "token request carrying a resource is accepted", SeveritySHOULD,
			func(t *Target) Result {
				resp, err := ccForm(t, rfc8707ProbeResource)
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
				}
				if resp.StatusCode == 200 {
					return Result{Status: StatusPass, Message: "resource parameter accepted", Evidence: resp.Evidence}
				}
				if resp.JSON()["error"] == "invalid_target" {
					return Result{Status: StatusFail, Message: "legitimate resource rejected with invalid_target", Evidence: resp.Evidence}
				}
				if grantRejected(resp) {
					return Result{Status: StatusSkip, SkipKind: SkipUntested, Message: "AS does not support client_credentials (unsupported_grant_type); pass --client-id at an AS offering it", Evidence: resp.Evidence}
				}
				return Result{Status: StatusFail, Message: "resource request rejected", Evidence: resp.Evidence}
			}),

		mk("rfc8707.token.reflects_audience", "§2", "issued token's aud reflects the requested resource", SeveritySHOULD,
			func(t *Target) Result {
				resp, err := ccForm(t, rfc8707ProbeResource)
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
				}
				if grantRejected(resp) {
					return Result{Status: StatusSkip, SkipKind: SkipUntested, Message: "AS does not support client_credentials (unsupported_grant_type); pass --client-id at an AS offering it", Evidence: resp.Evidence}
				}
				if resp.StatusCode != 200 {
					return Result{Status: StatusFail, Message: "resource request rejected", Evidence: resp.Evidence}
				}
				tok, _ := resp.JSON()["access_token"].(string)
				claims := probe.DecodeJWTPayload(tok)
				if audMatches(claims["aud"], rfc8707ProbeResource) {
					return Result{Status: StatusPass, Message: "aud reflects requested resource", Evidence: resp.Evidence}
				}
				return Result{Status: StatusFail, Message: "aud absent or does not reflect resource", Evidence: resp.Evidence}
			}),

		mk("rfc8707.token.multiple_resources", "§2", "multiple resource parameters are handled without error", SeverityMAY,
			func(t *Target) Result {
				resp, err := ccForm(t, rfc8707ProbeResource, "https://other.example")
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
				}
				if resp.StatusCode >= 500 {
					return Result{Status: StatusFail, Message: "server error on repeated resource", Evidence: resp.Evidence}
				}
				if grantRejected(resp) {
					return Result{Status: StatusSkip, SkipKind: SkipUntested, Message: "AS does not support client_credentials (unsupported_grant_type); pass --client-id at an AS offering it", Evidence: resp.Evidence}
				}
				return Result{Status: StatusPass, Message: "multiple resources handled", Evidence: resp.Evidence}
			}),
	)

	r.Add(Check{
		ID: "rfc8707.authcode.aud_reflects_resource", Profile: ProfileCore, RFC: "RFC 8707", Section: "§2",
		Severity:     SeveritySHOULD,
		Description:  "the token from the interactive round is audience-bound to this MCP server",
		Precondition: needs(mcpTarget, authCodeFlow),
		Run: func(t *Target) Result {
			claims := probe.DecodeJWTPayload(t.Creds.SubjectToken)
			if len(claims) == 0 {
				return Result{Status: StatusSkip, SkipKind: SkipUntested,
					Message: "the audience cannot be read from an opaque access token; ask the operator whether the resource server validates aud against " + t.MCPURL}
			}
			if audMatchesResource(claims["aud"], t.MCPURL) {
				return Result{Status: StatusPass, Message: "aud binds the token to " + t.MCPURL}
			}
			if claims["aud"] == nil {
				return Result{Status: StatusFail,
					Message: "the authorization round sent resource=" + t.MCPURL + " and the issued token carries no aud, so nothing stops it being replayed at another resource"}
			}
			return Result{Status: StatusFail,
				Message: fmt.Sprintf("the authorization round sent resource=%s and the issued token's aud is %v", t.MCPURL, claims["aud"])}
		},
	})
}

func audMatches(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

func audMatchesResource(aud any, resource string) bool {
	want := normalizeResource(resource)
	switch v := aud.(type) {
	case string:
		return normalizeResource(v) == want
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && normalizeResource(s) == want {
				return true
			}
		}
	}
	return false
}
