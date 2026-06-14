package conformance

import (
	"github.com/0ndreu/aoa-conformance/probe"
)

const rfc8707ProbeResource = "https://tool.example"

func registerRFC8707(r *Registry) {
	mk := func(id, section, desc string, sev Severity, run func(*Target) Result) Check {
		return Check{ID: CheckID(id), Profile: ProfileCore, RFC: "RFC 8707", Section: section,
			Severity: sev, Description: desc,
			Precondition: func(t *Target) bool { return t.Plan.hasClient() },
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
				return Result{Status: StatusFail, Message: "resource request rejected", Evidence: resp.Evidence}
			}),

		mk("rfc8707.token.reflects_audience", "§2", "issued token's aud reflects the requested resource", SeveritySHOULD,
			func(t *Target) Result {
				resp, err := ccForm(t, rfc8707ProbeResource)
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
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
				return Result{Status: StatusPass, Message: "multiple resources handled", Evidence: resp.Evidence}
			}),
	)
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
