package conformance

import (
	"github.com/0ndreu/aoa-conformance/probe"
)

func registerRFC7009(r *Registry) {
	r.Add(Check{
		ID: "rfc7009.revoke.honored", Profile: ProfileExtended, RFC: "RFC 7009", Section: "§2",
		Severity:    SeverityMAY,
		Description: "a revoked token becomes inactive (confirmed via introspection)",
		Precondition: func(t *Target) bool {
			return t.Discovered.RevocationEndpoint != "" && t.Discovered.IntrospectionEndpoint != "" && t.Creds.hasClient()
		},
		Run: func(t *Target) Result {
			token, ev, err := obtainToken(t)
			if err != nil {
				return Result{Status: StatusError, Message: "obtain token: " + err.Error(), Evidence: ev}
			}
			if token == "" {
				return Result{Status: StatusSkip, Message: "could not obtain a token to revoke", Evidence: ev}
			}
			form := probe.FormString("token", token, "client_id", t.Creds.ClientID)
			if t.Creds.ClientSecret != "" {
				form.Set("client_secret", t.Creds.ClientSecret)
			}
			if _, err := probe.PostForm(t.Context(), t.httpClient(), t.Discovered.RevocationEndpoint, form, nil); err != nil {
				return Result{Status: StatusError, Message: "revoke request failed: " + err.Error()}
			}
			resp, err := introspect(t, token)
			if err != nil {
				return Result{Status: StatusError, Message: err.Error()}
			}
			if active, _ := resp.JSON()["active"].(bool); active {
				return Result{Status: StatusFail, Message: "token still active after revocation", Evidence: resp.Evidence}
			}
			return Result{Status: StatusPass, Message: "token inactive after revocation", Evidence: resp.Evidence}
		},
	})
}
