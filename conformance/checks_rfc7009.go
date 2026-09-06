package conformance

import (
	"github.com/0ndreu/aoa-conformance/probe"
)

func registerRFC7009(r *Registry) {
	// advertisement is its own check: the behavioural probe below can only run
	// where introspection also exists, so without this row a server that
	// offers revocation but not introspection would be reported as not
	// supporting revocation at all.
	r.Add(Check{
		ID: "rfc7009.advertise.revocation_endpoint", Profile: ProfileExtended, RFC: "RFC 7009", Section: "§2",
		Severity:    SeverityMAY,
		Description: "the AS advertises a revocation_endpoint",
		Run: func(t *Target) Result {
			if t.Discovered.RevocationEndpoint == "" {
				return Result{Status: StatusSkip, SkipKind: SkipUnsupported, Message: "AS metadata advertises no revocation_endpoint"}
			}
			return Result{Status: StatusPass, Message: "revocation_endpoint advertised: " + t.Discovered.RevocationEndpoint}
		},
	})

	r.Add(Check{
		ID: "rfc7009.revoke.honored", Profile: ProfileExtended, RFC: "RFC 7009", Section: "§2",
		Severity:     SeverityMAY,
		Description:  "a revoked token becomes inactive (confirmed via introspection)",
		Precondition: needs(revocationEndpoint, introspectionEndpoint, tokenSource),
		Run: func(t *Target) Result {
			token, ev, err := obtainToken(t)
			if err != nil {
				return Result{Status: StatusError, Message: "obtain token: " + err.Error(), Evidence: ev}
			}
			if token == "" {
				return Result{Status: StatusSkip, SkipKind: SkipUntested, Message: "the AS issued no token to revoke; pass --subject-token", Evidence: ev}
			}
			form := probe.FormString("token", token)
			h := t.clientAuth(form)
			if _, err := probe.PostForm(t.Context(), t.httpClient(), t.Discovered.RevocationEndpoint, form, h); err != nil {
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
