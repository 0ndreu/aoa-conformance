package conformance

import (
	"fmt"

	"github.com/0ndreu/aoa-conformance/probe"
)

func registerRFC7009(r *Registry) {
	// the advertisement is its own check: the behavioural probe below can only
	// run where introspection also exists, so without this row a server that
	// offers revocation but not introspection would be reported as not
	// supporting revocation at all. It is not taken on trust either — an
	// advertised endpoint that is not deployed is the same absent capability
	// as no advertisement, and the reader should not have to discover that
	// from their own logs.
	r.Add(Check{
		ID: "rfc7009.advertise.revocation_endpoint", Profile: ProfileExtended, RFC: "RFC 7009", Section: "§2",
		Severity:     SeverityMAY,
		Description:  "the advertised revocation_endpoint is deployed and answers a revocation request",
		Precondition: needs(revocationEndpoint),
		Run: func(t *Target) Result {
			endpoint := t.Discovered.RevocationEndpoint
			form := probe.FormString("token", "aoaconform."+probe.RandToken())
			resp, err := probe.PostForm(t.Context(), t.httpClient(), endpoint, form, t.clientAuth(form))
			if err != nil {
				return Result{Status: StatusError, Message: "revocation request to " + endpoint + " failed: " + err.Error()}
			}
			// RFC 7009 §2.2 lets a live endpoint answer 200 (including for a
			// token it does not recognise), 400 or 401. Only the statuses that
			// mean "nothing is routed here" say the capability is absent.
			switch resp.StatusCode {
			case 404, 405, 501:
				return Result{Status: StatusSkip, SkipKind: SkipUnsupported,
					Message:  fmt.Sprintf("revocation_endpoint %s is advertised but answers HTTP %d, so no revocation endpoint is deployed there", endpoint, resp.StatusCode),
					Evidence: resp.Evidence}
			}
			return Result{Status: StatusPass,
				Message:  fmt.Sprintf("revocation_endpoint %s answered HTTP %d", endpoint, resp.StatusCode),
				Evidence: resp.Evidence}
		},
	})

	r.Add(Check{
		ID: "rfc7009.revoke.honored", Profile: ProfileExtended, RFC: "RFC 7009", Section: "§2",
		Severity:     SeverityMAY,
		Description:  "a revoked token becomes inactive (confirmed via introspection)",
		Precondition: needs(revocationEndpoint, introspectionForRevocation, tokenSource),
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
