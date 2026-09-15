package conformance

import (
	"github.com/0ndreu/aoa-conformance/probe"
)

func registerRFC7662(r *Registry) {
	r.Add(Check{
		ID: "rfc7662.introspect.active", Profile: ProfileExtended, RFC: "RFC 7662", Section: "§2",
		Severity: SeverityMAY, Description: "an issued token introspects as active:true",
		Precondition: needs(introspectionEndpoint, tokenSource),
		Run: func(t *Target) Result {
			token, ev, err := obtainToken(t)
			if err != nil {
				return Result{Status: StatusError, Message: "obtain token: " + err.Error(), Evidence: ev}
			}
			if token == "" {
				return Result{Status: StatusSkip, SkipKind: SkipUntested, Message: "the AS issued no token to introspect; pass --subject-token", Evidence: ev}
			}
			resp, err := introspect(t, token)
			if err != nil {
				return Result{Status: StatusError, Message: err.Error()}
			}
			if active, _ := resp.JSON()["active"].(bool); active {
				return Result{Status: StatusPass, Message: "token introspects as active", Evidence: resp.Evidence}
			}
			return Result{Status: StatusFail, Message: "issued token reported inactive", Evidence: resp.Evidence}
		},
	})
}

func introspect(t *Target, token string) (*probe.Response, error) {
	form := probe.FormString("token", token)
	h := t.clientAuth(form)
	return probe.PostForm(t.Context(), t.httpClient(), t.Discovered.IntrospectionEndpoint, form, h)
}
