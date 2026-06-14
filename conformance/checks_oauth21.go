package conformance

import (
	"github.com/0ndreu/aoa-conformance/probe"
)

func registerOAuth21(r *Registry) {
	mk := func(id, section, desc string, run func(*Target) Result) Check {
		return Check{ID: CheckID(id), Profile: ProfileCore, RFC: "OAuth 2.1", Section: section,
			Severity: SeverityMUST, Description: desc,
			Precondition: func(t *Target) bool { return t.Discovered.TokenEndpoint != "" },
			Run:          run}
	}

	r.Add(
		mk("oauth21.token.reachable", "RFC 6749 §3.2", "token endpoint returns an HTTP response",
			func(t *Target) Result {
				form := probe.FormString("grant_type", "client_credentials")
				resp, err := probe.PostForm(t.Context(), t.httpClient(), t.Discovered.TokenEndpoint, form, nil)
				if err != nil {
					return Result{Status: StatusFail, Message: "token endpoint unreachable: " + err.Error()}
				}
				return Result{Status: StatusPass, Message: "token endpoint reachable", Evidence: resp.Evidence}
			}),

		mk("oauth21.token.rejects_unknown_grant", "RFC 6749 §5.2", "unknown grant_type is rejected with 400 + error",
			func(t *Target) Result {
				form := probe.FormString("grant_type", "bogus")
				resp, err := probe.PostForm(t.Context(), t.httpClient(), t.Discovered.TokenEndpoint, form, nil)
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
				}
				if resp.StatusCode == 200 {
					return Result{Status: StatusFail, Message: "unknown grant_type accepted", Evidence: resp.Evidence}
				}
				if resp.JSON()["error"] == nil {
					return Result{Status: StatusFail, Message: "rejected but no error field", Evidence: resp.Evidence}
				}
				return Result{Status: StatusPass, Message: "unknown grant_type rejected with error", Evidence: resp.Evidence}
			}),

		mk("oauth21.token.error_shape_rfc6749", "RFC 6749 §5.2", "error response is JSON with an error field",
			func(t *Target) Result {
				form := probe.FormString("grant_type", "bogus")
				resp, err := probe.PostForm(t.Context(), t.httpClient(), t.Discovered.TokenEndpoint, form, nil)
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
				}
				if _, ok := resp.JSON()["error"].(string); !ok {
					return Result{Status: StatusFail, Message: "error response is not JSON with an error field", Evidence: resp.Evidence}
				}
				return Result{Status: StatusPass, Message: "RFC 6749 §5.2 error shape", Evidence: resp.Evidence}
			}),
	)
}
