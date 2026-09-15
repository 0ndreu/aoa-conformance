package conformance

import (
	"net/url"
	"strings"

	"github.com/0ndreu/aoa-conformance/probe"
)

func registerSEP2207(r *Registry) {
	r.Add(Check{
		ID: "sep2207.refresh.scope_semantics", Profile: Profile2026_07, RFC: "SEP-2207", Section: "refresh scope",
		Severity:    SeveritySHOULD,
		Description: "a refresh with a narrowed scope is honored without widening (RFC 6749 §6)",
		Precondition: needs(tokenEndpoint, func(t *Target) SkipReason {
			if t.Creds.RefreshToken == "" {
				return Untested("no refresh token; needs --auth-code with an offline-capable scope")
			}
			return satisfied
		}),
		Run: runRefreshScope,
	})
}

// runRefreshScope refreshes with a strict subset of the granted scope and fails
// if the AS returns any scope outside that subset (a widening).
func runRefreshScope(t *Target) Result {
	granted := strings.Fields(t.Hints["granted_scope"])
	if len(granted) < 2 {
		return Result{Status: StatusSkip, SkipKind: SkipUntested, Message: "need at least two granted scopes to test narrowing; granted=" + t.Hints["granted_scope"]}
	}
	narrowed := granted[:len(granted)-1]
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", t.Creds.RefreshToken)
	form.Set("scope", strings.Join(narrowed, " "))
	h := t.clientAuth(form)
	resp, err := probe.PostForm(t.Context(), t.httpClient(), t.Discovered.TokenEndpoint, form, h)
	if err != nil {
		return Result{Status: StatusError, Message: "refresh request failed: " + err.Error()}
	}
	returned, _ := resp.JSON()["scope"].(string)
	allowed := map[string]bool{}
	for _, s := range narrowed {
		allowed[s] = true
	}
	for _, s := range strings.Fields(returned) {
		if !allowed[s] {
			return Result{Status: StatusFail,
				Message:  "refresh widened scope: returned " + returned + " exceeds requested " + strings.Join(narrowed, " "),
				Evidence: resp.Evidence}
		}
	}
	return Result{Status: StatusPass, Message: "refresh honored the narrowed scope: " + returned, Evidence: resp.Evidence}
}
