package conformance

import (
	"strings"

	"github.com/0ndreu/aoa-conformance/probe"
)

// obtainToken gets an access token for the checks that need to hold one
// (presentation, introspection, revocation), in order of preference:
//
//  1. a token the operator pasted in with --subject-token, or the one an
//     interactive --auth-code round captured — both land in Creds.SubjectToken;
//  2. a client_credentials token obtained as the resolved plan client.
//
// Reaching for client_credentials unconditionally is what made these checks
// unusable against real MCP servers: they issue public clients and do not
// offer that grant.
//
// It returns the token, the raw exchange as evidence (nil for a supplied
// token, which involved no exchange), and a transport error. An empty token
// with a nil error means the AS refused to issue one.
func obtainToken(t *Target) (string, []byte, error) {
	if tok := t.Creds.SubjectToken; tok != "" {
		return tok, nil, nil
	}
	form := probe.FormString("grant_type", "client_credentials")
	h := t.clientAuth(form)
	if scopes := t.Plan.Scopes; len(scopes) > 0 {
		form.Set("scope", strings.Join(scopes, " "))
	}
	resp, err := probe.PostForm(t.Context(), t.httpClient(), t.Discovered.TokenEndpoint, form, h)
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode != 200 {
		return "", resp.Evidence, nil
	}
	tok, _ := resp.JSON()["access_token"].(string)
	return tok, resp.Evidence, nil
}
