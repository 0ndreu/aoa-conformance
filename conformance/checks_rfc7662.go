package conformance

import (
	"github.com/0ndreu/aoa-conformance/probe"
)

func registerRFC7662(r *Registry) {
	r.Add(Check{
		ID: "rfc7662.introspect.active", Profile: ProfileExtended, RFC: "RFC 7662", Section: "§2",
		Severity: SeverityMAY, Description: "an issued token introspects as active:true",
		Precondition: func(t *Target) bool {
			return t.Discovered.IntrospectionEndpoint != "" && t.Creds.hasClient()
		},
		Run: func(t *Target) Result {
			token, ev, err := obtainToken(t)
			if err != nil {
				return Result{Status: StatusError, Message: "obtain token: " + err.Error(), Evidence: ev}
			}
			if token == "" {
				return Result{Status: StatusSkip, Message: "could not obtain a token to introspect", Evidence: ev}
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

// obtainToken gets a client_credentials access token for use by introspection/
// revocation checks.
func obtainToken(t *Target) (string, []byte, error) {
	form := probe.FormString("grant_type", "client_credentials", "client_id", t.Creds.ClientID)
	if t.Creds.ClientSecret != "" {
		form.Set("client_secret", t.Creds.ClientSecret)
	}
	resp, err := probe.PostForm(t.Context(), t.httpClient(), t.Discovered.TokenEndpoint, form, nil)
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode != 200 {
		return "", resp.Evidence, nil
	}
	tok, _ := resp.JSON()["access_token"].(string)
	return tok, resp.Evidence, nil
}

func introspect(t *Target, token string) (*probe.Response, error) {
	form := probe.FormString("token", token, "client_id", t.Creds.ClientID)
	if t.Creds.ClientSecret != "" {
		form.Set("client_secret", t.Creds.ClientSecret)
	}
	return probe.PostForm(t.Context(), t.httpClient(), t.Discovered.IntrospectionEndpoint, form, nil)
}
