package conformance

import (
	"net/http"
	"strings"

	"github.com/0ndreu/aoa-conformance/probe"
)

func registerSmoke(r *Registry) {
	r.Add(Check{
		ID: "smoke.present.token_accepted", Profile: ProfileCore, RFC: "MCP loop", Section: "",
		Severity: SeveritySHOULD, Description: "a token obtained from the AS is accepted by the MCP resource server",
		Precondition: func(t *Target) bool {
			return t.MCPURL != "" && t.Creds.PresentEnabled &&
				(t.Creds.hasSubject() || t.Creds.hasClient())
		},
		Run: func(t *Target) Result {
			token := t.Creds.SubjectToken
			if token == "" {
				// obtain a client_credentials token.
				form := probe.FormString("grant_type", "client_credentials", "client_id", t.Creds.ClientID)
				if t.Creds.ClientSecret != "" {
					form.Set("client_secret", t.Creds.ClientSecret)
				}
				if scopes := EffectiveScopes(t.Creds.Scopes, t.Discovered.PRMScopesSupported); len(scopes) > 0 {
					form.Set("scope", strings.Join(scopes, " "))
				}
				resp, err := probe.PostForm(t.Context(), t.httpClient(), t.Discovered.TokenEndpoint, form, nil)
				if err != nil {
					return Result{Status: StatusError, Message: "token request failed: " + err.Error()}
				}
				if resp.StatusCode != 200 {
					return Result{Status: StatusSkip, Message: "could not obtain a token to present", Evidence: resp.Evidence}
				}
				token, _ = resp.JSON()["access_token"].(string)
			}
			if token == "" {
				return Result{Status: StatusSkip, Message: "no token obtainable"}
			}

			resp, err := probe.GetWithHeaders(t.Context(), t.httpClient(), t.MCPURL, http.Header{
				"Authorization": {"Bearer " + token},
			})
			if err != nil {
				return Result{Status: StatusError, Message: "presenting token failed: " + err.Error()}
			}
			if resp.StatusCode == 401 {
				return Result{Status: StatusFail, Message: "resource server rejected the obtained token (401)", Evidence: resp.Evidence}
			}
			return Result{Status: StatusPass, Message: "token accepted by resource server", Evidence: resp.Evidence}
		},
	})
}
