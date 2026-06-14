package conformance

import (
	"fmt"
	"strings"

	"github.com/0ndreu/aoa-conformance/probe"
)

func registerSmoke(r *Registry) {
	r.Add(Check{
		ID: "smoke.present.token_accepted", Profile: ProfileCore, RFC: "MCP loop", Section: "",
		Severity: SeveritySHOULD, Description: "a token obtained from the AS is accepted by the MCP resource server",
		Precondition: func(t *Target) bool {
			return t.MCPURL != "" && t.Creds.PresentEnabled &&
				(t.Creds.hasSubject() || t.Plan.hasClient())
		},
		Run: func(t *Target) Result {
			token := t.Creds.SubjectToken
			if token == "" {
				// obtain a client_credentials token.
				form := probe.FormString("grant_type", "client_credentials")
				h := t.clientAuth(form)
				if scopes := t.Plan.Scopes; len(scopes) > 0 {
					form.Set("scope", strings.Join(scopes, " "))
				}
				resp, err := probe.PostForm(t.Context(), t.httpClient(), t.Discovered.TokenEndpoint, form, h)
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

			var dpopKey *probe.ProofKey
			if t.Plan.DPoPRequired {
				k, err := probe.NewProofKey()
				if err != nil {
					return Result{Status: StatusError, Message: "dpop key: " + err.Error()}
				}
				dpopKey = k
			}

			resp, err := presentWithRetry(t, token, dpopKey)
			if err != nil {
				return Result{Status: StatusError, Message: "presenting token failed: " + err.Error()}
			}
			switch resp.StatusCode {
			case 401:
				return Result{Status: StatusFail, Message: "resource server rejected the token (401)", Evidence: resp.Evidence}
			case 403:
				return Result{Status: StatusFail, Message: "token authenticated but lacks required scope (403)", Evidence: resp.Evidence}
			}
			if resp.StatusCode >= 400 {
				return Result{Status: StatusFail, Message: fmt.Sprintf("resource server returned HTTP %d", resp.StatusCode), Evidence: resp.Evidence}
			}
			return Result{Status: StatusPass, Message: "token accepted by resource server", Evidence: resp.Evidence}
		},
	})
}

// presentWithRetry presents the token to the resource and retries once when the
// resource answers a DPoP request with a use_dpop_nonce challenge.
func presentWithRetry(t *Target, token string, key *probe.ProofKey) (*probe.Response, error) {
	in := probe.PresentInput{ResourceURL: t.MCPURL, Token: token, Method: t.Plan.BearerMethod, DPoP: key}
	resp, err := probe.PresentToken(t.Context(), t.httpClient(), in)
	if err != nil {
		return nil, err
	}
	if key != nil && resp.StatusCode == 401 {
		if nonce := resp.Header.Get("DPoP-Nonce"); nonce != "" {
			in.DPoPNonce = nonce
			return probe.PresentToken(t.Context(), t.httpClient(), in)
		}
	}
	return resp, nil
}
