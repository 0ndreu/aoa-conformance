package conformance

import (
	"fmt"

	"github.com/0ndreu/aoa-conformance/probe"
)

func registerSmoke(r *Registry) {
	r.Add(Check{
		ID: "smoke.present.token_accepted", Profile: ProfileCore, RFC: "MCP loop", Section: "",
		Severity: SeveritySHOULD, Description: "a token obtained from the AS is accepted on a real MCP tools/list call",
		Precondition: needs(mcpTarget,
			func(t *Target) SkipReason {
				if !t.Creds.PresentEnabled {
					return Untested("needs --present to complete the agent loop against the resource server")
				}
				return satisfied
			},
			tokenSource,
		),
		Run: func(t *Target) Result {
			token, ev, err := obtainToken(t)
			if err != nil {
				return Result{Status: StatusError, Message: "token request failed: " + err.Error()}
			}
			if token == "" {
				return Result{Status: StatusSkip, SkipKind: SkipUntested,
					Message: "the AS issued no token to present; pass --subject-token", Evidence: ev}
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
			return Result{Status: StatusPass, Message: "token accepted on an MCP tools/list call", Evidence: resp.Evidence}
		},
	})
}

// presentWithRetry presents the token to the resource and retries once when the
// resource answers a DPoP request with a use_dpop_nonce challenge. The token
// always rides the Authorization header on a real MCP JSON-RPC POST: that is
// the presentation MCP §2.3 mandates of clients, and it is the only one a
// server has to accept. What PRM advertises is judged separately by
// mcp.token.header_method_advertised; presenting by an advertised method the
// server does not read would blame the token for the advertisement's mistake.
func presentWithRetry(t *Target, token string, key *probe.ProofKey) (*probe.Response, error) {
	in := probe.PresentInput{ResourceURL: t.MCPURL, Token: token, DPoP: key}
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
