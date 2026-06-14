package conformance

import (
	"strings"

	"github.com/0ndreu/aoa-conformance/probe"
)

func registerPKCE(r *Registry) {
	r.Add(
		Check{
			ID: "pkce.advertise.s256", Profile: ProfileCore, RFC: "RFC 7636 (PKCE)", Section: "§4.2",
			Severity: SeverityMUST, Description: "S256 code_challenge_method is advertised",
			Precondition: func(t *Target) bool { return t.Discovered.Issuer != "" },
			Run: func(t *Target) Result {
				if t.Discovered.advertisesS256() {
					return Result{Status: StatusPass, Message: "S256 advertised: " + strings.Join(t.Discovered.CodeChallengeMethodsSupported, ", ")}
				}
				return Result{Status: StatusFail,
					Message: "S256 not advertised; methods: " + strings.Join(t.Discovered.CodeChallengeMethodsSupported, ", ")}
			},
		},

		Check{
			ID: "pkce.enforce.reject_plain", Profile: ProfileCore, RFC: "RFC 7636 (PKCE)", Section: "§4.4.1",
			Severity: SeverityMUST, Description: "a deliberate plain PKCE downgrade is rejected",
			Precondition: func(t *Target) bool {
				return t.Discovered.Issuer != "" && t.Creds.AuthCodeAvailable
			},
			Run: func(t *Target) Result {
				// with an auth_code-obtained token available, attempt a token
				// request using a plain code_challenge_method; a conformant AS
				// must reject it.
				form := probe.FormString(
					"grant_type", "authorization_code",
					"code", "downgrade-probe",
					"code_verifier", "plain-verifier",
					"code_challenge_method", "plain",
				)
				h := t.clientAuth(form)
				resp, err := probe.PostForm(t.Context(), t.httpClient(), t.Discovered.TokenEndpoint, form, h)
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
				}
				if resp.StatusCode == 200 {
					return Result{Status: StatusFail, Message: "plain PKCE downgrade accepted", Evidence: resp.Evidence}
				}
				return Result{Status: StatusPass, Message: "plain PKCE downgrade rejected", Evidence: resp.Evidence}
			},
		},
	)
}
