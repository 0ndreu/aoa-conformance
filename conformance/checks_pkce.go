package conformance

import (
	"strings"
)

func registerPKCE(r *Registry) {
	r.Add(
		Check{
			ID: "pkce.advertise.s256", Profile: ProfileCore, RFC: "RFC 7636 (PKCE)", Section: "§4.2",
			Severity: SeverityMUST, Description: "S256 code_challenge_method is advertised",
			Precondition: needs(resolvedIssuer),
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
			Precondition: needs(resolvedIssuer, authCodeFlow),
			// a genuine downgrade probe needs its own, never-redeemed
			// authorization code (attempt the exchange with code_challenge_method
			// = plain and code_verifier = the S256 challenge, which is all an
			// on-path attacker would have observed); the code obtained by
			// --auth-code is already consumed by the legitimate exchange other
			// checks depend on, and a second interactive round is not something
			// a Run function can open. Until that plumbing exists, reporting a
			// fabricated request's "invalid_grant" as a pass would be dishonest —
			// every AS rejects an unknown code regardless of PKCE enforcement, so
			// the previous version of this check always passed without testing
			// anything.
			Run: func(t *Target) Result {
				return Result{Status: StatusSkip, SkipKind: SkipUntested,
					Message: "cannot yet probe a live plain-PKCE downgrade: it needs a dedicated authorization code that --auth-code's shared exchange doesn't provide"}
			},
		},
	)
}
