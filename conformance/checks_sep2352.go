package conformance

import "net/url"

func registerSEP2352(r *Registry) {
	r.Add(Check{
		ID: "sep2352.register.issuer_binding", Profile: Profile2026_07, RFC: "SEP-2352", Section: "DCR coherence",
		Severity:     SeverityMUST,
		Description:  "the DCR-issued registration_client_uri is bound to the AS issuer origin (no cross-issuer reuse)",
		Precondition: needs(registrationEndpoint, registeredClient),
		Run: func(t *Target) Result {
			rcu := t.Plan.RegistrationClientURI
			if rcu == "" {
				// RFC 7591 §3.2.1 makes registration_client_uri optional: it
				// comes back only with an RFC 7592 client-configuration
				// endpoint. SEP-2352 asks that stored credentials never be
				// replayed at another issuer, and a credential that was never
				// handed out cannot be.
				if t.Plan.RegistrationAccessToken != "" {
					return Result{Status: StatusFail,
						Message:  "registration returned a registration_access_token with no registration_client_uri, so nothing records which issuer the credential belongs to",
						Evidence: t.Plan.RegistrationEvidence}
				}
				return Result{Status: StatusPass,
					Message:  "registration handed back no client-configuration credential, so there is none that could be replayed at another issuer",
					Evidence: t.Plan.RegistrationEvidence}
			}
			if !sameOrigin(rcu, t.Discovered.Issuer) {
				return Result{Status: StatusFail,
					Message:  "registration_client_uri origin " + originOfURL(rcu) + " != issuer origin " + originOfURL(t.Discovered.Issuer),
					Evidence: t.Plan.RegistrationEvidence}
			}
			return Result{Status: StatusPass, Message: "registered credential bound to the issuer origin", Evidence: t.Plan.RegistrationEvidence}
		},
	})
}

func sameOrigin(a, b string) bool {
	oa := originOfURL(a)
	return oa != "" && oa == originOfURL(b)
}

func originOfURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}
