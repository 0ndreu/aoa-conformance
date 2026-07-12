package conformance

import "net/url"

func registerSEP2352(r *Registry) {
	r.Add(Check{
		ID: "sep2352.register.issuer_binding", Profile: ProfileJuly28RC, RFC: "SEP-2352", Section: "DCR coherence",
		Severity:     SeveritySHOULD,
		Description:  "the DCR-issued registration_client_uri is bound to the AS issuer origin (no cross-issuer reuse)",
		Precondition: func(t *Target) bool { return t.Plan.Registered },
		Run: func(t *Target) Result {
			rcu := t.Plan.RegistrationClientURI
			if rcu == "" {
				return Result{Status: StatusFail, Message: "registered client has no registration_client_uri to bind to the issuer", Evidence: t.Plan.RegistrationEvidence}
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
