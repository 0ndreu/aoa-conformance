package conformance

func registerRFC9207(r *Registry) {
	r.Add(Check{
		ID: "rfc9207.authorize.iss_present", Profile: ProfileCore, RFC: "RFC 9207", Section: "§2",
		// the precondition below (issParameterAdvertised) already requires the AS
		// to have declared support; RFC 9207 §2 says that once declared, iss MUST
		// be present. Unlike sep2468.authorize.iss_present (checks_sep2468.go),
		// which runs unconditionally and is deliberately softened to SHOULD, this
		// check only ever runs once the MUST clause is squarely in effect.
		Severity:     SeverityMUST,
		Description:  "authorization response carries iss matching the issuer when advertised",
		Precondition: needs(issParameterAdvertised, authCodeFlow),
		Run: func(t *Target) Result {
			iss := t.Hints["authorize_iss"]
			if iss == "" {
				return Result{Status: StatusFail, Message: "authorization response carried no iss parameter"}
			}
			if !sameIssuer(iss, t.Discovered.Issuer) {
				return Result{Status: StatusFail, Message: "callback iss " + iss + " != issuer " + t.Discovered.Issuer}
			}
			return Result{Status: StatusPass, Message: "iss present and matches issuer"}
		},
	})
}
