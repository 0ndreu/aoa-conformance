package conformance

func registerRFC9207(r *Registry) {
	r.Add(Check{
		ID: "rfc9207.authorize.iss_present", Profile: ProfileCore, RFC: "RFC 9207", Section: "§2",
		Severity:    SeveritySHOULD,
		Description: "authorization response carries iss matching the issuer when advertised",
		Precondition: func(t *Target) bool {
			return t.Discovered.AuthorizationResponseIssParameterSupported && t.Creds.AuthCodeAvailable
		},
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
