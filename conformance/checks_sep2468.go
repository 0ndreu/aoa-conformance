package conformance

func registerSEP2468(r *Registry) {
	r.Add(
		Check{
			ID: "sep2468.advertise.iss_parameter", Profile: ProfileJuly28RC, RFC: "SEP-2468", Section: "advertise",
			Severity:     SeverityMUST,
			Description:  "AS metadata sets authorization_response_iss_parameter_supported (RC hardens this to MUST)",
			Precondition: func(t *Target) bool { return len(t.Discovered.RawASMetadata) > 0 },
			Run: func(t *Target) Result {
				if !t.Discovered.AuthorizationResponseIssParameterSupported {
					return Result{Status: StatusFail,
						Message:  "authorization_response_iss_parameter_supported absent or false (RC hardens it to MUST)",
						Evidence: t.Discovered.RawASMetadata}
				}
				return Result{Status: StatusPass,
					Message:  "authorization_response_iss_parameter_supported advertised",
					Evidence: t.Discovered.RawASMetadata}
			},
		},
		Check{
			ID: "sep2468.authorize.iss_present", Profile: ProfileJuly28RC, RFC: "SEP-2468", Section: "authorize",
			Severity:     SeverityMUST,
			Description:  "authorization response carries iss matching the issuer (RC hardens RFC 9207 to MUST)",
			Precondition: func(t *Target) bool { return t.Creds.AuthCodeAvailable },
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
		},
	)
}
