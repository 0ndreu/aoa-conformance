package conformance

func registerSEP2468(r *Registry) {
	r.Add(
		Check{
			ID: "sep2468.advertise.iss_parameter", Profile: Profile2026_07, RFC: "SEP-2468", Section: "advertise",
			Severity:     SeveritySHOULD,
			Description:  "AS metadata sets authorization_response_iss_parameter_supported",
			Precondition: needs(asMetadata),
			Run: func(t *Target) Result {
				if !t.Discovered.AuthorizationResponseIssParameterSupported {
					return Result{Status: StatusFail,
						Message:  "authorization_response_iss_parameter_supported absent or false; a future revision raises this to MUST",
						Evidence: t.Discovered.RawASMetadata}
				}
				return Result{Status: StatusPass,
					Message:  "authorization_response_iss_parameter_supported advertised",
					Evidence: t.Discovered.RawASMetadata}
			},
		},
		Check{
			ID: "sep2468.authorize.iss_present", Profile: Profile2026_07, RFC: "SEP-2468", Section: "authorize",
			Severity:     SeveritySHOULD,
			Description:  "authorization response carries iss matching the issuer (RFC 9207)",
			Precondition: needs(authCodeFlow),
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
