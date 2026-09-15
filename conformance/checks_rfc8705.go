package conformance

func registerRFC8705(r *Registry) {
	r.Add(Check{
		ID: "rfc8705.advertise.mtls_bound", Profile: ProfileExtended, RFC: "RFC 8705", Section: "§3.3",
		Severity:    SeverityMAY,
		Description: "mTLS-bound access tokens are advertised coherently (flag + endpoint aliases)",
		Precondition: needs(func(t *Target) SkipReason {
			if !t.Discovered.TLSClientCertificateBoundAccessTokens {
				return Unsupported("AS does not advertise tls_client_certificate_bound_access_tokens")
			}
			return satisfied
		}),
		Run: func(t *Target) Result {
			if len(t.Discovered.MTLSEndpointAliases) == 0 {
				return Result{Status: StatusFail,
					Message: "tls_client_certificate_bound_access_tokens set but mtls_endpoint_aliases absent"}
			}
			return Result{Status: StatusPass, Message: "mTLS binding advertised with endpoint aliases"}
		},
	})
}
