package conformance

func registerRFC8705(r *Registry) {
	r.Add(Check{
		ID: "rfc8705.advertise.mtls_bound", Profile: ProfileExtended, RFC: "RFC 8705", Section: "§3.3",
		Severity:     SeverityMAY,
		Description:  "mTLS-bound access tokens are advertised coherently (flag + endpoint aliases)",
		Precondition: func(t *Target) bool { return t.Discovered.TLSClientCertificateBoundAccessTokens },
		Run: func(t *Target) Result {
			if len(t.Discovered.MTLSEndpointAliases) == 0 {
				return Result{Status: StatusFail,
					Message: "tls_client_certificate_bound_access_tokens set but mtls_endpoint_aliases absent"}
			}
			return Result{Status: StatusPass, Message: "mTLS binding advertised with endpoint aliases"}
		},
	})
}
