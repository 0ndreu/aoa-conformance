package conformance

import "github.com/0ndreu/aoa-conformance/probe"

// The gates shared by more than one checks_*.go file. Each names the exact
// metadata field or CLI flag that is missing, so a skipped check in the report
// is self-explanatory: either the server does not offer the capability, or the
// operator did not supply the input that would test it.

// mcpTarget requires a resource server under test (--target).
func mcpTarget(t *Target) SkipReason {
	if t.MCPURL == "" {
		return Untested("no MCP server under test; run with --target <mcp-url>")
	}
	return satisfied
}

// resolvedIssuer requires discovery to have landed on an authorization server.
func resolvedIssuer(t *Target) SkipReason {
	if t.Discovered.Issuer == "" {
		return Unsupported("no authorization server issuer resolved during discovery")
	}
	return satisfied
}

// asMetadata requires a fetched RFC 8414 metadata document.
func asMetadata(t *Target) SkipReason {
	if len(t.Discovered.RawASMetadata) == 0 {
		return Unsupported("no authorization server metadata document was fetched")
	}
	return satisfied
}

// tokenEndpoint requires an advertised token_endpoint.
func tokenEndpoint(t *Target) SkipReason {
	if t.Discovered.TokenEndpoint == "" {
		return Unsupported("AS metadata advertises no token_endpoint")
	}
	return satisfied
}

// authorizationEndpoint requires an advertised authorization_endpoint.
func authorizationEndpoint(t *Target) SkipReason {
	if t.Discovered.AuthorizationEndpoint == "" {
		return Unsupported("AS metadata advertises no authorization_endpoint")
	}
	return satisfied
}

// registrationEndpoint requires an advertised RFC 7591 registration_endpoint.
func registrationEndpoint(t *Target) SkipReason {
	if t.Discovered.RegistrationEndpoint == "" {
		return Unsupported("AS metadata advertises no registration_endpoint")
	}
	return satisfied
}

// introspectionEndpoint requires an advertised RFC 7662 introspection_endpoint.
func introspectionEndpoint(t *Target) SkipReason {
	if t.Discovered.IntrospectionEndpoint == "" {
		return Unsupported("AS metadata advertises no introspection_endpoint")
	}
	return satisfied
}

// revocationEndpoint requires an advertised RFC 7009 revocation_endpoint.
func revocationEndpoint(t *Target) SkipReason {
	if t.Discovered.RevocationEndpoint == "" {
		return Unsupported("AS metadata advertises no revocation_endpoint")
	}
	return satisfied
}

// introspectionForRevocation requires the introspection endpoint the revocation
// probe reads its answer from. An AS is free to offer revocation without
// introspection, so this is the verification path missing, not the capability:
// untested, and gated after revocationEndpoint so a genuinely absent revocation
// endpoint still reports as unsupported.
func introspectionForRevocation(t *Target) SkipReason {
	if t.Discovered.IntrospectionEndpoint == "" {
		return Untested("revocation was not verified: the AS advertises no introspection_endpoint to confirm the token went inactive")
	}
	return satisfied
}

// planClient requires a client the run can act as: supplied with --client-id
// or obtained by dynamic registration. A public client (no secret) qualifies.
func planClient(t *Target) SkipReason {
	if !t.Plan.hasClient() {
		if t.Plan.RegistrationError != "" {
			return Untested("no usable client: dynamic registration failed (" + t.Plan.RegistrationError + "); pass --client-id")
		}
		return Untested("no usable client; pass --client-id (with --client-secret for a confidential client) or point at an AS that allows dynamic registration")
	}
	return satisfied
}

// clientCredentialsGrant requires the AS to offer the machine-to-machine grant
// the token-endpoint probes mint their own token with. Most public MCP
// authorization servers do not offer it, and that says nothing about the
// capability under test — so the skip is untested, not unsupported: calling a
// server non-conformant because we had no way to drive the probe is the same
// false negative in a different costume.
func clientCredentialsGrant(t *Target) SkipReason {
	g := t.Discovered.GrantTypesSupported
	if len(g) == 0 {
		return satisfied // nothing advertised: try it and let the AS answer
	}
	for _, x := range g {
		if x == "client_credentials" {
			return satisfied
		}
	}
	return Untested("this check mints its own token and the AS does not advertise the client_credentials grant")
}

// grantRejected reports whether resp is the AS declining the grant type
// itself (unsupported_grant_type) rather than answering the check's actual
// question. A check that mints its own client_credentials token can reach
// this even when clientCredentialsGrant let it through — an AS is allowed to
// omit grant_types_supported entirely (RFC 8414 defaults it to
// authorization_code + implicit) and still not support client_credentials.
// Scoring that response a MUST-level protocol failure would be exactly the
// false negative the untested/unsupported split exists to prevent.
func grantRejected(resp *probe.Response) bool {
	return resp != nil && resp.JSON()["error"] == "unsupported_grant_type"
}

// tokenSource requires some way to get an access token: a token the operator
// pasted in (--subject-token, or the one an interactive --auth-code round
// captured), or a client the run can obtain one as.
func tokenSource(t *Target) SkipReason {
	if t.Creds.hasSubject() {
		return satisfied
	}
	if t.Plan.hasClient() && clientCredentialsGrant(t) == satisfied {
		return satisfied
	}
	return Untested("no token source; pass --subject-token, run with --auth-code, or supply --client-id at an AS offering client_credentials")
}

// registeredClient requires that this run performed a dynamic registration:
// the DCR response is the evidence the check inspects.
func registeredClient(t *Target) SkipReason {
	if !t.Plan.Registered {
		return Untested("no dynamic client registration was performed in this run")
	}
	return satisfied
}

// subjectToken requires a user token to act on (--subject-token).
func subjectToken(t *Target) SkipReason {
	if !t.Creds.hasSubject() {
		return Untested("needs --subject-token (a user token to exchange)")
	}
	return satisfied
}

// authCodeFlow requires a completed interactive authorization-code round.
func authCodeFlow(t *Target) SkipReason {
	if !t.Creds.AuthCodeAvailable {
		return Untested("needs --auth-code (an interactive authorization-code round)")
	}
	return satisfied
}

// issParameterAdvertised requires the AS to claim RFC 9207 support before the
// authorization response is judged against it.
func issParameterAdvertised(t *Target) SkipReason {
	if !t.Discovered.AuthorizationResponseIssParameterSupported {
		return Unsupported("AS does not advertise authorization_response_iss_parameter_supported")
	}
	return satisfied
}

// cimdAdvertised requires the AS to claim Client-ID Metadata Document support.
func cimdAdvertised(t *Target) SkipReason {
	if !t.Discovered.ClientIDMetadataDocumentSupported {
		return Unsupported("AS does not advertise client_id_metadata_document_supported")
	}
	return satisfied
}
