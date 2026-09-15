package conformance

import "github.com/0ndreu/aoa-conformance/probe"

// registerCIMD adds the Client-ID Metadata Documents checks (MCP 2026-07-28).
func registerCIMD(r *Registry) {
	r.Add(Check{
		ID: "cimd.advertise.supported", Profile: Profile2026_07, RFC: "CIMD", Section: "advertise",
		Severity:    SeverityMAY,
		Description: "AS advertises client_id_metadata_document_supported",
		Run: func(t *Target) Result {
			if t.Discovered.ClientIDMetadataDocumentSupported {
				return Result{Status: StatusPass, Message: "client_id_metadata_document_supported: true"}
			}
			return Result{Status: StatusSkip, SkipKind: SkipUnsupported, Message: "AS does not advertise client_id_metadata_document_supported"}
		},
	})

	r.Add(Check{
		ID: "cimd.register.url_client_id", Profile: Profile2026_07, RFC: "CIMD", Section: "behavior",
		Severity:     SeveritySHOULD,
		Description:  "AS fetches a URL (CIMD) client_id document and accepts the client",
		Precondition: needs(cimdAdvertised, authorizationEndpoint),
		Run:          runCIMDBehavioral,
	})
}

// runCIMDBehavioral presents a URL client_id to the authorization endpoint. A
// caller-supplied --cimd-client-url (Hints["cimd_client_url"]) is used verbatim
// so a remote AS can fetch it; otherwise the tool hosts a loopback document. When
// the loopback document is never fetched and the AS rejected the client, the AS
// most likely could not reach loopback, so the result is skip (indeterminate),
// never a false fail.
func runCIMDBehavioral(t *Target) Result {
	const redirectURI = "http://127.0.0.1:1/callback"
	docURL := t.Hints["cimd_client_url"]
	var hosted *probe.ClientDoc
	if docURL == "" {
		d, err := probe.HostClientDoc(redirectURI)
		if err != nil {
			return Result{Status: StatusError, Message: "could not host client-metadata document: " + err.Error()}
		}
		defer d.Close()
		hosted = d
		docURL = d.URL
	}
	res, err := probe.ProbeCIMDAuthorize(t.Context(), t.httpClient(), t.Discovered.AuthorizationEndpoint, docURL, redirectURI)
	if err != nil {
		return Result{Status: StatusError, Message: "authorize probe failed: " + err.Error()}
	}
	switch {
	case !res.Rejected:
		return Result{Status: StatusPass, Message: "AS accepted a URL client_id (CIMD)", Evidence: res.Evidence}
	case hosted != nil && !hosted.Fetched():
		return Result{Status: StatusSkip, SkipKind: SkipUntested, Message: "AS did not fetch the loopback client document (unreachable); pass --cimd-client-url to test this AS", Evidence: res.Evidence}
	default:
		return Result{Status: StatusFail, Message: "AS advertised CIMD but rejected the URL client_id with invalid_client", Evidence: res.Evidence}
	}
}
