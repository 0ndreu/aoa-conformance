package conformance

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/0ndreu/aoa-conformance/probe"
)

func registerRFC8414(r *Registry) {
	mk := func(id, section, desc string, sev Severity, run func(*Target) Result) Check {
		return Check{ID: CheckID(id), Profile: ProfileCore, RFC: "RFC 8414", Section: section,
			Severity: sev, Description: desc,
			Precondition: func(t *Target) bool { return t.Discovered.Issuer != "" },
			Run:          run}
	}

	r.Add(
		mk("rfc8414.metadata.reachable", "§3", "AS metadata document is reachable", SeverityMUST,
			func(t *Target) Result {
				if len(t.Discovered.RawASMetadata) == 0 {
					return Result{Status: StatusFail, Message: "no AS metadata document fetched"}
				}
				return Result{Status: StatusPass, Message: "metadata fetched", Evidence: t.Discovered.RawASMetadata}
			}),

		mk("rfc8414.metadata.issuer_match", "§3.3", "issuer in metadata equals the requested issuer", SeverityMUST,
			func(t *Target) Result {
				got := issuerFromRaw(t.Discovered.RawASMetadata)
				if got == "" {
					return Result{Status: StatusFail, Message: "metadata has no issuer field"}
				}
				if !sameIssuer(got, t.Discovered.Issuer) {
					return Result{Status: StatusFail,
						Message: fmt.Sprintf("issuer %q != requested %q", got, t.Discovered.Issuer)}
				}
				return Result{Status: StatusPass, Message: "issuer matches"}
			}),

		mk("rfc8414.metadata.token_endpoint_present", "§2", "token_endpoint is present", SeverityMUST,
			func(t *Target) Result {
				if t.Discovered.TokenEndpoint == "" {
					return Result{Status: StatusFail, Message: "token_endpoint missing"}
				}
				return Result{Status: StatusPass, Message: t.Discovered.TokenEndpoint}
			}),

		mk("rfc8414.metadata.token_endpoint_https", "§2", "token_endpoint uses https (localhost exempt)", SeverityMUST,
			func(t *Target) Result {
				u, err := url.Parse(t.Discovered.TokenEndpoint)
				if err != nil {
					return Result{Status: StatusFail, Message: "token_endpoint not a URL"}
				}
				if u.Scheme == "https" || isLocalhost(u.Host) {
					return Result{Status: StatusPass, Message: u.Scheme + "://" + u.Host}
				}
				return Result{Status: StatusFail, Message: "token_endpoint is not https: " + u.Scheme}
			}),

		mk("rfc8414.metadata.jwks_uri_present", "§2", "jwks_uri is present", SeveritySHOULD,
			func(t *Target) Result {
				if t.Discovered.JWKSURI == "" {
					return Result{Status: StatusFail, Message: "jwks_uri missing"}
				}
				return Result{Status: StatusPass, Message: t.Discovered.JWKSURI}
			}),

		mk("rfc8414.metadata.grant_types_advertised", "§2", "grant_types_supported is advertised", SeveritySHOULD,
			func(t *Target) Result {
				if len(t.Discovered.GrantTypesSupported) == 0 {
					return Result{Status: StatusFail, Message: "grant_types_supported missing"}
				}
				return Result{Status: StatusPass, Message: strings.Join(t.Discovered.GrantTypesSupported, ", ")}
			}),

		Check{
			ID: "rfc8414.metadata.signed_metadata_valid", Profile: ProfileCore, RFC: "RFC 8414", Section: "§2.1",
			Severity: SeveritySHOULD, Description: "signed_metadata JWT verifies against the issuer JWKS",
			Precondition: func(t *Target) bool {
				return t.Discovered.SignedMetadata != "" && t.Discovered.JWKSURI != ""
			},
			Run: func(t *Target) Result {
				err := probe.VerifyJWTWithJWKS(t.Context(), t.httpClient(), t.Discovered.SignedMetadata, t.Discovered.JWKSURI)
				if err != nil {
					return Result{Status: StatusFail, Message: "signed_metadata invalid: " + err.Error()}
				}
				return Result{Status: StatusPass, Message: "signed_metadata signature valid"}
			},
		},
	)
}

func issuerFromRaw(raw []byte) string {
	var m struct {
		Issuer string `json:"issuer"`
	}
	_ = jsonUnmarshal(raw, &m)
	return m.Issuer
}

func sameIssuer(a, b string) bool {
	return strings.TrimRight(a, "/") == strings.TrimRight(b, "/")
}

func isLocalhost(host string) bool {
	h := host
	if i := strings.LastIndex(host, ":"); i >= 0 && !strings.Contains(host, "]") {
		h = host[:i]
	}
	return h == "127.0.0.1" || h == "localhost" || h == "[::1]" || h == "::1"
}
