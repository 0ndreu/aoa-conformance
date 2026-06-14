package conformance

import (
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
)

// discoverInto runs discovery against an issuer and returns the populated target.
// Defined once here; reused across check test files.
func discoverInto(t *testing.T, issuer string) *Target {
	t.Helper()
	tgt := &Target{Issuer: issuer}
	(&Runner{Registry: DefaultRegistry()}).Run(tgt)
	return tgt
}

func TestRFC8414_Reachable(t *testing.T) {
	good := fakeas.NewAS(fakeas.Violations{})
	defer good.Close()
	gt := discoverInto(t, good.URL)
	if got := runChecksFor(t, "RFC 8414", gt)["rfc8414.metadata.reachable"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8414_IssuerMatch(t *testing.T) {
	good := fakeas.NewAS(fakeas.Violations{})
	defer good.Close()
	bad := fakeas.NewAS(fakeas.Violations{MalformedDiscovery: true})
	defer bad.Close()

	gt := discoverInto(t, good.URL)
	if got := runChecksFor(t, "RFC 8414", gt)["rfc8414.metadata.issuer_match"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}
	bt := discoverInto(t, bad.URL)
	if got := runChecksFor(t, "RFC 8414", bt)["rfc8414.metadata.issuer_match"]; got.Status != StatusFail {
		t.Fatalf("want fail, got %s", got.Status)
	}
}

func TestRFC8414_TokenEndpointPresent(t *testing.T) {
	good := fakeas.NewAS(fakeas.Violations{})
	defer good.Close()
	gt := discoverInto(t, good.URL)
	if got := runChecksFor(t, "RFC 8414", gt)["rfc8414.metadata.token_endpoint_present"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8414_TokenEndpointHTTPS(t *testing.T) {
	good := fakeas.NewAS(fakeas.Violations{})
	defer good.Close()
	gt := discoverInto(t, good.URL)
	// httptest serves http://; the check treats 127.0.0.1 as an allowed dev exception.
	if got := runChecksFor(t, "RFC 8414", gt)["rfc8414.metadata.token_endpoint_https"]; got.Status != StatusPass {
		t.Fatalf("localhost dev exception: want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8414_JWKSURIPresent(t *testing.T) {
	good := fakeas.NewAS(fakeas.Violations{})
	defer good.Close()
	gt := discoverInto(t, good.URL)
	if got := runChecksFor(t, "RFC 8414", gt)["rfc8414.metadata.jwks_uri_present"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8414_GrantTypesAdvertised(t *testing.T) {
	good := fakeas.NewAS(fakeas.Violations{})
	defer good.Close()
	gt := discoverInto(t, good.URL)
	if got := runChecksFor(t, "RFC 8414", gt)["rfc8414.metadata.grant_types_advertised"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8414_SkipsWithoutIssuer(t *testing.T) {
	tgt := &Target{}
	if got := runChecksFor(t, "RFC 8414", tgt)["rfc8414.metadata.reachable"]; got.Status != StatusSkip {
		t.Fatalf("no issuer: want skip, got %s", got.Status)
	}
}

func TestRFC8414_SignedMetadataValid(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{EmitSignedMetadata: true})
	defer as.Close()
	tgt := discoverInto(t, as.URL)
	if got := runChecksFor(t, "RFC 8414", tgt)["rfc8414.metadata.signed_metadata_valid"]; got.Status != StatusPass {
		t.Fatalf("valid signed_metadata: want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8414_SignedMetadataInvalid(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{BadSignedMetadata: true})
	defer as.Close()
	tgt := discoverInto(t, as.URL)
	if got := runChecksFor(t, "RFC 8414", tgt)["rfc8414.metadata.signed_metadata_valid"]; got.Status != StatusFail {
		t.Fatalf("bad signed_metadata: want fail, got %s", got.Status)
	}
}

func TestRFC8414_SignedMetadataSkipsWhenAbsent(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	tgt := discoverInto(t, as.URL)
	if got := runChecksFor(t, "RFC 8414", tgt)["rfc8414.metadata.signed_metadata_valid"]; got.Status != StatusSkip {
		t.Fatalf("absent signed_metadata: want skip, got %s", got.Status)
	}
}
