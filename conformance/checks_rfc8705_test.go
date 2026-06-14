package conformance

import (
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
)

func TestRFC8705_MTLSBoundCoherent(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{AdvertiseMTLS: true})
	defer as.Close()
	tgt := discoverInto(t, as.URL)
	if got := runChecksFor(t, "RFC 8705", tgt)["rfc8705.advertise.mtls_bound"]; got.Status != StatusPass {
		t.Fatalf("coherent mTLS: want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8705_MTLSBoundIncoherent(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{IncoherentMTLS: true})
	defer as.Close()
	tgt := discoverInto(t, as.URL)
	if got := runChecksFor(t, "RFC 8705", tgt)["rfc8705.advertise.mtls_bound"]; got.Status != StatusFail {
		t.Fatalf("incoherent mTLS: want fail, got %s", got.Status)
	}
}

func TestRFC8705_SkipsWhenNotAdvertised(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	tgt := discoverInto(t, as.URL)
	if got := runChecksFor(t, "RFC 8705", tgt)["rfc8705.advertise.mtls_bound"]; got.Status != StatusSkip {
		t.Fatalf("not advertised: want skip, got %s", got.Status)
	}
}
