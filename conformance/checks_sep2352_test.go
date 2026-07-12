package conformance

import (
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
)

func TestSEP2352_BoundToIssuerPasses(t *testing.T) {
	tgt := newRegisteredTarget(t, fakeas.Violations{})
	if !tgt.Plan.Registered {
		t.Fatal("precondition: expected DCR to register a client")
	}
	got := runChecksFor(t, "SEP-2352", tgt)["sep2352.register.issuer_binding"]
	if got.Status != StatusPass {
		t.Fatalf("same-origin registration_client_uri: want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestSEP2352_ForeignURIFails(t *testing.T) {
	tgt := newRegisteredTarget(t, fakeas.Violations{ForeignRegistrationURI: true})
	got := runChecksFor(t, "SEP-2352", tgt)["sep2352.register.issuer_binding"]
	if got.Status != StatusFail {
		t.Fatalf("cross-origin registration_client_uri: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestSEP2352_SkipsWithoutDCR(t *testing.T) {
	tgt := newRegisteredTarget(t, fakeas.Violations{NoRegistration: true})
	got := runChecksFor(t, "SEP-2352", tgt)["sep2352.register.issuer_binding"]
	if got.Status != StatusSkip {
		t.Fatalf("no DCR: want skip, got %s", got.Status)
	}
}
