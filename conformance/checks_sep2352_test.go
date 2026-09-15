package conformance

import (
	"strings"
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

// RFC 7591 returns registration_client_uri only alongside a client-configuration
// endpoint. Semrush's AS returns neither it nor a registration access token, and
// scoring that a MUST-level break is what made the matrix claim the server has
// no registration endpoint at all.
func TestSEP2352_NoClientConfigCredentialPassesAndDCRReadsSupported(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{NoClientConfigEndpoint: true})
	defer as.Close()

	tgt := &Target{Issuer: as.URL}
	rep := (&Runner{Registry: DefaultRegistry(), ResolveOpts: &ResolveOptions{}}).Run(tgt)
	if !tgt.Plan.Registered {
		t.Fatal("precondition: expected DCR to register a client")
	}

	got := runChecksFor(t, "SEP-2352", tgt)["sep2352.register.issuer_binding"]
	if got.Status != StatusPass {
		t.Fatalf("no client-configuration credential: want pass, got %s (%s)", got.Status, got.Message)
	}
	if !strings.Contains(got.Message, "replayed at another issuer") {
		t.Errorf("message should say why there is nothing to bind: %q", got.Message)
	}

	for _, c := range rep.Capabilities {
		if c.Key == "dcr" && c.State != CapSupported {
			t.Fatalf("DCR row: want supported, got %s (%s)", c.State, c.Reason)
		}
	}
}

// a registration access token with no URI to bind it to is the real hazard the
// SEP names: a credential with no recorded issuer.
func TestSEP2352_AccessTokenWithoutURIFails(t *testing.T) {
	tgt := newRegisteredTarget(t, fakeas.Violations{})
	tgt.Plan.RegistrationClientURI = ""
	got := runChecksFor(t, "SEP-2352", tgt)["sep2352.register.issuer_binding"]
	if got.Status != StatusFail {
		t.Fatalf("unbound registration_access_token: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestSEP2352_SkipsWithoutDCR(t *testing.T) {
	tgt := newRegisteredTarget(t, fakeas.Violations{NoRegistration: true})
	got := runChecksFor(t, "SEP-2352", tgt)["sep2352.register.issuer_binding"]
	if got.Status != StatusSkip {
		t.Fatalf("no DCR: want skip, got %s", got.Status)
	}
}
