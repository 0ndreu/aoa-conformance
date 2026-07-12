package conformance

import (
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
)

// newRegisteredTarget discovers against a fresh fake AS and resolves the plan,
// triggering DCR when the AS advertises a registration endpoint. reused by the
// SEP-2352 tests.
func newRegisteredTarget(t *testing.T, v fakeas.Violations) *Target {
	t.Helper()
	as := fakeas.NewAS(v)
	t.Cleanup(as.Close)
	tgt := &Target{Issuer: as.URL}
	(&Runner{Registry: DefaultRegistry(), ResolveOpts: &ResolveOptions{}}).Run(tgt)
	return tgt
}

func TestSEP837_ApplicationTypeEchoed(t *testing.T) {
	tgt := newRegisteredTarget(t, fakeas.Violations{})
	if !tgt.Plan.Registered {
		t.Fatal("precondition: expected DCR to register a client")
	}
	got := runChecksFor(t, "SEP-837", tgt)["sep837.register.application_type"]
	if got.Status != StatusPass {
		t.Fatalf("native echoed: want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestSEP837_MangledFails(t *testing.T) {
	tgt := newRegisteredTarget(t, fakeas.Violations{MangleApplicationType: true})
	got := runChecksFor(t, "SEP-837", tgt)["sep837.register.application_type"]
	if got.Status != StatusFail {
		t.Fatalf("mangled application_type: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestSEP837_SkipsWithoutDCR(t *testing.T) {
	tgt := newRegisteredTarget(t, fakeas.Violations{NoRegistration: true})
	got := runChecksFor(t, "SEP-837", tgt)["sep837.register.application_type"]
	if got.Status != StatusSkip {
		t.Fatalf("no registration endpoint: want skip, got %s", got.Status)
	}
}
