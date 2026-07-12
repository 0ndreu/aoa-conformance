package conformance

import (
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
)

func TestSEP2351_SuffixPathResolves(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{})
	defer rs.Close()
	tgt := &Target{MCPURL: rs.URL + "/mcp"}
	got := runChecksFor(t, "SEP-2351", tgt)["sep2351.discovery.suffix_path"]
	if got.Status != StatusPass {
		t.Fatalf("suffix PRM served: want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestSEP2351_MissingSuffixFails(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{NoSuffixPRM: true})
	defer rs.Close()
	tgt := &Target{MCPURL: rs.URL + "/mcp"}
	got := runChecksFor(t, "SEP-2351", tgt)["sep2351.discovery.suffix_path"]
	if got.Status != StatusFail {
		t.Fatalf("suffix PRM absent: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestSEP2351_SkipsInIssuerMode(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	tgt := &Target{Issuer: as.URL} // no MCPURL to suffix
	got := runChecksFor(t, "SEP-2351", tgt)["sep2351.discovery.suffix_path"]
	if got.Status != StatusSkip {
		t.Fatalf("issuer mode: want skip, got %s", got.Status)
	}
}
