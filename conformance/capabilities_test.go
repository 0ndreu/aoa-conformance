package conformance

import (
	"strings"
	"testing"
)

func capOf(caps []Capability, key string) Capability {
	for _, c := range caps {
		if c.Key == key {
			return c
		}
	}
	return Capability{}
}

// TestCapabilitiesAreThreeValued is the readiness criterion in miniature: the
// same report must say "supported", "not supported" and "not tested" about
// three different capabilities, and never conflate the last two.
func TestCapabilitiesAreThreeValued(t *testing.T) {
	entries := []Entry{
		{Check: Check{ID: "pkce.advertise.s256", Severity: SeverityMUST},
			Result: Result{Status: StatusPass, Message: "S256 advertised"}},
		{Check: Check{ID: "dpop.advertise.algs", Severity: SeverityMUST},
			Result: Result{Status: StatusSkip, SkipKind: SkipUnsupported,
				Message: "AS does not advertise dpop_signing_alg_values_supported"}},
		{Check: Check{ID: "rfc7662.introspect.active", Severity: SeverityMUST},
			Result: Result{Status: StatusSkip, SkipKind: SkipUntested,
				Message: "no token to introspect; pass --subject-token"}},
	}
	caps := Capabilities(entries)

	if got := capOf(caps, "pkce-s256"); got.State != CapSupported || !strings.Contains(got.Reason, "S256 advertised") {
		t.Errorf("pkce: want supported with the passing message, got %+v", got)
	}
	if got := capOf(caps, "dpop"); got.State != CapNotSupported || !strings.Contains(got.Reason, "dpop_signing_alg_values_supported") {
		t.Errorf("dpop: an absent capability must read not supported and name it, got %+v", got)
	}
	if got := capOf(caps, "introspection"); got.State != CapNotTested || !strings.Contains(got.Reason, "--subject-token") {
		t.Errorf("introspection: a withheld credential must read not tested and name the flag, got %+v", got)
	}
	// a capability no entry spoke to is not tested, not silently supported.
	if got := capOf(caps, "resource-indicators"); got.State != CapNotTested {
		t.Errorf("resource-indicators: no entries must yield not tested, got %+v", got)
	}
}

// TestCapabilitySurvivesShouldLevelShortfall guards the same bug Task 6 fixed
// for agent verdicts: a missing jwks_uri (SHOULD) must not make AS metadata
// read "not supported" when the MUST-level checks pass.
func TestCapabilitySurvivesShouldLevelShortfall(t *testing.T) {
	entries := []Entry{
		{Check: Check{ID: "rfc8414.metadata.reachable", Severity: SeverityMUST},
			Result: Result{Status: StatusPass, Message: "metadata reachable"}},
		{Check: Check{ID: "rfc8414.metadata.jwks_uri_present", Severity: SeveritySHOULD},
			Result: Result{Status: StatusFail, Message: "jwks_uri missing"}},
	}
	got := capOf(Capabilities(entries), "as-metadata")
	if got.State != CapSupported {
		t.Fatalf("a SHOULD shortfall next to a passing MUST must stay supported, got %q (%s)", got.State, got.Reason)
	}
	if !strings.Contains(got.Reason, "SHOULD/MAY") {
		t.Errorf("the shortfall must still be flagged in the reason, got %q", got.Reason)
	}
}

// TestCapabilityMustFailureIsNotSupported: a MUST-level failure is the answer
// the developer needs on the front page, not buried in a table.
func TestCapabilityMustFailureIsNotSupported(t *testing.T) {
	entries := []Entry{
		{Check: Check{ID: "rfc9728.prm.fetchable", Severity: SeverityMUST},
			Result: Result{Status: StatusFail, Message: "PRM returned 404"}},
	}
	got := capOf(Capabilities(entries), "prm-discovery")
	if got.State != CapNotSupported || !strings.Contains(got.Reason, "PRM returned 404") {
		t.Fatalf("want not supported naming the failure, got %+v", got)
	}
}

// TestEveryCapabilityHasBackingChecks keeps the matrix honest against renames:
// a spec whose prefixes match nothing in the registry would render a permanent
// "not tested" row that no run could ever answer.
func TestEveryCapabilityHasBackingChecks(t *testing.T) {
	checks := DefaultRegistry().Checks()
	for _, spec := range capabilitySpecs {
		found := false
		for _, c := range checks {
			if spec.matches(c.ID) {
				found = true
				break
			}
		}
		// the dcr row also hangs off the synthetic "registration" entry the
		// runner emits, which is not in the registry; assert on its prefix.
		if !found && !spec.matches("registration") {
			t.Errorf("capability %q matches no registered check (prefixes %v)", spec.key, spec.prefixes)
		}
	}
}

// TestMCPServerChecksHaveACapabilityRow guards the zero-credential
// mcp.challenge.*/mcp.token.* checks specifically: they need no credential at
// all to run, so they are exactly the checks a third-party report should lead
// with, not bury in the per-RFC tables below the matrix.
func TestMCPServerChecksHaveACapabilityRow(t *testing.T) {
	for _, c := range DefaultRegistry().Checks() {
		if !strings.HasPrefix(string(c.ID), "mcp.") {
			continue
		}
		matched := false
		for _, spec := range capabilitySpecs {
			if spec.matches(c.ID) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("check %q matches no capability row; add a prefix in capabilitySpecs", c.ID)
		}
	}
}
