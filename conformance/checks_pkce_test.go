package conformance

import (
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
)

func TestPKCE_AdvertiseS256(t *testing.T) {
	good := fakeas.NewAS(fakeas.Violations{})
	defer good.Close()
	bad := fakeas.NewAS(fakeas.Violations{AcceptPlainPKCE: true})
	defer bad.Close()

	gt := discoverInto(t, good.URL)
	if got := runChecksFor(t, "RFC 7636 (PKCE)", gt)["pkce.advertise.s256"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}
	// AcceptPlainPKCE advertises both plain and S256; that still contains S256,
	// so the advertise check passes. Confirm S256 is detected regardless.
	bt := discoverInto(t, bad.URL)
	if got := runChecksFor(t, "RFC 7636 (PKCE)", bt)["pkce.advertise.s256"]; got.Status != StatusPass {
		t.Fatalf("plain+S256 still advertises S256: want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestPKCE_EnforceSkipsWithoutAuthCode(t *testing.T) {
	good := fakeas.NewAS(fakeas.Violations{})
	defer good.Close()
	gt := discoverInto(t, good.URL)
	if got := runChecksFor(t, "RFC 7636 (PKCE)", gt)["pkce.enforce.reject_plain"]; got.Status != StatusSkip || got.SkipKind != SkipUntested {
		t.Fatalf("no auth_code token: want skip/untested, got %s/%s (%s)", got.Status, got.SkipKind, got.Message)
	}
}

// TestPKCE_EnforceAlwaysSkipsEvenWithAuthCode guards against reintroducing the
// fabricated-code false pass: a hardcoded, never-issued authorization code
// always gets invalid_grant from a real AS regardless of code_challenge_method,
// so a naive live check would report "downgrade rejected" without ever
// exercising PKCE enforcement. Until a dedicated, never-redeemed code is
// available, the check honestly reports its own limitation instead.
func TestPKCE_EnforceAlwaysSkipsEvenWithAuthCode(t *testing.T) {
	good := fakeas.NewAS(fakeas.Violations{})
	defer good.Close()
	gt := discoverInto(t, good.URL)
	gt.Creds.AuthCodeAvailable = true
	if got := runChecksFor(t, "RFC 7636 (PKCE)", gt)["pkce.enforce.reject_plain"]; got.Status != StatusSkip || got.SkipKind != SkipUntested {
		t.Fatalf("want skip/untested even with an auth-code token, got %s/%s (%s)", got.Status, got.SkipKind, got.Message)
	}
}
