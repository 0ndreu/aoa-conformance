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

func TestPKCE_AdvertiseS256_Fail(t *testing.T) {
	// A target that advertises no S256 at all fails.
	tgt := &Target{}
	tgt.Discovered.Issuer = "https://issuer.example"
	tgt.Discovered.CodeChallengeMethodsSupported = []string{"plain"}
	if got := runChecksFor(t, "RFC 7636 (PKCE)", tgt)["pkce.advertise.s256"]; got.Status != StatusFail {
		t.Fatalf("plain-only: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestPKCE_EnforceSkipsWithoutAuthCode(t *testing.T) {
	good := fakeas.NewAS(fakeas.Violations{})
	defer good.Close()
	gt := discoverInto(t, good.URL)
	if got := runChecksFor(t, "RFC 7636 (PKCE)", gt)["pkce.enforce.reject_plain"]; got.Status != StatusSkip {
		t.Fatalf("no auth_code token: want skip, got %s (%s)", got.Status, got.Message)
	}
}
