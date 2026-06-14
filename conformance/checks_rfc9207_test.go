package conformance

import (
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
)

func iss9207Target(t *testing.T, advertised bool, callbackISS string) *Target {
	t.Helper()
	as := fakeas.NewAS(fakeas.Violations{IssParamSupported: advertised})
	t.Cleanup(as.Close)
	tgt := discoverInto(t, as.URL)
	tgt.Creds.AuthCodeAvailable = true
	if tgt.Hints == nil {
		tgt.Hints = map[string]string{}
	}
	tgt.Hints["authorize_iss"] = callbackISS
	return tgt
}

func TestRFC9207_IssPresentMatches(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{IssParamSupported: true})
	defer as.Close()
	tgt := discoverInto(t, as.URL)
	tgt.Creds.AuthCodeAvailable = true
	tgt.Hints = map[string]string{"authorize_iss": tgt.Discovered.Issuer}
	if got := runChecksFor(t, "RFC 9207", tgt)["rfc9207.authorize.iss_present"]; got.Status != StatusPass {
		t.Fatalf("matching iss: want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC9207_IssMissingFails(t *testing.T) {
	tgt := iss9207Target(t, true, "")
	if got := runChecksFor(t, "RFC 9207", tgt)["rfc9207.authorize.iss_present"]; got.Status != StatusFail {
		t.Fatalf("advertised but missing iss: want fail, got %s", got.Status)
	}
}

func TestRFC9207_SkipsWithoutAuthCode(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{IssParamSupported: true})
	defer as.Close()
	tgt := discoverInto(t, as.URL) // AuthCodeAvailable not set
	if got := runChecksFor(t, "RFC 9207", tgt)["rfc9207.authorize.iss_present"]; got.Status != StatusSkip {
		t.Fatalf("no auth-code: want skip, got %s", got.Status)
	}
}
