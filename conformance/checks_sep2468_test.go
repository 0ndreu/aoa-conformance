package conformance

import (
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
)

func TestSEP2468_AdvertisePass(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{IssParamSupported: true})
	defer as.Close()
	tgt := discoverInto(t, as.URL)
	got := runChecksFor(t, "SEP-2468", tgt)["sep2468.advertise.iss_parameter"]
	if got.Status != StatusPass {
		t.Fatalf("iss param advertised: want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestSEP2468_AdvertiseFailWhenAbsent(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{}) // IssParamSupported not set
	defer as.Close()
	tgt := discoverInto(t, as.URL)
	got := runChecksFor(t, "SEP-2468", tgt)["sep2468.advertise.iss_parameter"]
	if got.Status != StatusFail {
		t.Fatalf("iss param absent (RC MUST): want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestSEP2468_ReturnPass(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{IssParamSupported: true})
	defer as.Close()
	tgt := discoverInto(t, as.URL)
	tgt.Creds.AuthCodeAvailable = true
	tgt.Hints = map[string]string{"authorize_iss": tgt.Discovered.Issuer}
	got := runChecksFor(t, "SEP-2468", tgt)["sep2468.authorize.iss_present"]
	if got.Status != StatusPass {
		t.Fatalf("matching callback iss: want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestSEP2468_ReturnMissingFails(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{IssParamSupported: true})
	defer as.Close()
	tgt := discoverInto(t, as.URL)
	tgt.Creds.AuthCodeAvailable = true
	tgt.Hints = map[string]string{"authorize_iss": ""}
	got := runChecksFor(t, "SEP-2468", tgt)["sep2468.authorize.iss_present"]
	if got.Status != StatusFail {
		t.Fatalf("missing callback iss: want fail, got %s", got.Status)
	}
}

func TestSEP2468_ReturnSkipsWithoutAuthCode(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{IssParamSupported: true})
	defer as.Close()
	tgt := discoverInto(t, as.URL) // AuthCodeAvailable not set
	got := runChecksFor(t, "SEP-2468", tgt)["sep2468.authorize.iss_present"]
	if got.Status != StatusSkip {
		t.Fatalf("no auth-code: want skip, got %s", got.Status)
	}
}
