package conformance

import (
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
)

func TestCIMDAdvertisePassesWhenFlagSet(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{AdvertiseCIMD: true})
	defer as.Close()

	got := runChecksFor(t, "CIMD", discoverInto(t, as.URL))["cimd.advertise.supported"]
	if got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestCIMDAdvertiseSkipsWhenAbsent(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()

	got := runChecksFor(t, "CIMD", discoverInto(t, as.URL))["cimd.advertise.supported"]
	if got.Status != StatusSkip {
		t.Fatalf("want skip, got %s (%s)", got.Status, got.Message)
	}
}

func TestCIMDBehavioralPassesWhenASAcceptsURLClientID(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{AdvertiseCIMD: true})
	defer as.Close()

	got := runChecksFor(t, "CIMD", discoverInto(t, as.URL))["cimd.register.url_client_id"]
	if got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestCIMDBehavioralFailsWhenASRejectsURLClientID(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{AdvertiseCIMD: true, RejectCIMDClient: true})
	defer as.Close()

	got := runChecksFor(t, "CIMD", discoverInto(t, as.URL))["cimd.register.url_client_id"]
	if got.Status != StatusFail {
		t.Fatalf("want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestCIMDBehavioralSkipsWhenNotAdvertised(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()

	got := runChecksFor(t, "CIMD", discoverInto(t, as.URL))["cimd.register.url_client_id"]
	if got.Status != StatusSkip {
		t.Fatalf("want skip, got %s (%s)", got.Status, got.Message)
	}
}
