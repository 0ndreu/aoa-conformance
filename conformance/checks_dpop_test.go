package conformance

import (
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
)

func dpopTarget(t *testing.T, v fakeas.Violations) *Target {
	t.Helper()
	as := fakeas.NewAS(v)
	t.Cleanup(as.Close)
	tgt := discoverInto(t, as.URL)
	tgt.Creds.ClientID = "test-client"
	tgt.Creds.ClientSecret = "test-secret"
	return tgt
}

func TestDPoP_AdvertiseAlgs(t *testing.T) {
	tgt := dpopTarget(t, fakeas.Violations{})
	if got := runChecksFor(t, "RFC 9449", tgt)["dpop.advertise.algs"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestDPoP_AcceptsProof(t *testing.T) {
	tgt := dpopTarget(t, fakeas.Violations{})
	if got := runChecksFor(t, "RFC 9449", tgt)["dpop.token.accepts_proof"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestDPoP_AcceptsProof_Fail(t *testing.T) {
	bad := dpopTarget(t, fakeas.Violations{RejectValidDPoP: true})
	if got := runChecksFor(t, "RFC 9449", bad)["dpop.token.accepts_proof"]; got.Status != StatusFail {
		t.Fatalf("valid proof rejected: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestDPoP_NonceChallenge(t *testing.T) {
	good := dpopTarget(t, fakeas.Violations{})
	if got := runChecksFor(t, "RFC 9449", good)["dpop.token.nonce_challenge"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}

	bad := dpopTarget(t, fakeas.Violations{SkipDPoPNonce: true})
	if got := runChecksFor(t, "RFC 9449", bad)["dpop.token.nonce_challenge"]; got.Status != StatusFail {
		t.Fatalf("skip nonce: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestDPoP_BindsCnfJkt(t *testing.T) {
	good := dpopTarget(t, fakeas.Violations{})
	if got := runChecksFor(t, "RFC 9449", good)["dpop.token.binds_cnf_jkt"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}

	bad := dpopTarget(t, fakeas.Violations{NoCnfBinding: true})
	if got := runChecksFor(t, "RFC 9449", bad)["dpop.token.binds_cnf_jkt"]; got.Status != StatusFail {
		t.Fatalf("no cnf binding: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestDPoP_RejectsWrongHTU(t *testing.T) {
	good := dpopTarget(t, fakeas.Violations{})
	if got := runChecksFor(t, "RFC 9449", good)["dpop.token.rejects_wrong_htu"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}

	bad := dpopTarget(t, fakeas.Violations{AcceptWrongHTU: true})
	if got := runChecksFor(t, "RFC 9449", bad)["dpop.token.rejects_wrong_htu"]; got.Status != StatusFail {
		t.Fatalf("accept wrong htu: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestDPoP_SkipsWhenNotAdvertised(t *testing.T) {
	tgt := dpopTarget(t, fakeas.Violations{NoDPoP: true})
	if got := runChecksFor(t, "RFC 9449", tgt)["dpop.token.accepts_proof"]; got.Status != StatusSkip {
		t.Fatalf("not advertised: want skip, got %s", got.Status)
	}
	if got := runChecksFor(t, "RFC 9449", tgt)["dpop.advertise.algs"]; got.Status != StatusSkip {
		t.Fatalf("not advertised: want skip, got %s", got.Status)
	}
}
