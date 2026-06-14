package conformance

import (
	"net/http"
	"testing"
	"time"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
)

func TestOAuth21_Reachable(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	gt := discoverInto(t, as.URL)
	if got := runChecksFor(t, "OAuth 2.1", gt)["oauth21.token.reachable"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestOAuth21_RejectsUnknownGrant(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	gt := discoverInto(t, as.URL)
	if got := runChecksFor(t, "OAuth 2.1", gt)["oauth21.token.rejects_unknown_grant"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestOAuth21_ErrorShape(t *testing.T) {
	good := fakeas.NewAS(fakeas.Violations{})
	defer good.Close()
	gt := discoverInto(t, good.URL)
	if got := runChecksFor(t, "OAuth 2.1", gt)["oauth21.token.error_shape_rfc6749"]; got.Status != StatusPass {
		t.Fatalf("good AS: want pass, got %s (%s)", got.Status, got.Message)
	}

	bad := fakeas.NewAS(fakeas.Violations{BadErrorShape: true})
	defer bad.Close()
	bt := discoverInto(t, bad.URL)
	if got := runChecksFor(t, "OAuth 2.1", bt)["oauth21.token.error_shape_rfc6749"]; got.Status != StatusFail {
		t.Fatalf("bad error shape: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestOAuth21_Reachable_Fail(t *testing.T) {
	// hand-crafted target: token_endpoint precondition is met, but the endpoint
	// points at a closed port so the probe yields a transport error → fail.
	tgt := &Target{
		Discovered: Discovered{TokenEndpoint: "http://127.0.0.1:1/token"},
		Client:     &http.Client{Timeout: 2 * time.Second},
	}
	if got := runChecksFor(t, "OAuth 2.1", tgt)["oauth21.token.reachable"]; got.Status != StatusFail {
		t.Fatalf("unreachable token endpoint: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestOAuth21_RejectsUnknownGrant_Fail(t *testing.T) {
	bad := fakeas.NewAS(fakeas.Violations{AcceptUnknownGrant: true})
	defer bad.Close()
	bt := discoverInto(t, bad.URL)
	if got := runChecksFor(t, "OAuth 2.1", bt)["oauth21.token.rejects_unknown_grant"]; got.Status != StatusFail {
		t.Fatalf("unknown grant accepted: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestOAuth21_SkipsWithoutTokenEndpoint(t *testing.T) {
	tgt := &Target{}
	if got := runChecksFor(t, "OAuth 2.1", tgt)["oauth21.token.reachable"]; got.Status != StatusSkip {
		t.Fatalf("no token endpoint: want skip, got %s", got.Status)
	}
}
