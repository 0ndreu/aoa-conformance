package conformance

import (
	"testing"

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

func TestOAuth21_ResponseTypeCode(t *testing.T) {
	tgt := &Target{}
	tgt.Discovered = Discovered{TokenEndpoint: "https://x/token", ResponseTypesSupported: []string{"code", "token"}}
	if got := runChecksFor(t, "OAuth 2.1", tgt)["oauth21.authorize.response_type_code"]; got.Status != StatusPass {
		t.Fatalf("code advertised: want pass, got %s (%s)", got.Status, got.Message)
	}

	bad := &Target{}
	bad.Discovered = Discovered{TokenEndpoint: "https://x/token", ResponseTypesSupported: []string{"token"}}
	if got := runChecksFor(t, "OAuth 2.1", bad)["oauth21.authorize.response_type_code"]; got.Status != StatusFail {
		t.Fatalf("code missing: want fail, got %s", got.Status)
	}

	absent := &Target{}
	absent.Discovered = Discovered{TokenEndpoint: "https://x/token"}
	if got := runChecksFor(t, "OAuth 2.1", absent)["oauth21.authorize.response_type_code"]; got.Status != StatusSkip {
		t.Fatalf("response_types absent: want skip, got %s", got.Status)
	}
}
