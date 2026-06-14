package conformance

import (
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
	"github.com/0ndreu/aoa-conformance/probe"
)

func clientTarget(t *testing.T, v fakeas.Violations) *Target {
	t.Helper()
	as := fakeas.NewAS(v)
	t.Cleanup(as.Close)
	tgt := discoverInto(t, as.URL)
	tgt.Plan = AuthPlan{ClientID: "test-client", ClientSecret: "test-secret", TokenAuthMethod: probe.AuthClientSecretPost}
	return tgt
}

func TestRFC8707_AcceptsResource(t *testing.T) {
	tgt := clientTarget(t, fakeas.Violations{})
	if got := runChecksFor(t, "RFC 8707", tgt)["rfc8707.token.accepts_resource"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8707_ReflectsAudience(t *testing.T) {
	good := clientTarget(t, fakeas.Violations{})
	if got := runChecksFor(t, "RFC 8707", good)["rfc8707.token.reflects_audience"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}

	bad := clientTarget(t, fakeas.Violations{IgnoreResourceParam: true})
	if got := runChecksFor(t, "RFC 8707", bad)["rfc8707.token.reflects_audience"]; got.Status != StatusFail {
		t.Fatalf("ignore resource: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8707_MultipleResources(t *testing.T) {
	tgt := clientTarget(t, fakeas.Violations{})
	if got := runChecksFor(t, "RFC 8707", tgt)["rfc8707.token.multiple_resources"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8707_AcceptsResource_Fail(t *testing.T) {
	bad := clientTarget(t, fakeas.Violations{RejectResource: true})
	if got := runChecksFor(t, "RFC 8707", bad)["rfc8707.token.accepts_resource"]; got.Status != StatusFail {
		t.Fatalf("resource rejected: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8707_MultipleResources_Fail(t *testing.T) {
	bad := clientTarget(t, fakeas.Violations{ErrorOnMultipleResources: true})
	if got := runChecksFor(t, "RFC 8707", bad)["rfc8707.token.multiple_resources"]; got.Status != StatusFail {
		t.Fatalf("500 on multiple resources: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8707_SkipsWithoutClient(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	tgt := discoverInto(t, as.URL) // no creds
	if got := runChecksFor(t, "RFC 8707", tgt)["rfc8707.token.reflects_audience"]; got.Status != StatusSkip {
		t.Fatalf("no client creds: want skip, got %s", got.Status)
	}
}
