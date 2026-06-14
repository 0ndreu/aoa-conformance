package conformance

import (
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
)

func introspectTarget(t *testing.T, v fakeas.Violations) *Target {
	t.Helper()
	as := fakeas.NewAS(v)
	t.Cleanup(as.Close)
	tgt := discoverInto(t, as.URL)
	tgt.Creds.ClientID = "test-client"
	tgt.Creds.ClientSecret = "test-secret"
	return tgt
}

func TestRFC7662_IntrospectActive(t *testing.T) {
	good := introspectTarget(t, fakeas.Violations{})
	if got := runChecksFor(t, "RFC 7662", good)["rfc7662.introspect.active"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}

	bad := introspectTarget(t, fakeas.Violations{IntrospectInactive: true})
	if got := runChecksFor(t, "RFC 7662", bad)["rfc7662.introspect.active"]; got.Status != StatusFail {
		t.Fatalf("buggy AS: want fail, got %s", got.Status)
	}
}

func TestRFC7662_SkipsWhenNoEndpoint(t *testing.T) {
	tgt := introspectTarget(t, fakeas.Violations{NoIntrospection: true})
	if got := runChecksFor(t, "RFC 7662", tgt)["rfc7662.introspect.active"]; got.Status != StatusSkip {
		t.Fatalf("no endpoint: want skip, got %s", got.Status)
	}
}
