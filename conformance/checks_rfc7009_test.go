package conformance

import (
	"strings"
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
)

func TestRFC7009_RevokeHonored(t *testing.T) {
	good := introspectTarget(t, fakeas.Violations{})
	if got := runChecksFor(t, "RFC 7009", good)["rfc7009.revoke.honored"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}

	bad := introspectTarget(t, fakeas.Violations{IgnoreRevoke: true})
	if got := runChecksFor(t, "RFC 7009", bad)["rfc7009.revoke.honored"]; got.Status != StatusFail {
		t.Fatalf("revoke ignored: want fail, got %s", got.Status)
	}
}

func TestRFC7009_SkipsWhenNoEndpoint(t *testing.T) {
	tgt := introspectTarget(t, fakeas.Violations{NoRevocation: true})
	got := runChecksFor(t, "RFC 7009", tgt)
	for _, id := range []CheckID{"rfc7009.advertise.revocation_endpoint", "rfc7009.revoke.honored"} {
		res := got[id]
		if res.Status != StatusSkip || res.SkipKind != SkipUnsupported {
			t.Fatalf("%s: no endpoint at all is the unsupported case, got %s/%s", id, res.Status, res.SkipKind)
		}
	}
}

// the shape Semrush deploys: metadata names a revocation_endpoint and the URL
// 404s. Trusting the advertisement would put "Token revocation: supported" in
// the capability matrix for an endpoint that does not exist.
func TestRFC7009_AdvertisedButDeadEndpointIsUnsupported(t *testing.T) {
	tgt := introspectTarget(t, fakeas.Violations{DeadRevocation: true})
	got := runChecksFor(t, "RFC 7009", tgt)["rfc7009.advertise.revocation_endpoint"]
	if got.Status != StatusSkip || got.SkipKind != SkipUnsupported {
		t.Fatalf("dead endpoint: want unsupported skip, got %s/%s (%s)", got.Status, got.SkipKind, got.Message)
	}
	if !strings.Contains(got.Message, "404") || !strings.Contains(got.Message, "/revoke") {
		t.Errorf("message should name the URL and the status: %q", got.Message)
	}
}

// Linear's shape: revocation is live, introspection is absent. The behavioural
// probe has no way to look at the token afterwards — that is a missing
// verification path, not an answer about revocation.
func TestRFC7009_LiveRevocationWithoutIntrospectionIsUntested(t *testing.T) {
	tgt := introspectTarget(t, fakeas.Violations{NoIntrospection: true})
	got := runChecksFor(t, "RFC 7009", tgt)

	if adv := got["rfc7009.advertise.revocation_endpoint"]; adv.Status != StatusPass {
		t.Fatalf("live revocation endpoint: want pass, got %s (%s)", adv.Status, adv.Message)
	}
	h := got["rfc7009.revoke.honored"]
	if h.Status != StatusSkip || h.SkipKind != SkipUntested {
		t.Fatalf("no introspection: want untested skip, got %s/%s (%s)", h.Status, h.SkipKind, h.Message)
	}
}
