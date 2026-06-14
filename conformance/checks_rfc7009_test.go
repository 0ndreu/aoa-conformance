package conformance

import (
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
	if got := runChecksFor(t, "RFC 7009", tgt)["rfc7009.revoke.honored"]; got.Status != StatusSkip {
		t.Fatalf("no endpoint: want skip, got %s", got.Status)
	}
}
