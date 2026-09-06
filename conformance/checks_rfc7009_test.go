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

// TestRFC7009_AdvertisementIsReportedIndependentlyOfIntrospection covers the
// case real servers actually present: Linear advertises a revocation_endpoint
// but no introspection_endpoint. The behavioural probe cannot run there, and
// without a separate advertisement check the capability matrix would tell the
// operator their server does not support revocation at all.
func TestRFC7009_AdvertisementIsReportedIndependentlyOfIntrospection(t *testing.T) {
	tgt := introspectTarget(t, fakeas.Violations{NoIntrospection: true})
	got := runChecksFor(t, "RFC 7009", tgt)

	if adv := got["rfc7009.advertise.revocation_endpoint"]; adv.Status != StatusPass {
		t.Fatalf("revocation advertised but reported %s (%s)", adv.Status, adv.Message)
	}
	if h := got["rfc7009.revoke.honored"]; h.Status != StatusSkip {
		t.Fatalf("without introspection the behavioural probe must skip, got %s", h.Status)
	}

	// An AS with no revocation_endpoint is the genuine "not supported" case.
	none := introspectTarget(t, fakeas.Violations{NoRevocation: true})
	adv := runChecksFor(t, "RFC 7009", none)["rfc7009.advertise.revocation_endpoint"]
	if adv.Status != StatusSkip || adv.SkipKind != SkipUnsupported {
		t.Fatalf("no revocation_endpoint: want unsupported skip, got %s/%s", adv.Status, adv.SkipKind)
	}
}
