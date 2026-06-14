package conformance

import (
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
	"github.com/0ndreu/aoa-conformance/probe"
)

func TestRFC8707_UsesResolvedBasicAuth(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	t.Cleanup(as.Close)

	tgt := &Target{Issuer: as.URL}
	(&Runner{Registry: &Registry{}}).Run(tgt) // discovery
	tgt.Plan = AuthPlan{ClientID: "cid", ClientSecret: "sec", TokenAuthMethod: probe.AuthClientSecretBasic}

	got := runChecksFor(t, "RFC 8707", tgt)["rfc8707.token.accepts_resource"]
	if got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}
	if as.LastClientAuthMethod() != "client_secret_basic" {
		t.Fatalf("token call did not use basic auth, used %q", as.LastClientAuthMethod())
	}
}
