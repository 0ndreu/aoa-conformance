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
	good := clientTarget(t, fakeas.Violations{})
	if got := runChecksFor(t, "RFC 8707", good)["rfc8707.token.accepts_resource"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}

	bad := clientTarget(t, fakeas.Violations{RejectResource: true})
	if got := runChecksFor(t, "RFC 8707", bad)["rfc8707.token.accepts_resource"]; got.Status != StatusFail {
		t.Fatalf("resource rejected: want fail, got %s (%s)", got.Status, got.Message)
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
	good := clientTarget(t, fakeas.Violations{})
	if got := runChecksFor(t, "RFC 8707", good)["rfc8707.token.multiple_resources"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}

	bad := clientTarget(t, fakeas.Violations{ErrorOnMultipleResources: true})
	if got := runChecksFor(t, "RFC 8707", bad)["rfc8707.token.multiple_resources"]; got.Status != StatusFail {
		t.Fatalf("500 on multiple resources: want fail, got %s (%s)", got.Status, got.Message)
	}
}

// the audience question the client_credentials probes above cannot reach on a
// server that only offers authorization_code — which is every public MCP
// server we have looked at.
func TestRFC8707_AuthCodeAudienceReflectsResource(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{})
	defer rs.Close()
	resource := rs.URL + "/mcp"

	for _, tc := range []struct {
		name  string
		token string
		want  Status
		kind  SkipKind
	}{
		{"bound to the resource", as.MintToken(map[string]any{"sub": "u", "aud": resource}), StatusPass, ""},
		{"bound elsewhere", as.MintToken(map[string]any{"sub": "u", "aud": "https://other.example"}), StatusFail, ""},
		{"no audience at all", as.MintToken(map[string]any{"sub": "u"}), StatusFail, ""},
		{"opaque token", "opaque-reference-token", StatusSkip, SkipUntested},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tgt := &Target{MCPURL: resource}
			(&Runner{Registry: DefaultRegistry()}).Run(tgt)
			tgt.Creds.SubjectToken = tc.token
			tgt.Creds.AuthCodeAvailable = true

			got := runChecksFor(t, "RFC 8707", tgt)["rfc8707.authcode.aud_reflects_resource"]
			if got.Status != tc.want || got.SkipKind != tc.kind {
				t.Fatalf("want %s/%s, got %s/%s (%s)", tc.want, tc.kind, got.Status, got.SkipKind, got.Message)
			}
		})
	}
}

func TestRFC8707_AuthCodeAudienceUntestedWithoutInteractiveRound(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{})
	defer rs.Close()

	tgt := &Target{MCPURL: rs.URL + "/mcp"}
	(&Runner{Registry: DefaultRegistry()}).Run(tgt)

	got := runChecksFor(t, "RFC 8707", tgt)["rfc8707.authcode.aud_reflects_resource"]
	if got.Status != StatusSkip || got.SkipKind != SkipUntested {
		t.Fatalf("no --auth-code: want untested skip, got %s/%s (%s)", got.Status, got.SkipKind, got.Message)
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
