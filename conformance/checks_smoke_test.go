package conformance

import (
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
	"github.com/0ndreu/aoa-conformance/probe"
)

func TestSmoke_TokenAccepted(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{AcceptAnyToken: true})
	defer rs.Close()

	tgt := &Target{MCPURL: rs.URL + "/mcp"}
	(&Runner{Registry: DefaultRegistry()}).Run(tgt) // discovery via PRM -> AS
	tgt.Plan = AuthPlan{ClientID: "test-client", ClientSecret: "test-secret", TokenAuthMethod: probe.AuthClientSecretPost}
	tgt.Creds.PresentEnabled = true

	if got := runChecksFor(t, "MCP loop", tgt)["smoke.present.token_accepted"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestSmoke_TokenRejected(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{}) // always 401
	defer rs.Close()

	tgt := &Target{MCPURL: rs.URL + "/mcp"}
	(&Runner{Registry: DefaultRegistry()}).Run(tgt)
	tgt.Plan = AuthPlan{ClientID: "test-client", ClientSecret: "test-secret", TokenAuthMethod: probe.AuthClientSecretPost}
	tgt.Creds.PresentEnabled = true

	if got := runChecksFor(t, "MCP loop", tgt)["smoke.present.token_accepted"]; got.Status != StatusFail {
		t.Fatalf("RS rejects token: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestSmoke_SkipsWithoutPresent(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{AcceptAnyToken: true})
	defer rs.Close()

	tgt := &Target{MCPURL: rs.URL + "/mcp"}
	(&Runner{Registry: DefaultRegistry()}).Run(tgt)
	tgt.Plan = AuthPlan{ClientID: "test-client", ClientSecret: "test-secret", TokenAuthMethod: probe.AuthClientSecretPost}
	// PresentEnabled not set

	if got := runChecksFor(t, "MCP loop", tgt)["smoke.present.token_accepted"]; got.Status != StatusSkip {
		t.Fatalf("no --present: want skip, got %s", got.Status)
	}
}

func TestSmoke_403InsufficientScopeFails(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{})
	rs.InsufficientScope = true
	defer rs.Close()

	tgt := &Target{MCPURL: rs.URL + "/mcp"}
	(&Runner{Registry: DefaultRegistry()}).Run(tgt)
	tgt.Plan = AuthPlan{ClientID: "test-client", ClientSecret: "test-secret", TokenAuthMethod: probe.AuthClientSecretPost, BearerMethod: "header"}
	tgt.Creds.PresentEnabled = true

	if got := runChecksFor(t, "MCP loop", tgt)["smoke.present.token_accepted"]; got.Status != StatusFail {
		t.Fatalf("403 must fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestSmoke_PresentsByAdvertisedBodyMethod(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{})
	rs.BearerMethods = []string{"body"}
	rs.RequireBearerMethod = "body"
	defer rs.Close()

	tgt := &Target{MCPURL: rs.URL + "/mcp"}
	(&Runner{Registry: DefaultRegistry()}).Run(tgt)
	tgt.Plan = AuthPlan{ClientID: "test-client", ClientSecret: "test-secret", TokenAuthMethod: probe.AuthClientSecretPost, BearerMethod: tgt.Discovered.PRMBearerMethodsSupported[0]}
	tgt.Creds.PresentEnabled = true

	if got := runChecksFor(t, "MCP loop", tgt)["smoke.present.token_accepted"]; got.Status != StatusPass {
		t.Fatalf("body presentation should pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestSmoke_DPoPRequiredPresentation(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{})
	rs.RequireDPoP = true
	defer rs.Close()

	tgt := &Target{MCPURL: rs.URL + "/mcp"}
	(&Runner{Registry: DefaultRegistry()}).Run(tgt)
	tgt.Plan = AuthPlan{ClientID: "test-client", ClientSecret: "test-secret", TokenAuthMethod: probe.AuthClientSecretPost, BearerMethod: "header", DPoPRequired: true}
	tgt.Creds.PresentEnabled = true

	if got := runChecksFor(t, "MCP loop", tgt)["smoke.present.token_accepted"]; got.Status != StatusPass {
		t.Fatalf("DPoP-bound presentation should pass, got %s (%s)", got.Status, got.Message)
	}
}
