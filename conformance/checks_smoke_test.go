package conformance

import (
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
)

func TestSmoke_TokenAccepted(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{AcceptAnyToken: true})
	defer rs.Close()

	tgt := &Target{MCPURL: rs.URL + "/mcp"}
	(&Runner{Registry: DefaultRegistry()}).Run(tgt) // discovery via PRM -> AS
	tgt.Creds.ClientID = "test-client"
	tgt.Creds.ClientSecret = "test-secret"
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
	tgt.Creds.ClientID = "test-client"
	tgt.Creds.ClientSecret = "test-secret"
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
	tgt.Creds.ClientID = "test-client"
	tgt.Creds.ClientSecret = "test-secret"
	// PresentEnabled not set

	if got := runChecksFor(t, "MCP loop", tgt)["smoke.present.token_accepted"]; got.Status != StatusSkip {
		t.Fatalf("no --present: want skip, got %s", got.Status)
	}
}
