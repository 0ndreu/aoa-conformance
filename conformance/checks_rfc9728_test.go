package conformance

import (
	"net/http"
	"testing"
	"time"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
)

// runChecksFor evaluates every registered check whose RFC label matches and
// returns the results keyed by CheckID. Defined once here; reused everywhere.
func runChecksFor(t *testing.T, rfc string, tgt *Target) map[CheckID]Result {
	t.Helper()
	reg := DefaultRegistry()
	out := map[CheckID]Result{}
	for _, c := range reg.Checks() {
		if c.RFC == rfc {
			out[c.ID] = c.Evaluate(tgt)
		}
	}
	return out
}

func TestRFC9728_ChallengeResourceMetadata(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()

	good := fakeas.NewRS(as.URL, fakeas.RSViolations{})
	defer good.Close()
	bad := fakeas.NewRS(as.URL, fakeas.RSViolations{OmitChallenge: true})
	defer bad.Close()

	gt := &Target{MCPURL: good.URL + "/mcp"}
	(&Runner{Registry: DefaultRegistry()}).Run(gt)
	if got := runChecksFor(t, "RFC 9728", gt)["rfc9728.challenge.resource_metadata"]; got.Status != StatusPass {
		t.Fatalf("good RS: want pass, got %s (%s)", got.Status, got.Message)
	}

	bt := &Target{MCPURL: bad.URL + "/mcp"}
	(&Runner{Registry: DefaultRegistry()}).Run(bt)
	if got := runChecksFor(t, "RFC 9728", bt)["rfc9728.challenge.resource_metadata"]; got.Status != StatusFail {
		t.Fatalf("bad RS: want fail, got %s", got.Status)
	}

	st := &Target{Issuer: as.URL}
	if got := runChecksFor(t, "RFC 9728", st)["rfc9728.challenge.resource_metadata"]; got.Status != StatusSkip {
		t.Fatalf("issuer mode: want skip, got %s", got.Status)
	}
}

func TestRFC9728_PRMFetchable(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	good := fakeas.NewRS(as.URL, fakeas.RSViolations{})
	defer good.Close()

	gt := &Target{MCPURL: good.URL + "/mcp"}
	(&Runner{Registry: DefaultRegistry()}).Run(gt)
	if got := runChecksFor(t, "RFC 9728", gt)["rfc9728.prm.fetchable"]; got.Status != StatusPass {
		t.Fatalf("good RS: want pass, got %s (%s)", got.Status, got.Message)
	}

	st := &Target{Issuer: as.URL}
	if got := runChecksFor(t, "RFC 9728", st)["rfc9728.prm.fetchable"]; got.Status != StatusSkip {
		t.Fatalf("issuer mode: want skip, got %s", got.Status)
	}
}

func TestRFC9728_AuthServersPresent(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()

	good := fakeas.NewRS(as.URL, fakeas.RSViolations{})
	defer good.Close()
	bad := fakeas.NewRS(as.URL, fakeas.RSViolations{OmitAuthorizationServers: true})
	defer bad.Close()

	gt := &Target{MCPURL: good.URL + "/mcp"}
	(&Runner{Registry: DefaultRegistry()}).Run(gt)
	if got := runChecksFor(t, "RFC 9728", gt)["rfc9728.prm.authorization_servers_present"]; got.Status != StatusPass {
		t.Fatalf("good RS: want pass, got %s (%s)", got.Status, got.Message)
	}

	bt := &Target{MCPURL: bad.URL + "/mcp"}
	(&Runner{Registry: DefaultRegistry()}).Run(bt)
	if got := runChecksFor(t, "RFC 9728", bt)["rfc9728.prm.authorization_servers_present"]; got.Status != StatusFail {
		t.Fatalf("bad RS: want fail, got %s", got.Status)
	}

	st := &Target{Issuer: as.URL}
	if got := runChecksFor(t, "RFC 9728", st)["rfc9728.prm.authorization_servers_present"]; got.Status != StatusSkip {
		t.Fatalf("issuer mode: want skip, got %s", got.Status)
	}
}

func TestRFC9728_ASResolvable(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	good := fakeas.NewRS(as.URL, fakeas.RSViolations{})
	defer good.Close()

	gt := &Target{MCPURL: good.URL + "/mcp"}
	(&Runner{Registry: DefaultRegistry()}).Run(gt)
	if got := runChecksFor(t, "RFC 9728", gt)["rfc9728.prm.as_resolvable"]; got.Status != StatusPass {
		t.Fatalf("good RS: want pass, got %s (%s)", got.Status, got.Message)
	}

	st := &Target{Issuer: as.URL}
	if got := runChecksFor(t, "RFC 9728", st)["rfc9728.prm.as_resolvable"]; got.Status != StatusSkip {
		t.Fatalf("issuer mode: want skip, got %s", got.Status)
	}
}

func TestRFC9728_PRMFetchable_Fail(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	bad := fakeas.NewRS(as.URL, fakeas.RSViolations{MalformedPRM: true})
	defer bad.Close()

	bt := &Target{MCPURL: bad.URL + "/mcp"}
	(&Runner{Registry: DefaultRegistry()}).Run(bt)
	if got := runChecksFor(t, "RFC 9728", bt)["rfc9728.prm.fetchable"]; got.Status != StatusFail {
		t.Fatalf("malformed PRM: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC9728_ASResolvable_Fail(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	bad := fakeas.NewRS(as.URL, fakeas.RSViolations{UnresolvableAuthServer: true})
	defer bad.Close()

	// short-timeout client so the closed-port AS fetch fails fast.
	bt := &Target{MCPURL: bad.URL + "/mcp", Client: &http.Client{Timeout: 2 * time.Second}}
	(&Runner{Registry: DefaultRegistry()}).Run(bt)
	if got := runChecksFor(t, "RFC 9728", bt)["rfc9728.prm.as_resolvable"]; got.Status != StatusFail {
		t.Fatalf("unresolvable AS: want fail, got %s (%s)", got.Status, got.Message)
	}
}
