package conformance

import (
	"strings"
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
)

// runMCPServerChecks discovers against the RS exactly as a real run does, then
// evaluates the resource-server checks. No credentials are involved anywhere:
// that is the point of this file.
func runMCPServerChecks(t *testing.T, rs *fakeas.RS) map[CheckID]Result {
	t.Helper()
	tgt := &Target{MCPURL: rs.URL + "/mcp"}
	if err := Discover(tgt); err != nil {
		t.Fatalf("discovery: %v", err)
	}
	return runChecksFor(t, "MCP Authorization", tgt)
}

// conformantRS is an RS that advertises scopes and rejects every token it did
// not issue — i.e. every token this tool can present without a credential.
func conformantRS(t *testing.T) *fakeas.RS {
	t.Helper()
	as := fakeas.NewAS(fakeas.Violations{})
	t.Cleanup(as.Close)
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{})
	rs.Scopes = []string{"read", "write"}
	rs.BearerMethods = nil
	t.Cleanup(rs.Close)
	return rs
}

func want(t *testing.T, got map[CheckID]Result, id CheckID, status Status) Result {
	t.Helper()
	res, ok := got[id]
	if !ok {
		t.Fatalf("%s not evaluated", id)
	}
	if res.Status != status {
		t.Fatalf("%s: want %s, got %s (%s)", id, status, res.Status, res.Message)
	}
	return res
}

func TestMCPServer_ConformantResourcePassesEveryZeroCredentialCheck(t *testing.T) {
	got := runMCPServerChecks(t, conformantRS(t))
	for _, id := range []CheckID{
		"mcp.challenge.scope_present",
		"mcp.challenge.no_offline_access",
		"mcp.prm.resource_canonical",
		"mcp.token.query_not_advertised",
		"mcp.token.header_method_advertised",
		"mcp.token.invalid_rejected",
		"mcp.token.foreign_audience_rejected",
	} {
		want(t, got, id, StatusPass)
	}
}

func TestMCPServer_ChallengeWithoutScopeFails(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{}) // no Scopes → no scope in the challenge
	defer rs.Close()

	res := want(t, runMCPServerChecks(t, rs), "mcp.challenge.scope_present", StatusFail)
	if !strings.Contains(res.Message, "scope") {
		t.Errorf("message should name the missing parameter: %q", res.Message)
	}
}

func TestMCPServer_OfflineAccessAdvertisedFails(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{})
	rs.Scopes = []string{"read", "offline_access"}
	defer rs.Close()

	res := want(t, runMCPServerChecks(t, rs), "mcp.challenge.no_offline_access", StatusFail)
	if !strings.Contains(res.Message, "scopes_supported") || !strings.Contains(res.Message, "challenge") {
		t.Errorf("message should name both places it was advertised: %q", res.Message)
	}
}

func TestMCPServer_NonCanonicalResourceFails(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{NonCanonicalResource: true})
	defer rs.Close()

	res := want(t, runMCPServerChecks(t, rs), "mcp.prm.resource_canonical", StatusFail)
	if !strings.Contains(res.Message, "fragment") {
		t.Errorf("message should name the fragment: %q", res.Message)
	}
}

func TestMCPServer_QueryBearerMethodFails(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{})
	rs.BearerMethods = []string{"header", "query"}
	defer rs.Close()

	want(t, runMCPServerChecks(t, rs), "mcp.token.query_not_advertised", StatusFail)
}

func TestMCPServer_BearerMethodsWithoutHeaderFails(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{})
	rs.BearerMethods = []string{"body"}
	defer rs.Close()

	res := want(t, runMCPServerChecks(t, rs), "mcp.token.header_method_advertised", StatusFail)
	if !strings.Contains(res.Message, "body") || !strings.Contains(res.Message, "Authorization header") {
		t.Errorf("message should quote the advertised list and name the header: %q", res.Message)
	}
}

func TestMCPServer_AdvertisedHeaderPasses(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{})
	rs.BearerMethods = []string{"header", "body"}
	defer rs.Close()

	want(t, runMCPServerChecks(t, rs), "mcp.token.header_method_advertised", StatusPass)
}

func TestMCPServer_ResourceAcceptingAnyTokenFails(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{AcceptAnyToken: true})
	defer rs.Close()

	got := runMCPServerChecks(t, rs)
	want(t, got, "mcp.token.invalid_rejected", StatusFail)
	res := want(t, got, "mcp.token.foreign_audience_rejected", StatusFail)
	if !strings.Contains(res.Message, foreignIssuer) {
		t.Errorf("message should name the foreign issuer it accepted: %q", res.Message)
	}
}

// a 403 means the resource authenticated a token it should never have
// recognised, and only reported it as short on scope.
func TestMCPServer_ForeignTokenAnsweredWith403Fails(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	rs := fakeas.NewRS(as.URL, fakeas.RSViolations{AcceptAnyToken: true})
	rs.BearerMethods = []string{"header"}
	rs.InsufficientScope = true
	defer rs.Close()

	res := want(t, runMCPServerChecks(t, rs), "mcp.token.foreign_audience_rejected", StatusFail)
	if !strings.Contains(res.Message, "403") {
		t.Errorf("message should report the 403: %q", res.Message)
	}
}

func TestCanonicalResourceProblem(t *testing.T) {
	const target = "https://mcp.example.com/mcp"
	for _, tc := range []struct {
		name     string
		resource string
		mustSay  string
	}{
		{"exact", "https://mcp.example.com/mcp", ""},
		{"trailing slash", "https://mcp.example.com/mcp/", ""},
		{"absent", "", "omits the required resource field"},
		{"origin only", "https://mcp.example.com", "canonical URI"},
		{"other host", "https://other.example.com/mcp", "canonical URI"},
		{"uppercase host", "https://MCP.example.com/mcp", "lowercase"},
		{"fragment", "https://mcp.example.com/mcp#a", "fragment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := canonicalResourceProblem(tc.resource, target)
			if tc.mustSay == "" && got != "" {
				t.Fatalf("want no problem, got %q", got)
			}
			if tc.mustSay != "" && !strings.Contains(got, tc.mustSay) {
				t.Fatalf("want a problem naming %q, got %q", tc.mustSay, got)
			}
		})
	}
}

// in issuer mode there is no resource server to interrogate, and the skips must
// say so rather than implying the server failed.
func TestMCPServer_SkipsWithoutTarget(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	tgt := &Target{Issuer: as.URL}

	for id, res := range runChecksFor(t, "MCP Authorization", tgt) {
		if res.Status != StatusSkip || res.SkipKind != SkipUntested {
			t.Errorf("%s: want skip/untested, got %s/%s (%s)", id, res.Status, res.SkipKind, res.Message)
		}
		if !strings.Contains(res.Message, "--target") {
			t.Errorf("%s: skip should name --target, got %q", id, res.Message)
		}
	}
}
