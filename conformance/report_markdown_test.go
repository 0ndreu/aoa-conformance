package conformance

import (
	"bytes"
	"strings"
	"testing"
)

func TestMarkdownReporterGroupsByProfileAndShowsStatusIcons(t *testing.T) {
	var buf bytes.Buffer
	if err := (MarkdownReporter{}).Write(&buf, sampleReport()); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"# MCP Auth Conformance: https://issuer.example",
		"## MCP Core", // profile heading
		"## MCP Agent-Auth Extended",
		"RFC 8414",            // rfc grouping
		"✅",                   // pass icon
		"❌",                   // fail icon
		"⚪",                   // skip icon
		"forged act accepted", // fail message surfaced
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("scorecard missing %q\n---\n%s", want, out)
		}
	}
}

func TestMarkdownReporter_ModelCompat(t *testing.T) {
	rep := Report{
		Target: "https://mcp.example",
		ModelVerdicts: []ModelVerdict{
			{
				Surface: ModelSurface{Name: "claude-web", Requires: []ModelRequirement{{ID: "rfc-9728"}}},
				Verdict: "not-aligned", DataDate: "2026-07-06",
				Reasons: []RequirementOutcome{{Requirement: ModelRequirement{ID: "rfc-9728"}, Status: "unmet"}},
			},
			{Surface: ModelSurface{Name: "claude-api"}, Verdict: "aligned", DataDate: "2026-07-06"},
			{Surface: ModelSurface{Name: "gemini-enterprise", Unscorable: true}, Verdict: "n/a", DataDate: "2026-07-06"},
		},
	}
	var b bytes.Buffer
	if err := (MarkdownReporter{}).Write(&b, rep); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"Agent compatibility (data as of 2026-07-06)",
		"claude-web", "not-aligned", "rfc-9728 unmet",
		"claude-api", "bearer-only",
		"gemini-enterprise", "out of OAuth scope",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}

	// absent entirely when there are no verdicts
	var b2 bytes.Buffer
	_ = (MarkdownReporter{}).Write(&b2, Report{Target: "x"})
	if strings.Contains(b2.String(), "Agent compatibility") {
		t.Errorf("section should be absent when no verdicts")
	}
}

// a report holding only 2026-07-28 entries must still render a table: the
// renderer used to iterate a hardcoded {core, extended} pair, so an entire
// profile's results landed in JSON and vanished from markdown.
func TestMarkdownReporter_Renders2026_07Only(t *testing.T) {
	rep := Report{
		Target: "https://mcp.example",
		Entries: []Entry{
			{
				Check:  Check{ID: "sep2351.discovery.suffix_path", Profile: Profile2026_07, RFC: "SEP-2351", Section: "well-known suffix", Severity: SeverityMUST},
				Result: Result{Status: StatusPass, Message: "PRM resolves at suffix path"},
			},
			{
				Check:  Check{ID: "cimd.advertise.supported", Profile: Profile2026_07, RFC: "CIMD", Section: "advertise", Severity: SeverityMAY},
				Result: Result{Status: StatusSkip, SkipKind: SkipUnsupported, Message: "AS does not advertise client_id_metadata_document_supported"},
			},
		},
	}
	var b bytes.Buffer
	if err := (MarkdownReporter{}).Write(&b, rep); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"## MCP 2026-07-28",
		"### SEP-2351",
		"### CIMD",
		"`sep2351.discovery.suffix_path`",
		"➖",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

// an entry whose profile the renderer does not know about still gets a heading
// rather than being dropped or given an empty one.
func TestMarkdownReporter_UnknownProfileStillRenders(t *testing.T) {
	rep := Report{
		Target: "https://mcp.example",
		Entries: []Entry{{
			Check:  Check{ID: "x.y", Profile: Profile("mcp-future"), RFC: "FUTURE", Section: "s", Severity: SeverityMUST},
			Result: Result{Status: StatusPass, Message: "ok"},
		}},
	}
	var b bytes.Buffer
	if err := (MarkdownReporter{}).Write(&b, rep); err != nil {
		t.Fatal(err)
	}
	if out := b.String(); !strings.Contains(out, "## mcp-future") || !strings.Contains(out, "`x.y`") {
		t.Errorf("unknown profile not rendered:\n%s", out)
	}
}

// TestMarkdownReporter_CapabilitySummaryComesFirst: the matrix is the section
// the developer reads, so it must render above the per-RFC working.
func TestMarkdownReporter_CapabilitySummaryComesFirst(t *testing.T) {
	rep := sampleReport()
	rep.Capabilities = []Capability{
		{Key: "pkce-s256", Title: "PKCE S256", State: CapSupported, Reason: "pkce.advertise.s256: S256 advertised"},
		{Key: "dpop", Title: "DPoP sender-constrained tokens (RFC 9449)", State: CapNotSupported, Reason: "not advertised"},
		{Key: "introspection", Title: "Token introspection (RFC 7662)", State: CapNotTested, Reason: "pass --subject-token"},
	}
	var buf bytes.Buffer
	if err := (MarkdownReporter{}).Write(&buf, rep); err != nil {
		t.Fatalf("write: %v", err)
	}
	out := buf.String()
	for _, want := range []string{
		"## Capability summary",
		"| ✅ | PKCE S256 | supported |",
		"| ➖ | DPoP sender-constrained tokens (RFC 9449) | not supported |",
		"| ⚪ | Token introspection (RFC 7662) | not tested |",
		"pass --subject-token",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Index(out, "## Capability summary") > strings.Index(out, "## MCP Core") {
		t.Error("the capability summary must render above the per-profile tables")
	}

	// absent entirely when the report carries no matrix
	var b2 bytes.Buffer
	_ = (MarkdownReporter{}).Write(&b2, sampleReport())
	if strings.Contains(b2.String(), "Capability summary") {
		t.Error("no capabilities means no section, not an empty table")
	}
}
