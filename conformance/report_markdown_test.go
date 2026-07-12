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
