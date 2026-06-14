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
		"# MCP Auth Conformance — https://issuer.example",
		"## MCP Core",          // profile heading
		"## MCP Agent-Auth Extended",
		"RFC 8414",             // rfc grouping
		"✅",                    // pass icon
		"❌",                    // fail icon
		"⚪",                    // skip icon
		"forged act accepted",  // fail message surfaced
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("scorecard missing %q\n---\n%s", want, out)
		}
	}
}
