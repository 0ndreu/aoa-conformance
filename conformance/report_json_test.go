package conformance

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func sampleReport() Report {
	return Report{
		SchemaVersion: ReportSchemaVersion,
		Target:        "https://issuer.example",
		Entries: []Entry{
			{Check: Check{ID: "a.pass", Profile: ProfileCore, RFC: "RFC 8414", Severity: SeverityMUST}, Result: Result{Status: StatusPass}},
			{Check: Check{ID: "b.fail", Profile: ProfileExtended, RFC: "RFC 8693", Severity: SeverityMUST}, Result: Result{Status: StatusFail, Message: "forged act accepted"}},
			{Check: Check{ID: "c.skip", Profile: ProfileExtended, RFC: "RFC 9449", Severity: SeverityMAY}, Result: Result{Status: StatusSkip}},
		},
	}
}

func TestReportSummaryCounts(t *testing.T) {
	s := sampleReport().Summarize()
	if s.Pass != 1 || s.Fail != 1 || s.Skip != 1 {
		t.Fatalf("want 1/1/1 got %d/%d/%d", s.Pass, s.Fail, s.Skip)
	}
	if !s.HasFailures() {
		t.Fatal("HasFailures should be true with one fail")
	}
}

func TestJSONReporterRoundTrips(t *testing.T) {
	var buf bytes.Buffer
	if err := (JSONReporter{}).Write(&buf, sampleReport()); err != nil {
		t.Fatalf("write: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("not valid json: %v", err)
	}
	if got["schema_version"] != ReportSchemaVersion {
		t.Fatalf("schema_version missing/wrong: %v", got["schema_version"])
	}
}

func TestJSONReporter_ModelCompat(t *testing.T) {
	rep := Report{
		Target: "https://mcp.example",
		ModelVerdicts: []ModelVerdict{{
			Surface: ModelSurface{Name: "claude-web"}, Verdict: "not-aligned", DataDate: "2026-07-06",
			Reasons: []RequirementOutcome{{Requirement: ModelRequirement{ID: "rfc-9728"}, Status: "unmet"}},
		}},
	}
	var b strings.Builder
	if err := (JSONReporter{}).Write(&b, rep); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, `"model_compatibility"`) || !strings.Contains(out, `"verdict": "not-aligned"`) {
		t.Fatalf("model_compatibility not emitted:\n%s", out)
	}

	// omitempty: absent when no verdicts
	var b2 strings.Builder
	_ = (JSONReporter{}).Write(&b2, Report{Target: "x"})
	if strings.Contains(b2.String(), "model_compatibility") {
		t.Fatalf("model_compatibility should be omitted when empty:\n%s", b2.String())
	}
}
