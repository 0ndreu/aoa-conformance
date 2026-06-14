package conformance

import (
	"bytes"
	"encoding/json"
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
