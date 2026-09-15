package conformance

import "io"

// ReportSchemaVersion is bumped on any breaking change to the JSON shape.
// 2 added the top-level "capabilities" support matrix.
const ReportSchemaVersion = "2"

// Entry pairs a check with its result.
type Entry struct {
	Check  Check  `json:"check"`
	Result Result `json:"result"`
}

// Report is the full output of a run.
type Report struct {
	SchemaVersion string  `json:"schema_version"`
	Target        string  `json:"target"`
	Entries       []Entry `json:"entries"`
	// Capabilities is the three-valued support matrix derived from Entries.
	// The Runner fills it; a hand-built Report can call Capabilities(entries).
	Capabilities  []Capability   `json:"capabilities,omitempty"`
	ModelVerdicts []ModelVerdict `json:"model_compatibility,omitempty"`
}

// Summary is a per-status count, used for the scorecard header and exit code.
// Skip is split into Unsupported and Untested; the two always sum to Skip.
type Summary struct {
	Pass, Fail, Skip, Error int
	Unsupported, Untested   int
}

func (s Summary) HasFailures() bool { return s.Fail > 0 }

func (r Report) Summarize() Summary {
	var s Summary
	for _, e := range r.Entries {
		switch e.Result.Status {
		case StatusPass:
			s.Pass++
		case StatusFail:
			s.Fail++
		case StatusSkip:
			s.Skip++
			if e.Result.SkipKind == SkipUnsupported {
				s.Unsupported++
			} else {
				s.Untested++
			}
		case StatusError:
			s.Error++
		}
	}
	return s
}

// Reporter renders a Report to a writer.
type Reporter interface {
	Write(io.Writer, Report) error
}
