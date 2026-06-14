package conformance

import "io"

// ReportSchemaVersion is bumped on any breaking change to the JSON shape.
const ReportSchemaVersion = "1"

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
}

// Summary is a per-status count, used for the scorecard header and exit code.
type Summary struct {
	Pass, Fail, Skip, Error int
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
