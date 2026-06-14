package conformance

import (
	"encoding/json"
	"io"
)

// JSONReporter writes the machine-readable, versioned JSON report.
type JSONReporter struct{}

func (JSONReporter) Write(w io.Writer, r Report) error {
	if r.SchemaVersion == "" {
		r.SchemaVersion = ReportSchemaVersion
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
