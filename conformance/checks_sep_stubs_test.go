package conformance

import (
	"strings"
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
)

func TestSEPStubsSkipWithMessage(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()
	tgt := discoverInto(t, as.URL)

	for _, tc := range []struct {
		rfc string
		id  CheckID
	}{
		{"SEP-2207", "sep2207.refresh.scope_semantics"},
		{"SEP-2350", "sep2350.stepup.scope_accumulation"},
	} {
		got := runChecksFor(t, tc.rfc, tgt)[tc.id]
		if got.Status != StatusSkip {
			t.Errorf("%s: want skip, got %s", tc.id, got.Status)
		}
		if !strings.Contains(got.Message, "not yet implemented") {
			t.Errorf("%s: want an explicit deferred message, got %q", tc.id, got.Message)
		}
	}
}
