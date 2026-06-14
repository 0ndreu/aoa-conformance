package conformance

import (
	"fmt"
	"io"
	"sort"
)

// MarkdownReporter writes the human-readable scorecard (suitable for a README
// or a published provider comparison).
type MarkdownReporter struct{}

var statusIcon = map[Status]string{
	StatusPass:  "✅",
	StatusFail:  "❌",
	StatusSkip:  "⚪",
	StatusError: "🟠",
}

var profileTitle = map[Profile]string{
	ProfileCore:     "MCP Core",
	ProfileExtended: "MCP Agent-Auth Extended",
}

func (MarkdownReporter) Write(w io.Writer, r Report) error {
	s := r.Summarize()
	fmt.Fprintf(w, "# MCP Auth Conformance — %s\n\n", r.Target)
	fmt.Fprintf(w, "%s %d passed · %s %d failed · %s %d skipped · %s %d errored\n\n",
		statusIcon[StatusPass], s.Pass, statusIcon[StatusFail], s.Fail,
		statusIcon[StatusSkip], s.Skip, statusIcon[StatusError], s.Error)

	for _, prof := range []Profile{ProfileCore, ProfileExtended} {
		entries := filterByProfile(r.Entries, prof)
		if len(entries) == 0 {
			continue
		}
		fmt.Fprintf(w, "## %s\n\n", profileTitle[prof])
		for _, rfc := range distinctRFCs(entries) {
			fmt.Fprintf(w, "### %s\n\n", rfc)
			fmt.Fprintln(w, "| | Check | Severity | Section | Notes |")
			fmt.Fprintln(w, "|---|---|---|---|---|")
			for _, e := range entries {
				if e.Check.RFC != rfc {
					continue
				}
				fmt.Fprintf(w, "| %s | `%s` | %s | %s | %s |\n",
					statusIcon[e.Result.Status], e.Check.ID, e.Check.Severity,
					e.Check.Section, e.Result.Message)
			}
			fmt.Fprintln(w)
		}
	}
	return nil
}

func filterByProfile(entries []Entry, p Profile) []Entry {
	var out []Entry
	for _, e := range entries {
		if e.Check.Profile == p {
			out = append(out, e)
		}
	}
	return out
}

func distinctRFCs(entries []Entry) []string {
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		if !seen[e.Check.RFC] {
			seen[e.Check.RFC] = true
			out = append(out, e.Check.RFC)
		}
	}
	sort.Strings(out)
	return out
}
