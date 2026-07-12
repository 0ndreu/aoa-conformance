package conformance

import (
	"fmt"
	"io"
	"sort"
	"strings"
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
	fmt.Fprintf(w, "# MCP Auth Conformance: %s\n\n", r.Target)
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
	if len(r.ModelVerdicts) > 0 {
		writeModelCompat(w, r.ModelVerdicts)
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

// writeModelCompat renders the terse agent-compatibility section, one line per
// surface. The terminal output shows only the label and status; rationale and
// source stay in the JSON and YAML corpus.
func writeModelCompat(w io.Writer, verdicts []ModelVerdict) {
	fmt.Fprintf(w, "## Agent compatibility (data as of %s)\n\n", verdicts[0].DataDate)
	for _, v := range verdicts {
		fmt.Fprintf(w, "  %-18s %-14s %s\n", v.Surface.Name, v.Verdict, verdictSummary(v))
	}
	fmt.Fprintln(w)
}

func verdictSummary(v ModelVerdict) string {
	switch v.Verdict {
	case "n/a":
		return "out of OAuth scope"
	case "aligned":
		if len(v.Surface.Requires) == 0 {
			return "bearer-only"
		}
		var cav []string
		for _, c := range v.Caveats {
			cav = append(cav, reqName(c.Requirement)+" unmet — optional")
		}
		if len(cav) > 0 {
			return "(" + strings.Join(cav, "; ") + ")"
		}
		return ""
	default: // not-aligned | inconclusive
		var parts []string
		for _, r := range v.Reasons {
			parts = append(parts, reqName(r.Requirement)+" "+r.Status)
		}
		return strings.Join(parts, "; ")
	}
}
