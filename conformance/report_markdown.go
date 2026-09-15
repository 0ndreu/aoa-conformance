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

// resultIcon splits the two skip kinds apart: ➖ is a verdict ("the server does
// not do this"), ⚪ is the absence of one ("we never got to test it").
func resultIcon(res Result) string {
	if res.Status == StatusSkip && res.SkipKind == SkipUnsupported {
		return "➖"
	}
	return statusIcon[res.Status]
}

var profileTitle = map[Profile]string{
	ProfileCore:     "MCP Core",
	ProfileExtended: "MCP Agent-Auth Extended",
	Profile2026_07:  "MCP 2026-07-28",
}

// profileOrder is the rendering order for the profiles the tool knows about.
// a profile absent from it still renders, appended after the known ones, so a
// newly registered profile can never silently drop out of the report.
var profileOrder = []Profile{ProfileCore, ProfileExtended, Profile2026_07}

// profilesInReport lists every profile with at least one entry, known ones
// first in profileOrder, then anything else sorted by name.
func profilesInReport(entries []Entry) []Profile {
	present := map[Profile]bool{}
	for _, e := range entries {
		present[e.Check.Profile] = true
	}
	var out []Profile
	for _, p := range profileOrder {
		if present[p] {
			out = append(out, p)
			delete(present, p)
		}
	}
	var rest []Profile
	for p := range present {
		rest = append(rest, p)
	}
	sort.Slice(rest, func(i, j int) bool { return rest[i] < rest[j] })
	return append(out, rest...)
}

// titleOf falls back to the raw profile value so an unregistered profile still
// gets a heading instead of an empty one.
func titleOf(p Profile) string {
	if t, ok := profileTitle[p]; ok {
		return t
	}
	return string(p)
}

func (MarkdownReporter) Write(w io.Writer, r Report) error {
	s := r.Summarize()
	fmt.Fprintf(w, "# MCP Auth Conformance: %s\n\n", r.Target)
	fmt.Fprintf(w, "%s %d passed · %s %d failed · ➖ %d not supported · %s %d not tested · %s %d errored\n\n",
		statusIcon[StatusPass], s.Pass, statusIcon[StatusFail], s.Fail,
		s.Unsupported, statusIcon[StatusSkip], s.Untested, statusIcon[StatusError], s.Error)
	fmt.Fprintf(w, "Legend: %s pass · %s fail · ➖ not supported (the server does not offer it) · %s not tested (no credential or flag supplied) · %s error\n\n",
		statusIcon[StatusPass], statusIcon[StatusFail], statusIcon[StatusSkip], statusIcon[StatusError])

	if len(r.Capabilities) > 0 {
		writeCapabilities(w, r.Capabilities)
	}

	for _, prof := range profilesInReport(r.Entries) {
		entries := filterByProfile(r.Entries, prof)
		if len(entries) == 0 {
			continue
		}
		fmt.Fprintf(w, "## %s\n\n", titleOf(prof))
		for _, rfc := range distinctRFCs(entries) {
			fmt.Fprintf(w, "### %s\n\n", rfc)
			fmt.Fprintln(w, "| | Check | Severity | Section | Notes |")
			fmt.Fprintln(w, "|---|---|---|---|---|")
			for _, e := range entries {
				if e.Check.RFC != rfc {
					continue
				}
				fmt.Fprintf(w, "| %s | `%s` | %s | %s | %s |\n",
					resultIcon(e.Result), e.Check.ID, e.Check.Severity,
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

var capabilityIcon = map[CapabilityState]string{
	CapSupported:    "✅",
	CapNotSupported: "➖",
	CapNotTested:    "⚪",
}

// writeCapabilities renders the support matrix. It goes first because it is
// the answer to the question a third-party developer came with: what does this
// server support? The per-RFC tables underneath are the working.
func writeCapabilities(w io.Writer, caps []Capability) {
	fmt.Fprintln(w, "## Capability summary")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| | Capability | Status | Why |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for _, c := range caps {
		fmt.Fprintf(w, "| %s | %s | %s | %s |\n", capabilityIcon[c.State], c.Title, c.State, c.Reason)
	}
	fmt.Fprintln(w)
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
			cav = append(cav, reqName(c.Requirement)+" "+caveatWhy(c))
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

// caveatWhy says why a caveat did not sink the verdict: either the shortfall
// was SHOULD/MAY level, or the requirement is optional for this surface.
func caveatWhy(c RequirementOutcome) string {
	if c.Advisory {
		return "met with a SHOULD/MAY shortfall"
	}
	return "unmet — optional"
}
