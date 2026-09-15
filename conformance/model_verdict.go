package conformance

import "strings"

// RequirementOutcome is how one ModelRequirement resolved against a report.
type RequirementOutcome struct {
	Requirement ModelRequirement `json:"requirement"`
	Status      string           `json:"status"` // met | unmet | indeterminate
	// Advisory marks a met requirement that carries a SHOULD/MAY-level
	// shortfall: the agent will work, the server is not perfect.
	Advisory bool   `json:"advisory,omitempty"`
	Detail   string `json:"detail"`
}

// ModelVerdict is a per-surface compatibility verdict.
type ModelVerdict struct {
	Surface  ModelSurface         `json:"surface"`
	Verdict  string               `json:"verdict"` // aligned | not-aligned | inconclusive | n/a
	DataDate string               `json:"data_date"`
	Reasons  []RequirementOutcome `json:"reasons,omitempty"`
	Caveats  []RequirementOutcome `json:"caveats,omitempty"`
}

// EvaluateModels renders a verdict per surface. It is pure and total: a label
// absent from the report is treated as "not run", never a panic.
func EvaluateModels(rep Report, dataDate string, surfaces []ModelSurface) []ModelVerdict {
	out := make([]ModelVerdict, 0, len(surfaces))
	for _, s := range surfaces {
		v := ModelVerdict{Surface: s, DataDate: dataDate}
		switch {
		case s.Unscorable:
			v.Verdict = "n/a"
		case len(s.Requires) == 0:
			v.Verdict = "aligned"
		default:
			var mandUnmet, mandIndet, caveats []RequirementOutcome
			for _, req := range s.Requires {
				o := requirementOutcome(rep, req)
				switch {
				case o.Status == "met" && o.Advisory:
					caveats = append(caveats, o)
				case req.Criticality == "optional":
					if o.Status == "unmet" {
						caveats = append(caveats, o)
					}
				case o.Status == "unmet":
					mandUnmet = append(mandUnmet, o)
				case o.Status == "indeterminate":
					mandIndet = append(mandIndet, o)
				}
			}
			switch {
			case len(mandUnmet) > 0:
				v.Verdict = "not-aligned"
				v.Reasons = mandUnmet
			case len(mandIndet) > 0:
				v.Verdict = "inconclusive"
				v.Reasons = mandIndet
			default:
				v.Verdict = "aligned"
			}
			v.Caveats = caveats
		}
		out = append(out, v)
	}
	return out
}

func requirementOutcome(rep Report, req ModelRequirement) RequirementOutcome {
	optional := req.Criticality == "optional"
	if req.ID != "" {
		e := labelOutcome(rep, req.ID)
		if optional && e.status == "indeterminate" {
			e.status = "met"
		}
		return RequirementOutcome{Requirement: req, Status: e.status, Advisory: e.advisory, Detail: e.detail}
	}
	anyMet, allUnmet, advisory := false, true, false
	var details []string
	for _, slug := range req.AnyOf {
		e := labelOutcome(rep, slug)
		details = append(details, slug+":"+e.status)
		if e.status == "met" {
			anyMet = true
			advisory = advisory || e.advisory
		}
		if e.status != "unmet" {
			allUnmet = false
		}
	}
	status := "indeterminate"
	switch {
	case anyMet:
		status = "met"
	case allUnmet:
		status = "unmet"
	}
	if optional && status == "indeterminate" {
		status = "met"
	}
	return RequirementOutcome{Requirement: req, Status: status, Advisory: status == "met" && advisory, Detail: strings.Join(details, ", ")}
}

// labelEvidence is what a set of report entries adds up to.
type labelEvidence struct {
	status   string // met | unmet | indeterminate
	advisory bool   // met, but a SHOULD/MAY-level shortfall is worth naming
	detail   string
	// decidedBy is the entry the status hangs on: the MUST-level shortfall
	// that made it unmet, the pass that made it met, or the untested skip
	// that left it indeterminate. nil when no entry matched at all.
	decidedBy *Entry
}

// labelOutcome resolves one slug to its Check.RFC label and weighs the report
// entries carrying that label. Severity governs: only MUST-level evidence — a
// MUST check that failed, or a MUST check the target's absent capability gated
// off — can make a requirement unmet. A SHOULD or MAY shortfall next to a
// passing MUST is a caveat on an aligned verdict; a missing jwks_uri does not
// make a shipping connector incompatible.
//
// The two skip kinds part ways here too: an absent capability is an answer, a
// credential the operator did not supply is not. The latter can only ever
// yield indeterminate, so no run is called not-aligned for want of a flag.
func labelOutcome(rep Report, slug string) labelEvidence {
	label, ok := resolveLabel(slug)
	if !ok {
		return labelEvidence{status: "indeterminate", detail: slug + ": unknown slug"}
	}
	var matched []Entry
	for _, e := range rep.Entries {
		if e.Check.RFC == label {
			matched = append(matched, e)
		}
	}
	return weighEntries(matched)
}

// weighEntries is the shared severity-aware verdict over a set of entries. It
// backs both the agent-compatibility requirements (grouped by RFC label) and
// the capability matrix (grouped by check-ID prefix), so the two can never
// disagree about what the same evidence means.
func weighEntries(entries []Entry) labelEvidence {
	var mustBroken, advisoryBroken, firstPass, firstUntested *Entry
	var ids []string
	for i := range entries {
		e := &entries[i]
		ids = append(ids, string(e.Check.ID)+"="+entryOutcomeWord(*e))
		must := e.Check.Severity == SeverityMUST
		broken := e.Result.Status == StatusFail || e.Result.Status == StatusError ||
			(e.Result.Status == StatusSkip && e.Result.SkipKind == SkipUnsupported)
		switch {
		case e.Result.Status == StatusPass:
			if firstPass == nil {
				firstPass = e
			}
		case broken && must:
			if mustBroken == nil {
				mustBroken = e
			}
		case broken:
			if advisoryBroken == nil {
				advisoryBroken = e
			}
		case e.Result.Status == StatusSkip:
			if firstUntested == nil {
				firstUntested = e
			}
		}
	}
	detail := strings.Join(ids, ", ")
	switch {
	case mustBroken != nil:
		return labelEvidence{status: "unmet", detail: detail, decidedBy: mustBroken}
	case firstPass != nil:
		return labelEvidence{status: "met", advisory: advisoryBroken != nil, detail: detail, decidedBy: firstPass}
	case advisoryBroken != nil:
		// nothing passed and every check that ran found the capability
		// wanting or absent: the label itself is unmet, at SHOULD level.
		return labelEvidence{status: "unmet", detail: detail, decidedBy: advisoryBroken}
	case firstUntested != nil:
		return labelEvidence{status: "indeterminate", detail: detail, decidedBy: firstUntested}
	default:
		return labelEvidence{status: "indeterminate", detail: "not run"}
	}
}

// entryOutcomeWord renders one entry for a verdict detail line, keeping the
// skip kind visible: "skip:unsupported" and "skip:untested" are different
// answers and the reader needs to tell them apart.
func entryOutcomeWord(e Entry) string {
	if e.Result.Status == StatusSkip && e.Result.SkipKind != "" {
		return string(StatusSkip) + ":" + string(e.Result.SkipKind)
	}
	return string(e.Result.Status)
}
