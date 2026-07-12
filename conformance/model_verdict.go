package conformance

import "strings"

// RequirementOutcome is how one ModelRequirement resolved against a report.
type RequirementOutcome struct {
	Requirement ModelRequirement `json:"requirement"`
	Status      string           `json:"status"` // met | unmet | indeterminate
	Detail      string           `json:"detail"`
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
			var mandUnmet, mandIndet, optUnmet []RequirementOutcome
			for _, req := range s.Requires {
				o := requirementOutcome(rep, req)
				switch {
				case req.Criticality == "optional":
					if o.Status == "unmet" {
						optUnmet = append(optUnmet, o)
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
			v.Caveats = optUnmet
		}
		out = append(out, v)
	}
	return out
}

func requirementOutcome(rep Report, req ModelRequirement) RequirementOutcome {
	optional := req.Criticality == "optional"
	if req.ID != "" {
		status, detail := labelOutcome(rep, req.ID)
		if optional && status == "indeterminate" {
			status = "met"
		}
		return RequirementOutcome{Requirement: req, Status: status, Detail: detail}
	}
	anyMet, allUnmet := false, true
	var details []string
	for _, slug := range req.AnyOf {
		s, _ := labelOutcome(rep, slug)
		details = append(details, slug+":"+s)
		if s == "met" {
			anyMet = true
		}
		if s != "unmet" {
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
	return RequirementOutcome{Requirement: req, Status: status, Detail: strings.Join(details, ", ")}
}

// labelOutcome resolves one slug to its Check.RFC label and scans the report
// entries carrying that label.
func labelOutcome(rep Report, slug string) (string, string) {
	label, ok := resolveLabel(slug)
	if !ok {
		return "indeterminate", slug + ": unknown slug"
	}
	var sawFail, sawPass, sawSkip bool
	var ids []string
	for _, e := range rep.Entries {
		if e.Check.RFC != label {
			continue
		}
		ids = append(ids, string(e.Check.ID)+"="+string(e.Result.Status))
		switch e.Result.Status {
		case StatusFail, StatusError:
			sawFail = true
		case StatusPass:
			sawPass = true
		case StatusSkip:
			sawSkip = true
		}
	}
	detail := strings.Join(ids, ", ")
	switch {
	case sawFail:
		return "unmet", detail
	case sawPass:
		return "met", detail
	case sawSkip:
		return "indeterminate", detail
	default:
		return "indeterminate", "not run"
	}
}
