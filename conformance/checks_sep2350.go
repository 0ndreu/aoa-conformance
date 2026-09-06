package conformance

import "strings"

func registerSEP2350(r *Registry) {
	r.Add(Check{
		ID: "sep2350.stepup.scope_accumulation", Profile: Profile2026_07, RFC: "SEP-2350", Section: "step-up scope",
		Severity:    SeveritySHOULD,
		Description: "a step-up authorization accumulates the previously granted scope",
		Precondition: needs(func(t *Target) SkipReason {
			if t.Hints["stepup_second_scope"] == "" || t.Hints["stepup_scope_a"] == "" || t.Hints["stepup_scope_b"] == "" {
				return Untested("needs --stepup (two interactive authorization rounds over two distinct scopes)")
			}
			return satisfied
		}),
		Run: func(t *Target) Result {
			has := map[string]bool{}
			for _, s := range strings.Fields(t.Hints["stepup_second_scope"]) {
				has[s] = true
			}
			a, b := t.Hints["stepup_scope_a"], t.Hints["stepup_scope_b"]
			if has[a] && has[b] {
				return Result{Status: StatusPass, Message: "step-up token accumulated scope: " + t.Hints["stepup_second_scope"]}
			}
			return Result{Status: StatusFail,
				Message: "step-up token dropped a previously granted scope (want " + a + " and " + b + ", got " + t.Hints["stepup_second_scope"] + ")"}
		},
	})
}
