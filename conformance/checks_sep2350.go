package conformance

func registerSEP2350(r *Registry) {
	r.Add(Check{
		ID: "sep2350.stepup.scope_accumulation", Profile: ProfileJuly28RC, RFC: "SEP-2350", Section: "step-up scope",
		Severity:    SeveritySHOULD,
		Description: "scope accumulation on step-up auth (deep-flow probe deferred)",
		Run: func(t *Target) Result {
			return Result{Status: StatusSkip, Message: "July-28 RC SEP recognized; deep-flow probe not yet implemented."}
		},
	})
}
