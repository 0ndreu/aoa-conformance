package conformance

func registerSEP2207(r *Registry) {
	r.Add(Check{
		ID: "sep2207.refresh.scope_semantics", Profile: ProfileJuly28RC, RFC: "SEP-2207", Section: "refresh scope",
		Severity:    SeveritySHOULD,
		Description: "refresh-token scope semantics (deep-flow probe deferred)",
		Run: func(t *Target) Result {
			return Result{Status: StatusSkip, Message: "July-28 RC SEP recognized; deep-flow probe not yet implemented."}
		},
	})
}
