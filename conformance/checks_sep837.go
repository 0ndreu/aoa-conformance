package conformance

func registerSEP837(r *Registry) {
	r.Add(Check{
		ID: "sep837.register.application_type", Profile: ProfileJuly28RC, RFC: "SEP-837", Section: "DCR",
		Severity:    SeveritySHOULD,
		Description: "DCR accepts and echoes the OIDC application_type the tool declares (native)",
		Precondition: func(t *Target) bool {
			return t.Discovered.RegistrationEndpoint != "" && t.Plan.Registered
		},
		Run: func(t *Target) Result {
			switch t.Plan.RegisteredApplicationType {
			case "native":
				return Result{Status: StatusPass, Message: "application_type native accepted and echoed", Evidence: t.Plan.RegistrationEvidence}
			case "":
				return Result{Status: StatusPass, Message: "registration accepted application_type without rejecting it (not echoed)", Evidence: t.Plan.RegistrationEvidence}
			default:
				return Result{Status: StatusFail, Message: "declared application_type native but server registered as " + t.Plan.RegisteredApplicationType, Evidence: t.Plan.RegistrationEvidence}
			}
		},
	})
}
