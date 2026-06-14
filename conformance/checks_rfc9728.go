package conformance

import (
	"encoding/json"
	"strings"
)

func registerRFC9728(r *Registry) {
	mk := func(id, section, desc string, pre func(*Target) bool, run func(*Target) Result) Check {
		return Check{ID: CheckID(id), Profile: ProfileCore, RFC: "RFC 9728", Section: section,
			Severity: SeverityMUST, Description: desc, Precondition: pre, Run: run}
	}
	hasMCP := func(t *Target) bool { return t.MCPURL != "" }

	r.Add(
		mk("rfc9728.challenge.resource_metadata", "§5.1",
			"401 WWW-Authenticate carries a resource_metadata parameter", hasMCP,
			func(t *Target) Result {
				challenge := t.Hints["www_authenticate"]
				if challenge == "" {
					return Result{Status: StatusFail, Message: "no WWW-Authenticate challenge recorded"}
				}
				if !strings.Contains(challenge, "resource_metadata") {
					return Result{Status: StatusFail, Message: "challenge has no resource_metadata param: " + challenge}
				}
				return Result{Status: StatusPass, Message: "resource_metadata advertised in challenge"}
			}),

		mk("rfc9728.prm.fetchable", "§3",
			"Protected Resource Metadata is reachable and valid JSON", hasMCP,
			func(t *Target) Result {
				if len(t.Discovered.RawPRM) == 0 {
					return Result{Status: StatusFail, Message: "PRM document not fetched"}
				}
				var m map[string]any
				if err := json.Unmarshal(t.Discovered.RawPRM, &m); err != nil {
					return Result{Status: StatusFail, Message: "PRM is not valid JSON: " + err.Error(), Evidence: t.Discovered.RawPRM}
				}
				return Result{Status: StatusPass, Message: "PRM fetched", Evidence: t.Discovered.RawPRM}
			}),

		mk("rfc9728.prm.authorization_servers_present", "§3.1",
			"PRM lists at least one authorization_servers entry", hasMCP,
			func(t *Target) Result {
				if len(t.Discovered.PRMAuthorizationServers) == 0 {
					return Result{Status: StatusFail, Message: "PRM has no authorization_servers", Evidence: t.Discovered.RawPRM}
				}
				return Result{Status: StatusPass, Message: strings.Join(t.Discovered.PRMAuthorizationServers, ", "), Evidence: t.Discovered.RawPRM}
			}),

		mk("rfc9728.prm.as_resolvable", "§3.1",
			"the advertised authorization server resolves to usable metadata",
			func(t *Target) bool { return t.MCPURL != "" && len(t.Discovered.PRMAuthorizationServers) > 0 },
			func(t *Target) Result {
				if t.Discovered.TokenEndpoint == "" {
					return Result{Status: StatusFail, Message: "advertised AS has no resolvable token_endpoint", Evidence: t.Discovered.RawASMetadata}
				}
				return Result{Status: StatusPass, Message: "AS resolved: " + t.Discovered.TokenEndpoint, Evidence: t.Discovered.RawASMetadata}
			}),
	)
}
