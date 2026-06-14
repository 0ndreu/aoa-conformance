package conformance

import (
	"fmt"
	"time"

	"github.com/0ndreu/aoa-conformance/probe"
)

// Runner executes a Registry against a Target, running a discovery phase first
// (unless SkipDiscovery) to populate Target.Discovered.
type Runner struct {
	Registry      *Registry
	SkipDiscovery bool
}

func (r *Runner) Run(t *Target) Report {
	target := t.Issuer
	if target == "" {
		target = t.MCPURL
	}
	rep := Report{SchemaVersion: ReportSchemaVersion, Target: target}

	if !r.SkipDiscovery {
		if err := r.discover(t); err != nil {
			// discovery failure is not fatal: checks that need it will skip or
			// fail on their own. Record it as a synthetic error entry.
			rep.Entries = append(rep.Entries, Entry{
				Check:  Check{ID: "discovery", Profile: ProfileCore, RFC: "RFC 8414", Severity: SeverityMUST, Description: "resolve endpoints"},
				Result: Result{Status: StatusError, Message: fmt.Sprintf("discovery failed: %v", err)},
			})
		}
	}

	for _, c := range r.Registry.Checks() {
		rep.Entries = append(rep.Entries, Entry{Check: c, Result: evaluateSafely(c, t)})
	}
	return rep
}

func evaluateSafely(c Check, t *Target) (res Result) {
	start := time.Now()
	defer func() {
		if rec := recover(); rec != nil {
			res = Result{Status: StatusError, Message: fmt.Sprintf("check panicked: %v", rec)}
		}
		res.Duration = time.Since(start)
	}()
	return c.Evaluate(t)
}

// discover resolves PRM (in --target mode) and AS metadata into t.Discovered.
// It also stashes the raw WWW-Authenticate challenge into t.Hints["www_authenticate"].
func (r *Runner) discover(t *Target) error {
	d, err := probe.Discover(t.Context(), t.httpClient(), probe.DiscoverInput{
		MCPURL: t.MCPURL,
		Issuer: t.Issuer,
	})
	// populate whatever discovery resolved even on a partial failure: a
	// half-resolved chain (e.g. PRM lists an AS that doesn't yield usable
	// metadata) is exactly what some checks must observe and fail on. The
	// error is still propagated so the runner records the synthetic entry.
	if d != nil {
		t.Discovered = Discovered{
			Issuer:                        d.Issuer,
			TokenEndpoint:                 d.TokenEndpoint,
			AuthorizationEndpoint:         d.AuthorizationEndpoint,
			JWKSURI:                       d.JWKSURI,
			GrantTypesSupported:           d.GrantTypesSupported,
			CodeChallengeMethodsSupported: d.CodeChallengeMethodsSupported,
			DPoPSigningAlgValuesSupported: d.DPoPSigningAlgValuesSupported,
			PRMAuthorizationServers:       d.PRMAuthorizationServers,
			RawASMetadata:                 d.RawASMetadata,
			RawPRM:                        d.RawPRM,
		}
		if t.Hints == nil {
			t.Hints = map[string]string{}
		}
		t.Hints["www_authenticate"] = d.WWWAuthenticate
	}
	return err
}
