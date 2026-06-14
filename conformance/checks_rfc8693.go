package conformance

import (
	"fmt"
	"net/url"

	"github.com/0ndreu/aoa-conformance/probe"
)

func registerRFC8693(r *Registry) {
	// extended capability + Tier-2 subject token are required for most checks.
	needsExchange := func(t *Target) bool {
		return t.Discovered.advertisesTokenExchange() && t.Creds.hasSubject()
	}
	needsDelegation := func(t *Target) bool {
		return needsExchange(t) && t.Hints["actor_token"] != ""
	}
	mk := func(id, section, desc string, sev Severity, pre func(*Target) bool, run func(*Target) Result) Check {
		return Check{ID: CheckID(id), Profile: ProfileExtended, RFC: "RFC 8693", Section: section,
			Severity: sev, Description: desc, Precondition: pre, Run: run}
	}

	// helper: do an exchange and return the parsed response + status
	doExchange := func(t *Target, in probe.ExchangeInput, extra url.Values) (*probe.Response, error) {
		form := probe.ExchangeForm(in)
		for k, vs := range extra {
			for _, v := range vs {
				form.Add(k, v)
			}
		}
		form.Set("client_id", t.Creds.ClientID)
		if t.Creds.ClientSecret != "" {
			form.Set("client_secret", t.Creds.ClientSecret)
		}
		return probe.PostForm(t.Context(), t.httpClient(), t.Discovered.TokenEndpoint, form, nil)
	}

	r.Add(
		mk("rfc8693.grant.advertised", "§2.1", "token-exchange grant advertised", SeverityMAY, needsExchange,
			func(t *Target) Result {
				return Result{Status: StatusPass, Message: "token-exchange advertised"}
			}),

		mk("rfc8693.impersonation.issues_token", "§2.1", "impersonation (no actor) issues a token", SeverityMUST, needsExchange,
			func(t *Target) Result {
				resp, err := doExchange(t, probe.ExchangeInput{SubjectToken: t.Creds.SubjectToken, SubjectTokenType: "access_token"}, nil)
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
				}
				if resp.StatusCode == 200 && resp.JSON()["access_token"] != nil {
					return Result{Status: StatusPass, Message: "impersonation token issued", Evidence: resp.Evidence}
				}
				return Result{Status: StatusFail, Message: "no token issued for impersonation", Evidence: resp.Evidence}
			}),

		mk("rfc8693.delegation.issues_token", "§2.1", "delegation (with actor_token) issues a token", SeverityMUST, needsDelegation,
			func(t *Target) Result {
				resp, err := doExchange(t, probe.ExchangeInput{
					SubjectToken: t.Creds.SubjectToken, SubjectTokenType: "access_token",
					ActorToken: t.Hints["actor_token"], ActorTokenType: "access_token"}, nil)
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
				}
				if resp.StatusCode == 200 {
					return Result{Status: StatusPass, Message: "delegation token issued", Evidence: resp.Evidence}
				}
				return Result{Status: StatusFail, Message: "delegation rejected", Evidence: resp.Evidence}
			}),

		mk("rfc8693.delegation.act_present", "§4.1", "issued delegation token carries an act claim", SeverityMUST, needsDelegation,
			func(t *Target) Result {
				claims, ev, err := exchangeAndDecode(t, doExchange, true)
				if err != nil {
					return Result{Status: StatusError, Message: err.Error(), Evidence: ev}
				}
				if _, ok := claims["act"]; ok {
					return Result{Status: StatusPass, Message: "act present", Evidence: ev}
				}
				return Result{Status: StatusFail, Message: "delegation token has no act", Evidence: ev}
			}),

		mk("rfc8693.delegation.act_nesting", "§4.1", "existing subject act is nested under the new actor", SeverityMUST, needsDelegation,
			func(t *Target) Result {
				claims, ev, err := exchangeAndDecode(t, doExchange, true)
				if err != nil {
					return Result{Status: StatusError, Message: err.Error(), Evidence: ev}
				}
				act, _ := claims["act"].(map[string]any)
				if act == nil {
					return Result{Status: StatusFail, Message: "no act to inspect", Evidence: ev}
				}
				if _, nested := act["act"]; !nested {
					return Result{Status: StatusFail, Message: "subject's prior act was not nested (forged chain)", Evidence: ev}
				}
				return Result{Status: StatusPass, Message: "act chain correctly nested", Evidence: ev}
			}),

		mk("rfc8693.delegation.may_act_enforced", "§4.4", "may_act is enforced; unauthorized actor is rejected", SeverityMUST, needsDelegation,
			func(t *Target) Result {
				resp, err := doExchange(t, probe.ExchangeInput{
					SubjectToken: t.Creds.SubjectToken, SubjectTokenType: "access_token",
					ActorToken: t.Hints["actor_token"], ActorTokenType: "access_token"}, nil)
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
				}
				// the test supplies a subject whose may_act does NOT include the actor.
				// A correct AS rejects with invalid_grant; acceptance is a security failure.
				if resp.StatusCode == 200 {
					return Result{Status: StatusFail, Message: "unauthorized actor accepted; may_act not enforced", Evidence: resp.Evidence}
				}
				if resp.JSON()["error"] == "invalid_grant" {
					return Result{Status: StatusPass, Message: "unauthorized actor rejected with invalid_grant", Evidence: resp.Evidence}
				}
				return Result{Status: StatusFail, Message: fmt.Sprintf(
					"actor rejected but not via invalid_grant (HTTP %d, error=%v); cannot confirm may_act enforcement",
					resp.StatusCode, resp.JSON()["error"]), Evidence: resp.Evidence}
			}),

		mk("rfc8693.downscope.scope_honored", "§2.1", "requested narrower scope is honored, not widened", SeveritySHOULD, needsExchange,
			func(t *Target) Result {
				resp, err := doExchange(t, probe.ExchangeInput{
					SubjectToken: t.Creds.SubjectToken, SubjectTokenType: "access_token",
					Scope: []string{"read"}}, nil)
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
				}
				if resp.StatusCode != 200 {
					return Result{Status: StatusFail, Message: "downscoped exchange rejected", Evidence: resp.Evidence}
				}
				if s, ok := resp.JSON()["scope"].(string); ok && s != "" && s != "read" {
					return Result{Status: StatusFail, Message: "scope widened beyond request: " + s, Evidence: resp.Evidence}
				}
				return Result{Status: StatusPass, Message: "scope honored", Evidence: resp.Evidence}
			}),

		mk("rfc8693.error.invalid_grant_on_bad_subject", "§2.2.2", "bad subject_token yields invalid_grant", SeverityMUST, needsExchange,
			func(t *Target) Result {
				resp, err := doExchange(t, probe.ExchangeInput{SubjectToken: "not-a-token", SubjectTokenType: "access_token"}, nil)
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
				}
				if resp.StatusCode == 200 {
					return Result{Status: StatusFail, Message: "garbage subject_token accepted", Evidence: resp.Evidence}
				}
				return Result{Status: StatusPass, Message: "bad subject_token rejected", Evidence: resp.Evidence}
			}),

		mk("rfc8693.error.invalid_target_on_unknown_audience", "§2.2.2", "unknown audience yields invalid_target", SeverityMAY, needsExchange,
			func(t *Target) Result {
				resp, err := doExchange(t, probe.ExchangeInput{
					SubjectToken: t.Creds.SubjectToken, SubjectTokenType: "access_token",
					Audience: []string{"https://definitely-not-registered.example"}}, nil)
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
				}
				if resp.StatusCode != 200 && resp.JSON()["error"] == "invalid_target" {
					return Result{Status: StatusPass, Message: "unknown audience → invalid_target", Evidence: resp.Evidence}
				}
				// Many ASes don't validate audience membership; this is MAY, so a 200 is acceptable.
				return Result{Status: StatusPass, Message: "audience validation optional (MAY); no failure", Evidence: resp.Evidence}
			}),
	)
}

// exchangeAndDecode performs the standard delegation exchange and decodes the
// issued access token's claims (payload only; no signature verification needed
// to read act/aud). delegation=true includes the actor token.
func exchangeAndDecode(t *Target, do func(*Target, probe.ExchangeInput, url.Values) (*probe.Response, error), delegation bool) (map[string]any, []byte, error) {
	in := probe.ExchangeInput{SubjectToken: t.Creds.SubjectToken, SubjectTokenType: "access_token"}
	if delegation {
		in.ActorToken = t.Hints["actor_token"]
		in.ActorTokenType = "access_token"
	}
	resp, err := do(t, in, nil)
	if err != nil {
		return nil, nil, err
	}
	tok, _ := resp.JSON()["access_token"].(string)
	claims := probe.DecodeJWTPayload(tok)
	return claims, resp.Evidence, nil
}
