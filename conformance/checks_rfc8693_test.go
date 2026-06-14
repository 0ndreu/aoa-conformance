package conformance

import (
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
	"github.com/0ndreu/aoa-conformance/probe"
)

func exchangeTarget(t *testing.T, v fakeas.Violations, subjectClaims, actorClaims map[string]any) *Target {
	t.Helper()
	as := fakeas.NewAS(v)
	t.Cleanup(as.Close)
	tgt := &Target{Issuer: as.URL}
	(&Runner{Registry: DefaultRegistry()}).Run(tgt) // discovery
	tgt.Plan = AuthPlan{ClientID: "test-client", ClientSecret: "test-secret", TokenAuthMethod: probe.AuthClientSecretPost}
	tgt.Creds.SubjectToken = as.MintToken(subjectClaims)
	if actorClaims != nil {
		if tgt.Hints == nil {
			tgt.Hints = map[string]string{}
		}
		tgt.Hints["actor_token"] = as.MintToken(actorClaims)
	}
	return tgt
}

func TestRFC8693_ImpersonationIssuesToken(t *testing.T) {
	good := exchangeTarget(t, fakeas.Violations{}, map[string]any{"sub": "alice"}, nil)
	if got := runChecksFor(t, "RFC 8693", good)["rfc8693.impersonation.issues_token"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}

	bad := exchangeTarget(t, fakeas.Violations{FailImpersonation: true}, map[string]any{"sub": "alice"}, nil)
	if got := runChecksFor(t, "RFC 8693", bad)["rfc8693.impersonation.issues_token"]; got.Status != StatusFail {
		t.Fatalf("impersonation refused: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8693_DelegationIssuesToken(t *testing.T) {
	subject := map[string]any{"sub": "alice"}
	actor := map[string]any{"sub": "svc-new"}
	good := exchangeTarget(t, fakeas.Violations{}, subject, actor)
	if got := runChecksFor(t, "RFC 8693", good)["rfc8693.delegation.issues_token"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}

	bad := exchangeTarget(t, fakeas.Violations{RejectDelegation: true}, subject, actor)
	if got := runChecksFor(t, "RFC 8693", bad)["rfc8693.delegation.issues_token"]; got.Status != StatusFail {
		t.Fatalf("delegation refused: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8693_ActPresent(t *testing.T) {
	subject := map[string]any{"sub": "alice"}
	actor := map[string]any{"sub": "svc-new"}
	good := exchangeTarget(t, fakeas.Violations{}, subject, actor)
	if got := runChecksFor(t, "RFC 8693", good)["rfc8693.delegation.act_present"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}

	bad := exchangeTarget(t, fakeas.Violations{OmitAct: true}, subject, actor)
	if got := runChecksFor(t, "RFC 8693", bad)["rfc8693.delegation.act_present"]; got.Status != StatusFail {
		t.Fatalf("act omitted: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8693_MayActDenied(t *testing.T) {
	// subject authorizes only svc-A; actor is svc-EVIL.
	subject := map[string]any{"sub": "alice", "may_act": map[string]any{"sub": "svc-A"}}
	actor := map[string]any{"sub": "svc-EVIL"}

	good := exchangeTarget(t, fakeas.Violations{}, subject, actor)
	if got := runChecksFor(t, "RFC 8693", good)["rfc8693.delegation.may_act_enforced"]; got.Status != StatusPass {
		t.Fatalf("correct AS rejects unauthorized actor → want pass, got %s (%s)", got.Status, got.Message)
	}

	bad := exchangeTarget(t, fakeas.Violations{IgnoreMayAct: true}, subject, actor)
	if got := runChecksFor(t, "RFC 8693", bad)["rfc8693.delegation.may_act_enforced"]; got.Status != StatusFail {
		t.Fatalf("buggy AS accepts → want fail, got %s", got.Status)
	}
}

func TestRFC8693_ActNesting(t *testing.T) {
	subject := map[string]any{"sub": "alice", "act": map[string]any{"sub": "svc-prior"}}
	actor := map[string]any{"sub": "svc-new"}

	good := exchangeTarget(t, fakeas.Violations{}, subject, actor)
	if got := runChecksFor(t, "RFC 8693", good)["rfc8693.delegation.act_nesting"]; got.Status != StatusPass {
		t.Fatalf("correct nesting → want pass, got %s (%s)", got.Status, got.Message)
	}
	bad := exchangeTarget(t, fakeas.Violations{ForgeActChain: true}, subject, actor)
	if got := runChecksFor(t, "RFC 8693", bad)["rfc8693.delegation.act_nesting"]; got.Status != StatusFail {
		t.Fatalf("forged chain → want fail, got %s", got.Status)
	}
}

func TestRFC8693_DownscopeScopeHonored(t *testing.T) {
	good := exchangeTarget(t, fakeas.Violations{}, map[string]any{"sub": "alice"}, nil)
	if got := runChecksFor(t, "RFC 8693", good)["rfc8693.downscope.scope_honored"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}

	bad := exchangeTarget(t, fakeas.Violations{WidenScope: true}, map[string]any{"sub": "alice"}, nil)
	if got := runChecksFor(t, "RFC 8693", bad)["rfc8693.downscope.scope_honored"]; got.Status != StatusFail {
		t.Fatalf("scope widened: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8693_InvalidGrantOnBadSubject(t *testing.T) {
	good := exchangeTarget(t, fakeas.Violations{}, map[string]any{"sub": "alice"}, nil)
	if got := runChecksFor(t, "RFC 8693", good)["rfc8693.error.invalid_grant_on_bad_subject"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}

	bad := exchangeTarget(t, fakeas.Violations{AcceptBadSubject: true}, map[string]any{"sub": "alice"}, nil)
	if got := runChecksFor(t, "RFC 8693", bad)["rfc8693.error.invalid_grant_on_bad_subject"]; got.Status != StatusFail {
		t.Fatalf("garbage subject accepted: want fail, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8693_InvalidTargetOnUnknownAudience(t *testing.T) {
	tgt := exchangeTarget(t, fakeas.Violations{}, map[string]any{"sub": "alice"}, nil)
	if got := runChecksFor(t, "RFC 8693", tgt)["rfc8693.error.invalid_target_on_unknown_audience"]; got.Status != StatusPass {
		t.Fatalf("want pass (MAY), got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8693_GrantAdvertised(t *testing.T) {
	tgt := exchangeTarget(t, fakeas.Violations{}, map[string]any{"sub": "alice"}, nil)
	if got := runChecksFor(t, "RFC 8693", tgt)["rfc8693.grant.advertised"]; got.Status != StatusPass {
		t.Fatalf("want pass, got %s (%s)", got.Status, got.Message)
	}
}

func TestRFC8693_SkipsWhenCapabilityAbsent(t *testing.T) {
	tgt := exchangeTarget(t, fakeas.Violations{NoTokenExchange: true}, map[string]any{"sub": "alice"}, nil)
	if got := runChecksFor(t, "RFC 8693", tgt)["rfc8693.impersonation.issues_token"]; got.Status != StatusSkip {
		t.Fatalf("no token-exchange capability → want skip, got %s", got.Status)
	}
}

func TestRFC8693_DelegationSkipsWithoutActor(t *testing.T) {
	tgt := exchangeTarget(t, fakeas.Violations{}, map[string]any{"sub": "alice"}, nil)
	if got := runChecksFor(t, "RFC 8693", tgt)["rfc8693.delegation.issues_token"]; got.Status != StatusSkip {
		t.Fatalf("no actor token → want skip, got %s", got.Status)
	}
}
