package probe

import (
	"net/url"
	"testing"
)

func TestExchangeFormImpersonationAndDelegation(t *testing.T) {
	imp := ExchangeForm(ExchangeInput{SubjectToken: "S", SubjectTokenType: "access_token"})
	if imp.Get("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Fatalf("grant_type wrong: %s", imp.Get("grant_type"))
	}
	if imp.Get("subject_token") != "S" || imp.Has("actor_token") {
		t.Fatalf("impersonation should have subject only: %v", url.Values(imp))
	}
	del := ExchangeForm(ExchangeInput{SubjectToken: "S", SubjectTokenType: "access_token",
		ActorToken: "A", ActorTokenType: "access_token", Audience: []string{"https://tool"}})
	if del.Get("actor_token") != "A" {
		t.Fatal("delegation should carry actor_token")
	}
	if del.Get("audience") != "https://tool" {
		t.Fatalf("audience missing: %v", url.Values(del))
	}
}
