package conformance

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
	"github.com/0ndreu/aoa-conformance/probe"
)

func TestResolveTokenAuthMethod(t *testing.T) {
	cases := []struct {
		name       string
		explicit   string
		advertised []string
		want       string
	}{
		{"explicit wins", probe.AuthClientSecretBasic, []string{"client_secret_post"}, probe.AuthClientSecretBasic},
		{"intersection picks advertised we implement", "", []string{"private_key_jwt", "client_secret_basic"}, probe.AuthClientSecretBasic},
		{"post preferred when both advertised", "", []string{"client_secret_basic", "client_secret_post"}, probe.AuthClientSecretPost},
		{"default to post when nothing advertised", "", nil, probe.AuthClientSecretPost},
		{"default to post when only unimplemented advertised", "", []string{"private_key_jwt"}, probe.AuthClientSecretPost},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveTokenAuthMethod(c.explicit, c.advertised); got != c.want {
				t.Errorf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestResolveScopesPrecedence(t *testing.T) {
	// explicit > PRM (reuses EffectiveScopes).
	if got := EffectiveScopes([]string{"a"}, []string{"b"}); !reflect.DeepEqual(got, []string{"a"}) {
		t.Errorf("explicit must win, got %v", got)
	}
}

func TestResolve_UsesExplicitClient(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	t.Cleanup(as.Close)
	d := discoveredFor(t, as.URL)

	plan, err := Resolve(context.Background(), as.Client(), d, ResolveOptions{
		ClientID: "given", ClientSecret: "givensecret",
	})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if plan.Registered {
		t.Errorf("explicit client must not DCR")
	}
	if plan.ClientID != "given" || plan.ClientSecret != "givensecret" {
		t.Errorf("explicit client not used: %+v", plan)
	}
	if plan.TokenAuthMethod != probe.AuthClientSecretPost {
		t.Errorf("default auth method = %q", plan.TokenAuthMethod)
	}
}

func TestResolve_DCRWhenNoClient(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	t.Cleanup(as.Close)
	d := discoveredFor(t, as.URL)

	plan, err := Resolve(context.Background(), as.Client(), d, ResolveOptions{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !plan.Registered || plan.ClientID == "" || plan.ClientSecret == "" {
		t.Fatalf("expected a DCR'd client, got %+v", plan)
	}
}

func TestResolve_NoClientNoRegistrationLeavesEmpty(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{NoRegistration: true})
	t.Cleanup(as.Close)
	d := discoveredFor(t, as.URL)

	plan, err := Resolve(context.Background(), as.Client(), d, ResolveOptions{})
	if err != nil {
		t.Fatalf("resolve should not error when DCR unavailable: %v", err)
	}
	if plan.hasClient() {
		t.Fatalf("expected no client, got %+v", plan)
	}
}

func TestResolve_PARFromMetadata(t *testing.T) {
	d := Discovered{
		Issuer:                             "https://as.example",
		TokenEndpoint:                      "https://as.example/token",
		PushedAuthorizationRequestEndpoint: "https://as.example/par",
		RequirePushedAuthorizationRequests: true,
	}
	plan, err := Resolve(context.Background(), http.DefaultClient, d, ResolveOptions{ClientID: "c", ClientSecret: "s"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !plan.UsePAR || plan.PAREndpoint != "https://as.example/par" {
		t.Fatalf("PAR not resolved: %+v", plan)
	}
}

// discoveredFor runs discovery against the fake AS and returns the resolved
// Discovered, so resolver tests share one boot path.
func discoveredFor(t *testing.T, issuer string) Discovered {
	t.Helper()
	tgt := &Target{Issuer: issuer}
	(&Runner{Registry: &Registry{}}).Run(tgt) // discovery only; empty registry
	return tgt.Discovered
}
