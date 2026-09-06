package conformance

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/0ndreu/aoa-conformance/internal/fakeas"
	"github.com/0ndreu/aoa-conformance/probe"
)

func TestResolveTokenAuthMethod(t *testing.T) {
	cases := []struct {
		name       string
		explicit   string
		advertised []string
		hasSecret  bool
		want       string
	}{
		{"explicit wins", probe.AuthClientSecretBasic, []string{"client_secret_post"}, true, probe.AuthClientSecretBasic},
		{"intersection picks advertised we implement", "", []string{"private_key_jwt", "client_secret_basic"}, true, probe.AuthClientSecretBasic},
		{"post preferred when both advertised", "", []string{"client_secret_basic", "client_secret_post"}, true, probe.AuthClientSecretPost},
		{"default to post when nothing advertised", "", nil, true, probe.AuthClientSecretPost},
		{"default to post when only unimplemented advertised", "", []string{"private_key_jwt"}, true, probe.AuthClientSecretPost},
		{"none when secretless and advertised", "", []string{"none", "client_secret_post"}, false, probe.AuthNone},
		{"secret in hand outranks none", "", []string{"none", "client_secret_post"}, true, probe.AuthClientSecretPost},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolveTokenAuthMethod(c.explicit, c.advertised, c.hasSecret); got != c.want {
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

func TestResolve_PresentationFields(t *testing.T) {
	d := Discovered{
		Issuer:                           "https://as.example",
		TokenEndpoint:                    "https://as.example/token",
		PRMBearerMethodsSupported:        []string{"body", "header"},
		PRMDPoPBoundAccessTokensRequired: true,
	}
	plan, err := Resolve(context.Background(), http.DefaultClient, d, ResolveOptions{ClientID: "c", ClientSecret: "s"})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if plan.BearerMethod != "body" {
		t.Errorf("BearerMethod = %q, want first advertised (body)", plan.BearerMethod)
	}
	if !plan.DPoPRequired {
		t.Errorf("DPoPRequired = false")
	}
}

func TestResolve_BearerMethodDefaultsToHeader(t *testing.T) {
	plan, _ := Resolve(context.Background(), http.DefaultClient,
		Discovered{Issuer: "https://x", TokenEndpoint: "https://x/token"},
		ResolveOptions{ClientID: "c", ClientSecret: "s"})
	if plan.BearerMethod != "header" {
		t.Errorf("default BearerMethod = %q, want header", plan.BearerMethod)
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

// a public authorization server — one that issues secretless clients and never
// offers client_credentials — is the shape of every real MCP server. The run
// must come out of resolution with a client it can act as.
func TestResolve_PublicClientIsUsable(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{PublicClientsOnly: true, NoClientCredentials: true})
	t.Cleanup(as.Close)
	d := discoveredFor(t, as.URL)

	plan, err := Resolve(context.Background(), as.Client(), d, ResolveOptions{})
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !plan.hasClient() {
		t.Fatalf("a secretless client must count as a client: %+v", plan)
	}
	if plan.ClientSecret != "" {
		t.Errorf("public client should hold no secret, got %q", plan.ClientSecret)
	}
	if plan.TokenAuthMethod != probe.AuthNone {
		t.Errorf("TokenAuthMethod = %q, want none", plan.TokenAuthMethod)
	}
}

// what we ask for on DCR has to be registrable: the grants the AS actually
// offers, a redirect_uri (always), and an application_type that matches it.
func TestResolve_RegistrationRequestShape(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{NoClientCredentials: true})
	t.Cleanup(as.Close)
	d := discoveredFor(t, as.URL)

	if _, err := Resolve(context.Background(), as.Client(), d, ResolveOptions{}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	req := as.LastRegistration()
	grants := stringsOf(req["grant_types"])
	if !reflect.DeepEqual(grants, []string{"authorization_code"}) {
		t.Errorf("grant_types = %v, want only the advertised authorization_code", grants)
	}
	if len(stringsOf(req["redirect_uris"])) == 0 {
		t.Errorf("redirect_uris must always be sent, got %v", req["redirect_uris"])
	}
	if req["application_type"] != "native" {
		t.Errorf("application_type = %v, want native for a loopback redirect", req["application_type"])
	}
}

func TestResolve_ApplicationTypeFollowsRedirect(t *testing.T) {
	cases := map[string]string{
		"http://127.0.0.1:8765/callback":  "native",
		"http://localhost:8765/callback":  "native",
		"com.example.app:/oauth/callback": "native",
		"https://app.example/callback":    "web",
	}
	for redirect, want := range cases {
		if got := registrationApplicationType([]string{redirect}); got != want {
			t.Errorf("%s: got %q want %q", redirect, got, want)
		}
	}
}

// a refused registration must leave a reason behind, not an empty plan.
func TestResolve_RecordsRegistrationFailure(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{RejectRegistration: true})
	t.Cleanup(as.Close)
	d := discoveredFor(t, as.URL)

	plan, err := Resolve(context.Background(), as.Client(), d, ResolveOptions{})
	if err != nil {
		t.Fatalf("DCR failure must stay non-fatal: %v", err)
	}
	if plan.hasClient() {
		t.Fatalf("expected no client, got %+v", plan)
	}
	if !strings.Contains(plan.RegistrationError, "invalid_client_metadata") {
		t.Errorf("RegistrationError should quote the AS error, got %q", plan.RegistrationError)
	}
	if len(plan.RegistrationEvidence) == 0 {
		t.Error("failed registration must keep the raw exchange as evidence")
	}
}

// stringsOf converts a decoded JSON array into a []string.
func stringsOf(v any) []string {
	arr, _ := v.([]any)
	out := make([]string, 0, len(arr))
	for _, x := range arr {
		s, _ := x.(string)
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
