package probe

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscoverFromIssuerParsesASMetadata(t *testing.T) {
	var as *httptest.Server
	as = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			fmt.Fprintf(w, `{"issuer":%q,"token_endpoint":%q,"grant_types_supported":["authorization_code","urn:ietf:params:oauth:grant-type:token-exchange"],"code_challenge_methods_supported":["S256"],"dpop_signing_alg_values_supported":["ES256"]}`,
				as.URL, as.URL+"/token")
			return
		}
		w.WriteHeader(404)
	}))
	defer as.Close()

	d, err := Discover(context.Background(), http.DefaultClient, DiscoverInput{Issuer: as.URL})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if d.TokenEndpoint != as.URL+"/token" {
		t.Fatalf("token_endpoint = %s", d.TokenEndpoint)
	}
	if len(d.CodeChallengeMethodsSupported) != 1 || d.CodeChallengeMethodsSupported[0] != "S256" {
		t.Fatalf("pkce methods = %v", d.CodeChallengeMethodsSupported)
	}
	if len(d.DPoPSigningAlgValuesSupported) == 0 {
		t.Fatal("dpop algs should be advertised")
	}
}

func TestDiscoverFromMCPTargetFollowsPRM(t *testing.T) {
	var as, rs *httptest.Server
	as = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			fmt.Fprintf(w, `{"issuer":%q,"token_endpoint":%q}`, as.URL, as.URL+"/token")
		}
	}))
	defer as.Close()
	rs = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-protected-resource":
			fmt.Fprintf(w, `{"resource":%q,"authorization_servers":[%q]}`, rs.URL, as.URL)
		default:
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, rs.URL))
			w.WriteHeader(401)
		}
	}))
	defer rs.Close()

	d, err := Discover(context.Background(), http.DefaultClient, DiscoverInput{MCPURL: rs.URL + "/mcp"})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(d.PRMAuthorizationServers) != 1 || d.PRMAuthorizationServers[0] != as.URL {
		t.Fatalf("PRM authorization_servers = %v", d.PRMAuthorizationServers)
	}
	if d.TokenEndpoint != as.URL+"/token" {
		t.Fatalf("token endpoint via PRM->AS = %s", d.TokenEndpoint)
	}
}

func TestDiscover_PhaseAMetadataFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"issuer": "`+issuerOf(r)+`",
			"token_endpoint": "`+issuerOf(r)+`/token",
			"registration_endpoint": "`+issuerOf(r)+`/register",
			"token_endpoint_auth_methods_supported": ["client_secret_basic","client_secret_post"],
			"pushed_authorization_request_endpoint": "`+issuerOf(r)+`/par",
			"require_pushed_authorization_requests": true
		}`)
	}))
	defer srv.Close()

	d, err := Discover(context.Background(), srv.Client(), DiscoverInput{Issuer: srv.URL})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if d.RegistrationEndpoint != srv.URL+"/register" {
		t.Errorf("registration_endpoint = %q", d.RegistrationEndpoint)
	}
	if len(d.TokenEndpointAuthMethodsSupported) != 2 {
		t.Errorf("auth methods = %v", d.TokenEndpointAuthMethodsSupported)
	}
	if d.PushedAuthorizationRequestEndpoint != srv.URL+"/par" {
		t.Errorf("PAR endpoint = %q", d.PushedAuthorizationRequestEndpoint)
	}
	if !d.RequirePushedAuthorizationRequests {
		t.Errorf("require_pushed_authorization_requests = false")
	}
}

// issuerOf reconstructs the test server's base URL from the request.
func issuerOf(r *http.Request) string { return "http://" + r.Host }
