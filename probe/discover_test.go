package probe

import (
	"context"
	"fmt"
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
