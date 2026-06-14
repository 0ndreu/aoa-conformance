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

func TestDiscover_MetadataFields(t *testing.T) {
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

func TestDiscover_PRMPresentationFields(t *testing.T) {
	as := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-authorization-server" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"issuer":"`+issuerOf(r)+`","token_endpoint":"`+issuerOf(r)+`/token"}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer as.Close()

	rs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/mcp":
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+issuerOf(r)+`/.well-known/oauth-protected-resource"`)
			w.WriteHeader(401)
		case "/.well-known/oauth-protected-resource":
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"resource":"`+issuerOf(r)+`","authorization_servers":["`+as.URL+`"],"bearer_methods_supported":["body","header"],"dpop_bound_access_tokens_required":true}`)
		}
	}))
	defer rs.Close()

	d, err := Discover(context.Background(), rs.Client(), DiscoverInput{MCPURL: rs.URL + "/mcp"})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if len(d.PRMBearerMethodsSupported) != 2 || d.PRMBearerMethodsSupported[0] != "body" {
		t.Errorf("bearer methods = %v", d.PRMBearerMethodsSupported)
	}
	if !d.PRMDPoPBoundAccessTokensRequired {
		t.Errorf("dpop_bound_access_tokens_required = false")
	}
}

func TestDiscover_PhaseCMetadataFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{
			"issuer":"`+issuerOf(r)+`",
			"token_endpoint":"`+issuerOf(r)+`/token",
			"jwks_uri":"`+issuerOf(r)+`/jwks",
			"introspection_endpoint":"`+issuerOf(r)+`/introspect",
			"revocation_endpoint":"`+issuerOf(r)+`/revoke",
			"response_types_supported":["code","token"],
			"authorization_response_iss_parameter_supported":true,
			"signed_metadata":"eyJ.signed.jwt",
			"tls_client_certificate_bound_access_tokens":true,
			"mtls_endpoint_aliases":{"token_endpoint":"`+issuerOf(r)+`/mtls/token"}
		}`)
	}))
	defer srv.Close()

	d, err := Discover(context.Background(), srv.Client(), DiscoverInput{Issuer: srv.URL})
	if err != nil {
		t.Fatalf("discover: %v", err)
	}
	if d.IntrospectionEndpoint == "" || d.RevocationEndpoint == "" {
		t.Errorf("introspection/revocation = %q/%q", d.IntrospectionEndpoint, d.RevocationEndpoint)
	}
	if len(d.ResponseTypesSupported) != 2 {
		t.Errorf("response_types = %v", d.ResponseTypesSupported)
	}
	if !d.AuthorizationResponseIssParameterSupported {
		t.Errorf("iss param supported = false")
	}
	if d.SignedMetadata == "" {
		t.Errorf("signed_metadata empty")
	}
	if !d.TLSClientCertificateBoundAccessTokens {
		t.Errorf("mtls bound = false")
	}
	if d.MTLSEndpointAliases["token_endpoint"] == "" {
		t.Errorf("mtls aliases = %v", d.MTLSEndpointAliases)
	}
}

// issuerOf reconstructs the test server's base URL from the request.
func issuerOf(r *http.Request) string { return "http://" + r.Host }
