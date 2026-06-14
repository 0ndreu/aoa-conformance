package internal

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0ndreu/aoa"
	"github.com/0ndreu/aoa-conformance/conformance"
	"github.com/0ndreu/aoa-conformance/internal/fakeas"
)

// TestDogfoodAgainstRealAOAServer boots a real aoa-guarded resource server
// (RFC 9728 metadata handler + Bearer middleware) in front of a fake AS, and
// asserts aoa-conform's RFC 9728 discovery checks all go green against it,
// proving the tool works against a genuine aoa server without coupling the unit
// tests to aoa.
//
// API shapes used (verified against the installed aoa at ../aoa):
//
//   - aoa.MetadataPathFor(resource) → the RFC 9728 §3.1 well-known path; it
//     appends the resource's path component to /.well-known/oauth-protected-resource.
//   - aoa.NewMetadataHandler(aoa.ProtectedResourceMetadata{Resource, AuthorizationServers},
//     aoa.HandlerOptions{AllowInsecureLocalhost}) → the PRM handler. Only Resource
//     is required. AllowInsecureLocalhost relaxes the *resource* scheme to http for
//     localhost, but each AuthorizationServers entry is validated by aoa's
//     validateIssuerURL, which requires https with NO localhost exception. So the
//     advertised AS must be served over https: here a second httptest TLS server
//     that re-serves the fake AS's RFC 8414 metadata.
//   - aoa.BearerOpts has NO ResourceMetadata field. The RFC 9728 resource_metadata
//     hint in the 401 WWW-Authenticate challenge is derived from BearerOpts.Resource
//     (deriveChallengeParams → MetadataPathFor → resourceMetadataURL). We set
//     Resource to the guarded MCP URL so the challenge points at the PRM path we
//     registered. KeysJWKS+Issuer are wired to the fake AS so minted tokens verify.
//   - aoa.RequireBearer(opts) → (middleware, error).
//
// Because the aoa Resource and the resource_metadata pointer must be
// self-consistent with the server's own URL, the MCP httptest server is started
// first, then the metadata/bearer handlers are built against the now-known URL.
func TestDogfoodAgainstRealAOAServer(t *testing.T) {
	as := fakeas.NewAS(fakeas.Violations{})
	defer as.Close()

	// aoa rejects an http authorization_servers entry, so re-serve the fake AS's
	// RFC 8414 metadata over https. token_endpoint stays the fake AS's real (http)
	// endpoint, the RFC 9728 as_resolvable check only needs a resolvable
	// token_endpoint string, it does not have to be reached during discovery.
	asTLS := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			http.NotFound(w, r)
			return
		}
		proxyJSON(w, r, as.URL+"/.well-known/oauth-authorization-server")
	}))
	defer asTLS.Close()

	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	resource := srv.URL + "/mcp"

	prmPath, err := aoa.MetadataPathFor(resource)
	if err != nil {
		t.Fatalf("metadata path: %v", err)
	}
	h, err := aoa.NewMetadataHandler(aoa.ProtectedResourceMetadata{
		Resource:             resource,
		AuthorizationServers: []string{asTLS.URL},
	}, aoa.HandlerOptions{AllowInsecureLocalhost: true})
	if err != nil {
		t.Fatalf("metadata handler: %v", err)
	}
	mux.Handle(prmPath, h)

	bearer, err := aoa.RequireBearer(aoa.BearerOpts{
		KeysJWKS: as.SignerJWKS(),
		Issuer:   as.URL,
		Resource: resource,
	})
	if err != nil {
		t.Fatalf("bearer: %v", err)
	}
	mux.Handle("/mcp", bearer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	// one client that trusts the AS TLS server's cert (plain http to the MCP
	// server works on any client).
	pool := x509.NewCertPool()
	pool.AddCert(asTLS.Certificate())
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}}}

	tgt := &conformance.Target{MCPURL: resource, Client: client}
	rep := (&conformance.Runner{Registry: conformance.DefaultRegistry()}).Run(tgt)

	// all four RFC 9728 client-side discovery checks must PASS against a real
	// aoa server: the resource_metadata challenge hint, a fetchable+valid PRM,
	// a non-empty authorization_servers list, and a resolvable AS token endpoint.
	// we assert pass (not merely "not fail") and that all four actually ran, so a
	// regression that silently turned them into skips can't pass unnoticed.
	rfc9728Passes := 0
	for _, e := range rep.Entries {
		if e.Check.RFC != "RFC 9728" {
			continue
		}
		if e.Result.Status != conformance.StatusPass {
			t.Fatalf("RFC 9728 check %s should pass against a real aoa server, got %s: %s",
				e.Check.ID, e.Result.Status, e.Result.Message)
		}
		rfc9728Passes++
	}
	if rfc9728Passes != 4 {
		t.Fatalf("expected all 4 RFC 9728 discovery checks to run and pass, got %d", rfc9728Passes)
	}
}

// proxyJSON re-serves the JSON body of target as this response.
func proxyJSON(w http.ResponseWriter, r *http.Request, target string) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
