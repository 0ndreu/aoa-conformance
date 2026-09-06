package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegister_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s", r.Method)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"client_id":"cid","client_secret":"sec","registration_access_token":"rat","registration_client_uri":"` + "http://x/register/cid" + `"}`))
	}))
	defer srv.Close()

	got, err := Register(context.Background(), srv.Client(), RegisterInput{
		RegistrationEndpoint:    srv.URL,
		RedirectURIs:            []string{"http://127.0.0.1:9999/callback"},
		GrantTypes:              []string{"client_credentials"},
		TokenEndpointAuthMethod: AuthClientSecretPost,
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if got.ClientID != "cid" || got.ClientSecret != "sec" || got.RegistrationAccessToken != "rat" {
		t.Fatalf("unexpected result %+v", got)
	}
}

func TestRegisterSendsAndCapturesApplicationType(t *testing.T) {
	var seen map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &seen)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"client_id":"c","application_type":"native"}`))
	}))
	defer srv.Close()

	res, err := Register(context.Background(), srv.Client(), RegisterInput{
		RegistrationEndpoint: srv.URL,
		ApplicationType:      "native",
	})
	if err != nil {
		t.Fatal(err)
	}
	if seen["application_type"] != "native" {
		t.Fatalf("request application_type = %v, want native", seen["application_type"])
	}
	if res.ApplicationType != "native" {
		t.Fatalf("response application_type = %q, want native", res.ApplicationType)
	}
}

func TestRegister_ErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()
	if _, err := Register(context.Background(), srv.Client(), RegisterInput{RegistrationEndpoint: srv.URL}); err == nil {
		t.Fatal("want error on non-2xx, got nil")
	}
}

// TestDeleteRegistrationRemovesEphemeralClient covers the cleanup path for a
// client the run registered itself: the DELETE goes to the AS-supplied
// registration_client_uri with the registration access token, and a refusal is
// reported (callers log it) rather than swallowed.
func TestDeleteRegistrationRemovesEphemeralClient(t *testing.T) {
	var method, auth string
	status := 204
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, auth = r.Method, r.Header.Get("Authorization")
		w.WriteHeader(status)
	}))
	defer srv.Close()

	if err := DeleteRegistration(context.Background(), srv.Client(), srv.URL+"/register/cid", "rat"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if method != http.MethodDelete || auth != "Bearer rat" {
		t.Fatalf("request = %s, Authorization = %q", method, auth)
	}

	status = 403
	err := DeleteRegistration(context.Background(), srv.Client(), srv.URL+"/register/cid", "rat")
	if err == nil {
		t.Fatal("a refused delete must be reported, got nil")
	}

	// No registration_client_uri means there is nothing to clean up.
	if err := DeleteRegistration(context.Background(), srv.Client(), "  ", "rat"); err != nil {
		t.Fatalf("empty uri: %v", err)
	}
}

// TestRegistrationErrorCarriesRawExchange is the contract Task 5 relies on:
// resolve.go surfaces a DCR refusal as a named error entry, which needs both
// the AS's own error code and the raw exchange for the evidence file.
func TestRegistrationErrorCarriesRawExchange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		_, _ = w.Write([]byte(`{"error":"invalid_client_metadata","error_description":"grant_types not allowed"}`))
	}))
	defer srv.Close()

	_, err := Register(context.Background(), srv.Client(), RegisterInput{RegistrationEndpoint: srv.URL})
	var regErr *RegistrationError
	if !errors.As(err, &regErr) {
		t.Fatalf("err = %v, want *RegistrationError", err)
	}
	if !strings.Contains(regErr.Error(), "invalid_client_metadata") || !strings.Contains(regErr.Error(), "grant_types not allowed") {
		t.Fatalf("error message loses the AS's reason: %q", regErr.Error())
	}
	if !bytes.Contains(regErr.Evidence, []byte("invalid_client_metadata")) {
		t.Fatalf("evidence does not carry the exchange: %s", regErr.Evidence)
	}
	if errors.Unwrap(regErr) == nil {
		t.Fatal("Unwrap() = nil, the underlying error is lost")
	}
}

// TestRegisterResolvesRelativeRegistrationClientURI covers what real servers
// actually send: Linear answers DCR with registration_client_uri="/register/<id>".
// Taken literally that is not a URL — cleanup cannot DELETE it and the SEP-2352
// issuer-binding check compares an empty origin and reports a false MUST
// failure. RFC 3986 §5 says resolve it against the document it came from.
func TestRegisterResolvesRelativeRegistrationClientURI(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"client_id":"cid","registration_client_uri":"/register/cid"}`))
	}))
	defer srv.Close()

	got, err := Register(context.Background(), srv.Client(), RegisterInput{RegistrationEndpoint: srv.URL + "/oauth/register"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if want := srv.URL + "/register/cid"; got.RegistrationClientURI != want {
		t.Fatalf("RegistrationClientURI = %q, want %q", got.RegistrationClientURI, want)
	}

	// An absolute value is left exactly as the AS sent it: a cross-issuer
	// registration_client_uri is a real SEP-2352 finding and must not be
	// rewritten into the endpoint's own origin.
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"client_id":"cid","registration_client_uri":"https://elsewhere.example/register/cid"}`))
	}))
	defer srv2.Close()

	got2, err := Register(context.Background(), srv2.Client(), RegisterInput{RegistrationEndpoint: srv2.URL + "/oauth/register"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if got2.RegistrationClientURI != "https://elsewhere.example/register/cid" {
		t.Fatalf("absolute URI rewritten to %q", got2.RegistrationClientURI)
	}

	// A scheme-relative reference ("//host/path") also carries its own
	// authority and must not be resolved: url.ResolveReference would adopt the
	// reference's host while keeping the base's scheme, turning a value a
	// malicious/misbehaving AS controls into a fully qualified URL that
	// DeleteRegistration would then send the registration_access_token to.
	srv3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"client_id":"cid","registration_client_uri":"//evil.example/steal/cid"}`))
	}))
	defer srv3.Close()

	got3, err := Register(context.Background(), srv3.Client(), RegisterInput{RegistrationEndpoint: srv3.URL + "/oauth/register"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if got3.RegistrationClientURI != "//evil.example/steal/cid" {
		t.Fatalf("scheme-relative registration_client_uri resolved to an attacker-controlled URL: %q", got3.RegistrationClientURI)
	}
}
