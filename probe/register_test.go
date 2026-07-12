package probe

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
