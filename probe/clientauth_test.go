package probe

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func TestApplyClientAuth_Post(t *testing.T) {
	form := url.Values{}
	h := ApplyClientAuth(form, AuthClientSecretPost, "cid", "secret")
	if h != nil {
		t.Fatalf("post must not set headers, got %v", h)
	}
	if form.Get("client_id") != "cid" || form.Get("client_secret") != "secret" {
		t.Fatalf("post must put creds in form, got %v", form)
	}
}

func TestApplyClientAuth_Basic(t *testing.T) {
	form := url.Values{}
	h := ApplyClientAuth(form, AuthClientSecretBasic, "cid", "secret")
	if form.Get("client_secret") != "" {
		t.Fatalf("basic must not put secret in form")
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("cid:secret"))
	if got := h.Get("Authorization"); got != want {
		t.Fatalf("basic header = %q, want %q", got, want)
	}
}

func TestApplyClientAuth_NoSecretIsAnonymous(t *testing.T) {
	form := url.Values{}
	h := ApplyClientAuth(form, AuthClientSecretPost, "cid", "")
	if h != nil {
		t.Fatalf("no secret must not set headers")
	}
	if form.Get("client_id") != "cid" || form.Get("client_secret") != "" {
		t.Fatalf("no secret: client_id only, got %v", form)
	}
}

// TestImplementsClientAuthGatesUnsupportedMethods pins which
// token_endpoint_auth_method values resolveTokenAuthMethod may pick. Claiming
// a method we cannot perform would turn every credentialed check into an
// unexplained token-endpoint failure.
func TestImplementsClientAuthGatesUnsupportedMethods(t *testing.T) {
	for _, m := range []string{AuthClientSecretPost, AuthClientSecretBasic, AuthNone} {
		if !ImplementsClientAuth(m) {
			t.Errorf("ImplementsClientAuth(%q) = false, but ApplyClientAuth handles it", m)
		}
	}
	for _, m := range []string{"private_key_jwt", "client_secret_jwt", "tls_client_auth", "", "None"} {
		if ImplementsClientAuth(m) {
			t.Errorf("ImplementsClientAuth(%q) = true, but ApplyClientAuth cannot perform it", m)
		}
	}
}
