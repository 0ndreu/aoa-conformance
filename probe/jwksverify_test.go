package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyJWTWithJWKS(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatal(err)
	}
	jwks := signer.PublicJWKS()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	defer srv.Close()

	token, err := signer.SignJWT(map[string]any{"issuer": "https://x"})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyJWTWithJWKS(context.Background(), srv.Client(), token, srv.URL); err != nil {
		t.Fatalf("valid signed metadata rejected: %v", err)
	}

	other, _ := NewSigner()
	bad, _ := other.SignJWT(map[string]any{"issuer": "https://x"})
	if err := VerifyJWTWithJWKS(context.Background(), srv.Client(), bad, srv.URL); err == nil {
		t.Fatalf("token from wrong key should fail verification")
	}
}
