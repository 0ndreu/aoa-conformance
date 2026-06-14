package probe

import (
	"testing"
	"time"
)

func TestSignedJWTAndKeyMaterial(t *testing.T) {
	signer, err := NewSigner()
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	tok, err := signer.SignJWT(map[string]any{
		"sub": "alice",
		"iss": "https://issuer.example",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	claims, err := signer.Verify(tok)
	if err != nil {
		t.Fatalf("verify own token: %v", err)
	}
	if claims["sub"] != "alice" {
		t.Fatalf("sub = %v", claims["sub"])
	}
	if len(signer.PublicJWKS()) == 0 {
		t.Fatal("public JWKS should be non-empty")
	}
}

func TestTokenWithMayActAndAct(t *testing.T) {
	signer, _ := NewSigner()
	// A token authorizing actor "svc-gateway" to act for "alice".
	tok, err := signer.SignJWT(map[string]any{
		"sub":     "alice",
		"iss":     "https://issuer.example",
		"exp":     time.Now().Add(time.Hour).Unix(),
		"may_act": map[string]any{"sub": "svc-gateway"},
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	claims, _ := signer.Verify(tok)
	ma, ok := claims["may_act"].(map[string]any)
	if !ok || ma["sub"] != "svc-gateway" {
		t.Fatalf("may_act not round-tripped: %v", claims["may_act"])
	}
}
