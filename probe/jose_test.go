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
	// a token authorizing actor "svc-gateway" to act for "alice".
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

// TestDecodeJWTPayloadReadsClaimsWithoutKey covers the reader the token-
// exchange checks use to inspect act/aud on a token they never hold a key for.
func TestDecodeJWTPayloadReadsClaimsWithoutKey(t *testing.T) {
	s, err := NewSigner()
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	tok, err := s.SignJWT(map[string]any{
		"iss": "https://as.example",
		"aud": "https://rs.example/mcp",
		"act": map[string]any{"sub": "actor-1"},
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	claims := DecodeJWTPayload(tok)
	if claims["iss"] != "https://as.example" {
		t.Fatalf("iss claim = %v", claims["iss"])
	}
	// aud is signed as the JWT string-or-array claim, so it decodes as a list.
	aud, ok := claims["aud"].([]any)
	if !ok || len(aud) != 1 || aud[0] != "https://rs.example/mcp" {
		t.Fatalf("aud claim = %v", claims["aud"])
	}
	act, ok := claims["act"].(map[string]any)
	if !ok || act["sub"] != "actor-1" {
		t.Fatalf("act claim = %v", claims["act"])
	}

	// An opaque token is not an error: checks treat "no readable claims" as
	// "cannot assert on claims", so both shapes must yield an empty map.
	for _, bad := range []string{"opaque-access-token", "", "not.base64url!.sig"} {
		if got := DecodeJWTPayload(bad); len(got) != 0 {
			t.Errorf("DecodeJWTPayload(%q) = %v, want empty", bad, got)
		}
	}
}
