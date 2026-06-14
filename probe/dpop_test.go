package probe

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// decodeJWS splits a compact JWS and returns its protected header + payload as
// maps, without verifying the signature.
func decodeJWS(t *testing.T, compact string) (map[string]any, map[string]any) {
	t.Helper()
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("not a compact JWS: %q", compact)
	}
	hdrRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode header: %v", err)
	}
	clmRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	hdr := map[string]any{}
	clm := map[string]any{}
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		t.Fatalf("unmarshal header: %v", err)
	}
	if err := json.Unmarshal(clmRaw, &clm); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return hdr, clm
}

func TestDPoPProofHasRequiredClaims(t *testing.T) {
	k, err := NewProofKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	proof, err := k.Proof(ProofParams{HTM: "POST", HTU: "https://issuer.example/token"})
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	hdr, claims := decodeJWS(t, proof)
	if hdr["typ"] != "dpop+jwt" {
		t.Fatalf("typ = %v", hdr["typ"])
	}
	if _, ok := hdr["jwk"]; !ok {
		t.Fatal("proof header must embed the public jwk")
	}
	if claims["htm"] != "POST" || claims["htu"] != "https://issuer.example/token" {
		t.Fatalf("htm/htu wrong: %v / %v", claims["htm"], claims["htu"])
	}
	if claims["jti"] == nil {
		t.Fatal("jti required")
	}
}

func TestDPoPProofTamperOptions(t *testing.T) {
	k, _ := NewProofKey()
	// a proof with a deliberately wrong htu, to verify the AS rejects it.
	bad, err := k.Proof(ProofParams{HTM: "POST", HTU: "https://issuer.example/token", TamperHTU: "https://evil.example/token"})
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	_, claims := decodeJWS(t, bad)
	if !strings.Contains(claims["htu"].(string), "evil.example") {
		t.Fatalf("tamper not applied: %v", claims["htu"])
	}
	// a proof carrying a nonce (for the use_dpop_nonce retry).
	withNonce, _ := k.Proof(ProofParams{HTM: "POST", HTU: "https://issuer.example/token", Nonce: "abc123"})
	_, c2 := decodeJWS(t, withNonce)
	if c2["nonce"] != "abc123" {
		t.Fatalf("nonce not embedded: %v", c2["nonce"])
	}
}
