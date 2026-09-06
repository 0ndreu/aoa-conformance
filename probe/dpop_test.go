package probe

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
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

// TestThumbprintMatchesEmbeddedProofKey checks that the jkt we would compare
// against an AS-issued cnf claim is the thumbprint of the very key the proof
// carries in its jwk header — otherwise a DPoP-binding check would compare two
// unrelated values and pass or fail for the wrong reason.
func TestThumbprintMatchesEmbeddedProofKey(t *testing.T) {
	k, err := NewProofKey()
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	jkt, err := k.Thumbprint()
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}

	proof, err := k.Proof(ProofParams{HTM: "POST", HTU: "https://issuer.example/token"})
	if err != nil {
		t.Fatalf("proof: %v", err)
	}
	hdr, _ := decodeJWS(t, proof)
	embedded, ok := hdr["jwk"].(map[string]any)
	if !ok {
		t.Fatalf("proof header has no jwk: %v", hdr)
	}
	key, err := jwk.ParseKey(mustJSON(t, embedded))
	if err != nil {
		t.Fatalf("parse embedded jwk: %v", err)
	}
	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("thumbprint of embedded jwk: %v", err)
	}
	if want := b64url(tp); jkt != want {
		t.Fatalf("Thumbprint() = %q, embedded key thumbprint = %q", jkt, want)
	}

	// The thumbprint is a property of the key, not of the call.
	again, _ := k.Thumbprint()
	if again != jkt {
		t.Fatalf("Thumbprint() not stable: %q then %q", jkt, again)
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	buf, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return buf
}
