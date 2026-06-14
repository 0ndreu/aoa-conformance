package fakeas

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jws"
)

// dpopNonce is the fixed nonce the fake AS hands back in its use_dpop_nonce
// challenge. The client echoes it in the retried proof.
const dpopNonce = "fakeas-dpop-nonce-1"

// parsedProof is a parsed, signature-verified DPoP proof.
type parsedProof struct {
	jkt   string // base64url RFC 7638 thumbprint of the embedded public key
	htm   string
	htu   string
	nonce string
}

type dpopClaims struct {
	HTM   string `json:"htm"`
	HTU   string `json:"htu"`
	Nonce string `json:"nonce"`
}

// parseDPoPProof parses raw as a DPoP proof JWS, verifies the signature against
// the embedded jwk, and returns the decoded proof + thumbprint. Mirrors the aoa
// dpop_proof.go shapes for jwx v3.1.1.
func parseDPoPProof(raw []byte) (*parsedProof, error) {
	msg, err := jws.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse proof: %w", err)
	}
	sigs := msg.Signatures()
	if len(sigs) == 0 {
		return nil, errors.New("proof has no signature")
	}
	h := sigs[0].ProtectedHeaders()

	if typ, ok := h.Type(); !ok || typ != "dpop+jwt" {
		return nil, fmt.Errorf("proof typ = %q, want dpop+jwt", typ)
	}
	alg, ok := h.Algorithm()
	if !ok {
		return nil, errors.New("proof missing alg")
	}
	key, ok := h.JWK()
	if !ok {
		return nil, errors.New("proof missing jwk header")
	}

	payload, err := jws.Verify(raw, jws.WithKey(alg, key))
	if err != nil {
		return nil, fmt.Errorf("proof signature: %w", err)
	}

	tp, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("thumbprint: %w", err)
	}

	var c dpopClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, fmt.Errorf("proof claims: %w", err)
	}
	return &parsedProof{
		jkt:   base64.RawURLEncoding.EncodeToString(tp),
		htm:   c.HTM,
		htu:   c.HTU,
		nonce: c.Nonce,
	}, nil
}
