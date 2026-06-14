package probe

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// ProofKey mints DPoP proofs (RFC 9449). Tamper fields let checks build
// deliberately invalid proofs to confirm the AS rejects them.
type ProofKey struct {
	priv jwk.Key
	pub  jwk.Key
}

func NewProofKey() (*ProofKey, error) {
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	priv, err := jwk.Import(ek)
	if err != nil {
		return nil, err
	}
	pub, err := priv.PublicKey()
	if err != nil {
		return nil, err
	}
	return &ProofKey{priv: priv, pub: pub}, nil
}

// Thumbprint returns the RFC 7638 JWK thumbprint (the cnf.jkt the AS should bind).
func (k *ProofKey) Thumbprint() (string, error) {
	tp, err := k.pub.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return b64url(tp), nil
}

type ProofParams struct {
	HTM       string
	HTU       string
	Nonce     string // set for the use_dpop_nonce retry
	ATH       string // access-token hash; empty at the token endpoint
	TamperHTU string // if set, the proof carries this htu instead (negative test)
	OmitJTI   bool   // negative test
}

func (k *ProofKey) Proof(p ProofParams) (string, error) {
	htu := p.HTU
	if p.TamperHTU != "" {
		htu = p.TamperHTU
	}
	b := jwt.NewBuilder().
		Claim("htm", p.HTM).
		Claim("htu", htu).
		Claim("iat", nowUnix())
	if !p.OmitJTI {
		b.Claim("jti", randHex(16))
	}
	if p.Nonce != "" {
		b.Claim("nonce", p.Nonce)
	}
	if p.ATH != "" {
		b.Claim("ath", p.ATH)
	}
	tok, err := b.Build()
	if err != nil {
		return "", err
	}
	hdrs := jws.NewHeaders()
	_ = hdrs.Set("typ", "dpop+jwt")
	_ = hdrs.Set(jws.JWKKey, k.pub)
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.ES256(), k.priv, jws.WithProtectedHeaders(hdrs)))
	if err != nil {
		return "", fmt.Errorf("sign proof: %w", err)
	}
	return string(signed), nil
}
