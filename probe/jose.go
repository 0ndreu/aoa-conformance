package probe

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Signer mints (and verifies) JWTs with an in-memory RSA key. It is the
// building block both for the fake AS's correct tokens and for adversarial
// probes (e.g. handing a self-signed token to a real AS to see if it is
// wrongly accepted). It uses jwx directly. aoa hides jwx, so we cannot.
type Signer struct {
	priv jwk.Key
	pub  jwk.Key
	kid  string
}

func NewSigner() (*Signer, error) {
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	priv, err := jwk.Import(rk)
	if err != nil {
		return nil, err
	}
	_ = priv.Set(jwk.KeyIDKey, "probe-key-1")
	_ = priv.Set(jwk.AlgorithmKey, jwa.RS256())
	pub, err := priv.PublicKey()
	if err != nil {
		return nil, err
	}
	return &Signer{priv: priv, pub: pub, kid: "probe-key-1"}, nil
}

// SignJWT signs an arbitrary claim set. Use it to build subject/actor tokens
// (with may_act, act, cnf, etc.) for probing.
func (s *Signer) SignJWT(claims map[string]any) (string, error) {
	b := jwt.NewBuilder()
	for k, v := range claims {
		b.Claim(k, v)
	}
	tok, err := b.Build()
	if err != nil {
		return "", err
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256(), s.priv))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

// Verify validates a token against this signer's own public key.
func (s *Signer) Verify(token string) (map[string]any, error) {
	set := jwk.NewSet()
	_ = set.AddKey(s.pub)
	tok, err := jwt.Parse([]byte(token), jwt.WithKeySet(set), jwt.WithValidate(true))
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	for _, k := range tok.Keys() {
		var v any
		_ = tok.Get(k, &v)
		out[k] = v
	}
	return out, nil
}

// PublicJWKS returns the JSON JWKS for this signer's public key (served by the
// fake AS at its jwks_uri).
func (s *Signer) PublicJWKS() []byte {
	set := jwk.NewSet()
	_ = set.AddKey(s.pub)
	buf, _ := json.Marshal(set)
	return buf
}

// DecodeJWTPayload returns a JWS/JWT payload's claims without verifying the
// signature. Used by checks that only need to read issued claims (act, aud).
func DecodeJWTPayload(token string) map[string]any {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return map[string]any{}
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return map[string]any{}
	}
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return out
}
