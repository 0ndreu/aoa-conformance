package probe

import (
	"context"
	"fmt"
	"net/http"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
)

// VerifyJWTWithJWKS fetches a JWKS document and verifies that token's JWS
// signature is produced by one of its keys. It does not validate claims.
func VerifyJWTWithJWKS(ctx context.Context, c *http.Client, token, jwksURI string) error {
	resp, err := Get(ctx, c, jwksURI)
	if err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	if resp.StatusCode != 200 {
		return fmt.Errorf("jwks fetch: HTTP %d", resp.StatusCode)
	}
	set, err := jwk.Parse(resp.Body)
	if err != nil {
		return fmt.Errorf("parse jwks: %w", err)
	}
	if _, err := jws.Verify([]byte(token), jws.WithKeySet(set)); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}
