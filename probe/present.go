package probe

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// PresentInput describes presenting an access token to a resource (RFC 6750
// bearer method, with optional RFC 9449 DPoP binding).
type PresentInput struct {
	ResourceURL string
	Token       string
	Method      string // header | body | query (default header)

	// DPoP, when non-nil, binds the request: htm=GET (or POST for body),
	// htu=ResourceURL, ath=base64url(SHA-256(Token)). The token is sent as a
	// DPoP-scheme credential, not Bearer.
	DPoP *ProofKey
	// DPoPNonce is set on a use_dpop_nonce retry.
	DPoPNonce string
}

// PresentToken issues the resource request and captures the response.
func PresentToken(ctx context.Context, c *http.Client, in PresentInput) (*Response, error) {
	method := in.Method
	if method == "" {
		method = "header"
	}

	httpMethod := http.MethodGet
	var body string
	target := in.ResourceURL
	headers := http.Header{}

	switch method {
	case "query":
		u, err := url.Parse(in.ResourceURL)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("access_token", in.Token)
		u.RawQuery = q.Encode()
		target = u.String()
	case "body":
		httpMethod = http.MethodPost
		body = url.Values{"access_token": {in.Token}}.Encode()
		headers.Set("Content-Type", "application/x-www-form-urlencoded")
	default: // header
		scheme := "Bearer"
		if in.DPoP != nil {
			scheme = "DPoP"
		}
		headers.Set("Authorization", scheme+" "+in.Token)
	}

	if in.DPoP != nil {
		ath := S256(in.Token)
		proof, err := in.DPoP.Proof(ProofParams{HTM: httpMethod, HTU: in.ResourceURL, ATH: ath, Nonce: in.DPoPNonce})
		if err != nil {
			return nil, fmt.Errorf("mint resource DPoP proof: %w", err)
		}
		headers.Set("DPoP", proof)
	}

	req, err := http.NewRequestWithContext(ctx, httpMethod, target, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return do(c, req, fmt.Sprintf("%s %s (bearer method: %s)", httpMethod, target, method))
}
