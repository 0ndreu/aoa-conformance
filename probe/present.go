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

	// DPoP, when non-nil, binds the request: htm=POST (or GET for query),
	// htu=ResourceURL, ath=base64url(SHA-256(Token)). The token is sent as a
	// DPoP-scheme credential, not Bearer.
	DPoP *ProofKey
	// DPoPNonce is set on a use_dpop_nonce retry.
	DPoPNonce string
}

// PresentToken issues the resource request and captures the response.
//
// The default header method speaks MCP: the token rides an Authorization
// header on a real JSON-RPC POST, so the status reflects whether the resource
// server accepted the token rather than whether it tolerates a bare GET. The
// body and query methods stay as plain RFC 6750 presentations — their only
// purpose is the advisory check that a server must not accept them.
func PresentToken(ctx context.Context, c *http.Client, in PresentInput) (*Response, error) {
	method := in.Method
	if method == "" {
		method = "header"
	}
	if method == "header" {
		return presentViaMCP(ctx, c, in)
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
	default:
		return nil, fmt.Errorf("unsupported bearer method %q", method)
	}

	if in.DPoP != nil {
		proof, err := dpopProof(in, httpMethod)
		if err != nil {
			return nil, err
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

func presentViaMCP(ctx context.Context, c *http.Client, in PresentInput) (*Response, error) {
	mcpIn := MCPInput{Endpoint: in.ResourceURL, Token: in.Token, AuthScheme: "Bearer"}
	if in.DPoP != nil {
		mcpIn.AuthScheme = "DPoP"
		proof, err := dpopProof(in, http.MethodPost)
		if err != nil {
			return nil, err
		}
		mcpIn.ExtraHeaders = http.Header{"DPoP": {proof}}
	}
	res, err := MCPRequest(ctx, c, mcpIn)
	if err != nil {
		return nil, err
	}
	return res.Response, nil
}

func dpopProof(in PresentInput, httpMethod string) (string, error) {
	proof, err := in.DPoP.Proof(ProofParams{
		HTM:   httpMethod,
		HTU:   in.ResourceURL,
		ATH:   S256(in.Token),
		Nonce: in.DPoPNonce,
	})
	if err != nil {
		return "", fmt.Errorf("mint resource DPoP proof: %w", err)
	}
	return proof, nil
}
