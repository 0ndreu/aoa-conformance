package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/0ndreu/aoa"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type addIn struct {
	A int `json:"a" jsonschema:"first addend"`
	B int `json:"b" jsonschema:"second addend"`
}
type addOut struct {
	Sum int `json:"sum"`
}

// addHandler is a trivial local tool: proof that a guarded tool executes only
// with a valid token (the guard runs before this handler).
func addHandler(_ context.Context, _ *mcp.CallToolRequest, in addIn) (*mcp.CallToolResult, addOut, error) {
	return nil, addOut{Sum: in.A + in.B}, nil
}

type callIn struct {
	// reserved for future args; the tool currently calls a fixed downstream URL.
}
type callOut struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// gateway holds the RFC 8693 exchanger and downstream target for the
// call_downstream tool.
type gateway struct {
	exchanger     *aoa.TokenExchanger
	downstreamURL string
	audience      []string
	client        *http.Client
}

// handle exchanges the caller's token for a downscoped one and calls the
// downstream resource with it.
func (g *gateway) handle(ctx context.Context, req *mcp.CallToolRequest, _ callIn) (*mcp.CallToolResult, callOut, error) {
	authz := ""
	if req != nil && req.Extra != nil && req.Extra.Header != nil {
		authz = req.Extra.Header.Get("Authorization")
	}
	subject := strings.TrimSpace(authz)
	for _, scheme := range []string{"Bearer ", "DPoP "} {
		if len(subject) >= len(scheme) && strings.EqualFold(subject[:len(scheme)], scheme) {
			subject = subject[len(scheme):]
			break
		}
	}
	if subject == "" {
		return nil, callOut{}, fmt.Errorf("call_downstream: no caller token to exchange")
	}

	res, err := g.exchanger.Exchange(ctx, aoa.ExchangeRequest{
		SubjectToken: subject,
		Audience:     g.audience,
	})
	if err != nil {
		return nil, callOut{}, fmt.Errorf("token exchange: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, g.downstreamURL, nil)
	if err != nil {
		return nil, callOut{}, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+res.AccessToken)
	resp, err := g.client.Do(httpReq)
	if err != nil {
		return nil, callOut{}, fmt.Errorf("downstream call: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	return nil, callOut{Status: resp.StatusCode, Body: string(body)}, nil
}
