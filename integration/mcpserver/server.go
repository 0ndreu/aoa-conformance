package main

import (
	"fmt"
	"net/http"

	"github.com/0ndreu/aoa"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// buildDeps carries the discovered/overridden AS endpoints into buildMux so the
// function stays free of network calls (resolved by the caller in main / tests).
type buildDeps struct {
	jwksURI       string
	tokenEndpoint string
	// httpClient is used for the RFC 8693 token exchange and the gateway's
	// downstream call. It must trust the provider/downstream TLS (the dev
	// self-signed cert), since both endpoints are https. nil ⇒ http.DefaultClient
	// (fine for tests that don't exercise those calls, but the live server must
	// pass a CA-trusting client or the exchange/downstream call fails x509).
	httpClient *http.Client
	// keysJWKS is the provider's JWKS, pre-fetched by the caller with a
	// CA-trusting client and passed as static keys. aoa's own remote JWKS
	// fetcher uses a default http.Client that cannot trust the dev cert over
	// https, so without this every token validation 401s. nil ⇒ fall back to
	// JWKSURI (only viable when the JWKS is served over trusted TLS, e.g. tests).
	keysJWKS []byte
}

// buildMux wires the unguarded PRM, the guarded /mcp MCP transport, and the
// guarded /data downstream stub.
func buildMux(cfg *Config, deps buildDeps) (*http.ServeMux, error) {
	p, err := cfg.Active()
	if err != nil {
		return nil, err
	}
	resource := cfg.Server.Resource

	// --- RFC 9728 PRM (unguarded) ---
	prmPath, err := aoa.MetadataPathFor(resource)
	if err != nil {
		return nil, fmt.Errorf("metadata path: %w", err)
	}
	prm, err := aoa.NewMetadataHandler(aoa.ProtectedResourceMetadata{
		Resource:             resource,
		AuthorizationServers: []string{p.Issuer},
		ScopesSupported:      p.RequiredScopes,
	}, aoa.HandlerOptions{AllowInsecureLocalhost: true})
	if err != nil {
		return nil, fmt.Errorf("metadata handler: %w", err)
	}

	// --- Bearer guard for /mcp ---
	guard, err := aoa.RequireBearer(aoa.BearerOpts{
		Issuer:         p.Issuer,
		JWKSURI:        deps.jwksURI,
		KeysJWKS:       deps.keysJWKS, // takes precedence over JWKSURI when set
		Audience:       p.Audience,
		Resource:       resource,
		RequiredScopes: p.RequiredScopes,
		DPoP:           p.DPoPMode(),
	})
	if err != nil {
		return nil, fmt.Errorf("require bearer (mcp): %w", err)
	}

	// --- Bearer guard for /data (downstream audience) ---
	guardDown, err := aoa.RequireBearer(aoa.BearerOpts{
		Issuer:   p.Issuer,
		JWKSURI:  deps.jwksURI,
		KeysJWKS: deps.keysJWKS, // takes precedence over JWKSURI when set
		Audience: cfg.Downstream.Audience,
		Resource: cfg.Downstream.URL,
		DPoP:     aoa.DPoPOptional,
	})
	if err != nil {
		return nil, fmt.Errorf("require bearer (data): %w", err)
	}

	// --- MCP server with tools ---
	srv := mcp.NewServer(&mcp.Implementation{Name: "aoa-mcp", Version: "v0.1.0"}, nil)
	mcp.AddTool(srv, &mcp.Tool{Name: "add", Description: "Add two integers"}, addHandler)

	httpClient := deps.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	exch, err := aoa.NewTokenExchanger(aoa.ExchangeConfig{
		TokenEndpoint: deps.tokenEndpoint,
		ClientAuth:    aoa.ClientSecretAuth(p.Exchange.ClientID, p.Exchange.ClientSecret, true),
		HTTPClient:    deps.httpClient, // nil ⇒ aoa's own default client
	})
	if err != nil {
		return nil, fmt.Errorf("token exchanger: %w", err)
	}
	gw := &gateway{exchanger: exch, downstreamURL: cfg.Downstream.URL, audience: cfg.Downstream.Audience, client: httpClient}
	mcp.AddTool(srv, &mcp.Tool{Name: "call_downstream", Description: "Exchange the caller's token (RFC 8693) and call the downstream resource"}, gw.handle)

	mcpHandler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)

	mux := http.NewServeMux()
	mux.Handle(prmPath, prm)
	mux.Handle("/mcp", guard(mcpHandler))
	mux.Handle("/data", guardDown(downstreamHandler()))
	return mux, nil
}
