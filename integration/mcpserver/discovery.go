package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Discover fetches the issuer's OIDC discovery document and returns its
// jwks_uri and token_endpoint. Provider-agnostic: Keycloak, Hydra, and Okta
// all serve {issuer}/.well-known/openid-configuration.
func Discover(ctx context.Context, client *http.Client, issuer string) (jwksURI, tokenEndpoint string, err error) {
	url := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", fmt.Errorf("discovery fetch %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("discovery %s: status %d", url, resp.StatusCode)
	}
	var doc struct {
		JWKSURI       string `json:"jwks_uri"`
		TokenEndpoint string `json:"token_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", "", fmt.Errorf("discovery decode: %w", err)
	}
	if doc.JWKSURI == "" || doc.TokenEndpoint == "" {
		return "", "", fmt.Errorf("discovery %s: missing jwks_uri or token_endpoint", url)
	}
	return doc.JWKSURI, doc.TokenEndpoint, nil
}
