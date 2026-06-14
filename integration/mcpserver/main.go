package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"time"
)

func main() {
	configPath := flag.String("config", "config.yaml", "path to config.yaml")
	provider := flag.String("provider", "", "override active_provider (also $MCP_PROVIDER)")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil {
		slog.Error("load config", "err", err)
		os.Exit(1)
	}
	if *provider != "" {
		cfg.ActiveProvider = *provider
	} else if env := os.Getenv("MCP_PROVIDER"); env != "" {
		cfg.ActiveProvider = env
	}

	p, err := cfg.Active()
	if err != nil {
		slog.Error("resolve provider", "err", err)
		os.Exit(1)
	}

	// resolve AS endpoints: explicit config wins, else discover.
	jwks, tokenEP := p.JWKSURI, p.TokenEndpoint
	if jwks == "" || tokenEP == "" {
		client := tlsClient(cfg)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		djwks, dtok, derr := Discover(ctx, client, p.Issuer)
		if derr != nil {
			slog.Error("discovery", "issuer", p.Issuer, "err", derr)
			os.Exit(1)
		}
		if jwks == "" {
			jwks = djwks
		}
		if tokenEP == "" {
			tokenEP = dtok
		}
	}

	// client for the RFC 8693 exchange (provider token endpoint) and the
	// gateway's downstream call. Both are https with the dev self-signed cert,
	// so they need a CA-trusting client. ErrUseLastResponse stops credential
	// replay across redirects (aoa's exchanger recommends this for custom clients).
	exchClient := tlsClient(cfg)
	exchClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	// pre-fetch the provider JWKS with the CA-trusting client and pass it as
	// static keys: aoa's built-in remote JWKS fetcher uses a default http.Client
	// that cannot trust the dev cert over https, so without this the guards 401
	// every token. (A real https-trusted provider could rely on JWKSURI instead.)
	keysJWKS, err := fetchJWKS(tlsClient(cfg), jwks)
	if err != nil {
		slog.Error("fetch jwks", "uri", jwks, "err", err)
		os.Exit(1)
	}

	mux, err := buildMux(cfg, buildDeps{jwksURI: jwks, tokenEndpoint: tokenEP, httpClient: exchClient, keysJWKS: keysJWKS})
	if err != nil {
		slog.Error("build mux", "err", err)
		os.Exit(1)
	}

	slog.Info("mcpserver listening", "addr", cfg.Server.Addr, "provider", cfg.ActiveProvider, "issuer", p.Issuer)
	if err := http.ListenAndServeTLS(cfg.Server.Addr, cfg.Server.TLS.Cert, cfg.Server.TLS.Key, mux); err != nil {
		slog.Error("serve", "err", err)
		os.Exit(1)
	}
}

// fetchJWKS GETs the provider's JWKS document with the given client and returns
// the raw bytes (passed to aoa as BearerOpts.KeysJWKS).
func fetchJWKS(client *http.Client, uri string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch jwks %s: %w", uri, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch jwks %s: status %d", uri, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// tlsClient returns an HTTP client that trusts the server's own CA file (so the
// server can fetch the provider's https metadata when it uses the same dev cert).
func tlsClient(cfg *Config) *http.Client {
	pem, err := os.ReadFile(cfg.Server.TLS.Cert)
	if err != nil {
		return &http.Client{Timeout: 10 * time.Second}
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
	}
}
