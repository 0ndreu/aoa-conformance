package probe

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
)

// DiscoverInput selects the entry point. Exactly one of MCPURL / Issuer is set.
type DiscoverInput struct {
	MCPURL string
	Issuer string
}

// Discovered is the resolved endpoint/capability set (mirrors conformance.Discovered).
type Discovered struct {
	Issuer                        string
	TokenEndpoint                 string
	AuthorizationEndpoint         string
	JWKSURI                       string
	GrantTypesSupported           []string
	CodeChallengeMethodsSupported []string
	DPoPSigningAlgValuesSupported []string
	PRMAuthorizationServers       []string
	WWWAuthenticate               string
	RawASMetadata                 []byte
	RawPRM                        []byte
}

var resourceMetadataRE = regexp.MustCompile(`resource_metadata="([^"]+)"`)

// Discover walks the agent loop (in MCPURL mode) or fetches AS metadata directly
// (in Issuer mode) and returns the resolved endpoints + advertised capabilities.
func Discover(ctx context.Context, c *http.Client, in DiscoverInput) (*Discovered, error) {
	d := &Discovered{}
	issuer := in.Issuer

	if in.MCPURL != "" {
		// step 1: trigger the 401 and read the resource_metadata pointer.
		resp, err := Get(ctx, c, in.MCPURL)
		if err != nil {
			return nil, err
		}
		d.WWWAuthenticate = resp.Header.Get("WWW-Authenticate")
		prmURL := prmURLFromChallenge(d.WWWAuthenticate)
		if prmURL == "" {
			// fall back to the well-known default path on the MCP origin.
			prmURL = strings.TrimRight(originOf(in.MCPURL), "/") + "/.well-known/oauth-protected-resource"
		}
		// step 2: fetch the PRM.
		prm, err := Get(ctx, c, prmURL)
		if err != nil {
			return nil, err
		}
		d.RawPRM = prm.Body
		var prmDoc struct {
			AuthorizationServers []string `json:"authorization_servers"`
		}
		_ = json.Unmarshal(prm.Body, &prmDoc)
		d.PRMAuthorizationServers = prmDoc.AuthorizationServers
		if len(prmDoc.AuthorizationServers) == 0 {
			return d, errors.New("PRM has no authorization_servers")
		}
		issuer = prmDoc.AuthorizationServers[0]
	}

	if issuer == "" {
		return nil, errors.New("no issuer to discover")
	}
	d.Issuer = issuer

	// step 3: AS metadata (RFC 8414 well-known, with OIDC fallback).
	meta, raw, err := fetchASMetadata(ctx, c, issuer)
	if err != nil {
		return d, err
	}
	d.RawASMetadata = raw
	d.TokenEndpoint = meta.TokenEndpoint
	d.AuthorizationEndpoint = meta.AuthorizationEndpoint
	d.JWKSURI = meta.JWKSURI
	d.GrantTypesSupported = meta.GrantTypesSupported
	d.CodeChallengeMethodsSupported = meta.CodeChallengeMethodsSupported
	d.DPoPSigningAlgValuesSupported = meta.DPoPSigningAlgValuesSupported
	return d, nil
}

type asMetadata struct {
	Issuer                        string   `json:"issuer"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	JWKSURI                       string   `json:"jwks_uri"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported"`
}

func fetchASMetadata(ctx context.Context, c *http.Client, issuer string) (asMetadata, []byte, error) {
	for _, suffix := range []string{"/.well-known/oauth-authorization-server", "/.well-known/openid-configuration"} {
		resp, err := Get(ctx, c, strings.TrimRight(issuer, "/")+suffix)
		if err != nil || resp.StatusCode != 200 {
			continue
		}
		var m asMetadata
		if json.Unmarshal(resp.Body, &m) == nil && m.TokenEndpoint != "" {
			return m, resp.Body, nil
		}
	}
	return asMetadata{}, nil, errors.New("no usable AS metadata at well-known endpoints")
}

func prmURLFromChallenge(h string) string {
	m := resourceMetadataRE.FindStringSubmatch(h)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

func originOf(raw string) string {
	if i := strings.Index(raw, "://"); i >= 0 {
		if j := strings.Index(raw[i+3:], "/"); j >= 0 {
			return raw[:i+3+j]
		}
	}
	return raw
}
