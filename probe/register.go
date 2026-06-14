package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// RegisterInput is an RFC 7591 dynamic client registration request.
type RegisterInput struct {
	RegistrationEndpoint    string
	RedirectURIs            []string
	GrantTypes              []string
	TokenEndpointAuthMethod string
	Scope                   string
	InitialAccessToken      string // optional RFC 7591 §3 bearer
}

// RegisterResult holds the issued client. RegistrationAccessToken /
// RegistrationClientURI enable a best-effort RFC 7591 §4 delete on exit.
type RegisterResult struct {
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret"`
	RegistrationAccessToken string `json:"registration_access_token"`
	RegistrationClientURI   string `json:"registration_client_uri"`
	Evidence                []byte `json:"-"`
}

func Register(ctx context.Context, c *http.Client, in RegisterInput) (*RegisterResult, error) {
	body := map[string]any{}
	if len(in.RedirectURIs) > 0 {
		body["redirect_uris"] = in.RedirectURIs
	}
	if len(in.GrantTypes) > 0 {
		body["grant_types"] = in.GrantTypes
	}
	if in.TokenEndpointAuthMethod != "" {
		body["token_endpoint_auth_method"] = in.TokenEndpointAuthMethod
	}
	if in.Scope != "" {
		body["scope"] = in.Scope
	}
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, in.RegistrationEndpoint, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if in.InitialAccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+in.InitialAccessToken)
	}
	resp, err := do(c, req, fmt.Sprintf("POST %s\nbody: %s", in.RegistrationEndpoint, buf))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("registration failed: HTTP %d", resp.StatusCode)
	}
	var out RegisterResult
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, fmt.Errorf("registration response not JSON: %w", err)
	}
	if out.ClientID == "" {
		return nil, fmt.Errorf("registration response has no client_id")
	}
	out.Evidence = resp.Evidence
	return &out, nil
}

// DeleteRegistration issues a best-effort RFC 7591 §4 delete of an ephemeral
// client. Errors are returned for logging but are non-fatal to callers.
func DeleteRegistration(ctx context.Context, c *http.Client, registrationClientURI, registrationAccessToken string) error {
	if strings.TrimSpace(registrationClientURI) == "" {
		return nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, registrationClientURI, nil)
	if err != nil {
		return err
	}
	if registrationAccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+registrationAccessToken)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("delete registration: HTTP %d", resp.StatusCode)
	}
	return nil
}
