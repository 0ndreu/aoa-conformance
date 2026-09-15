package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// RegisterInput is an RFC 7591 dynamic client registration request.
type RegisterInput struct {
	RegistrationEndpoint    string
	RedirectURIs            []string
	GrantTypes              []string
	TokenEndpointAuthMethod string
	Scope                   string
	ApplicationType         string // OIDC application_type, e.g. "native" (SEP-837)
	ClientName              string // RFC 7591 client_name; omit when empty
	InitialAccessToken      string // optional RFC 7591 §3 bearer
}

// RegisterResult holds the issued client. RegistrationAccessToken /
// RegistrationClientURI enable a best-effort RFC 7591 §4 delete on exit.
type RegisterResult struct {
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret"`
	RegistrationAccessToken string `json:"registration_access_token"`
	RegistrationClientURI   string `json:"registration_client_uri"`
	ApplicationType         string `json:"application_type"`
	// TokenEndpointAuthMethod is the method the AS assigned to the client it
	// just issued; it overrides what we asked for.
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method"`
	Evidence                []byte `json:"-"`
}

// RegistrationError is a DCR failure that carries the raw exchange, so a run
// can report "we could not register, here is what the AS said" instead of
// leaving the operator to infer it from a wall of skipped checks.
type RegistrationError struct {
	Err      error
	Evidence []byte
}

func (e *RegistrationError) Error() string { return e.Err.Error() }
func (e *RegistrationError) Unwrap() error { return e.Err }

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
	if in.ApplicationType != "" {
		body["application_type"] = in.ApplicationType
	}
	if in.ClientName != "" {
		body["client_name"] = in.ClientName
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
		return nil, &RegistrationError{Err: fmt.Errorf("registration failed: HTTP %d%s", resp.StatusCode, registrationErrorDetail(resp)), Evidence: resp.Evidence}
	}
	var out RegisterResult
	if err := json.Unmarshal(resp.Body, &out); err != nil {
		return nil, &RegistrationError{Err: fmt.Errorf("registration response not JSON: %w", err), Evidence: resp.Evidence}
	}
	if out.ClientID == "" {
		return nil, &RegistrationError{Err: fmt.Errorf("registration response has no client_id"), Evidence: resp.Evidence}
	}
	out.RegistrationClientURI = resolveAgainst(in.RegistrationEndpoint, out.RegistrationClientURI)
	out.Evidence = resp.Evidence
	return &out, nil
}

// resolveAgainst turns a relative registration_client_uri into an absolute one
// by resolving it against the registration endpoint it came from (RFC 3986 §5).
// Real servers do return relative references here — Linear answers
// "/register/<id>" — and taking them literally would both break the RFC 7591 §4
// cleanup and make the issuer-binding check compare an empty origin.
//
// Only a reference with no authority component (a plain relative path) is
// resolved. A reference that already carries a host — whether fully absolute
// or scheme-relative ("//evil.example/x") — is returned untouched: resolving
// it would let a malicious or misbehaving AS redirect DeleteRegistration's
// bearer-credentialed cleanup request to an arbitrary host. A genuinely
// foreign value still reaches the caller unresolved, which is what the
// issuer-binding check is for.
func resolveAgainst(base, ref string) string {
	if ref == "" {
		return ""
	}
	r, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	if r.IsAbs() || r.Host != "" {
		return ref
	}
	b, err := url.Parse(base)
	if err != nil {
		return ref
	}
	return b.ResolveReference(r).String()
}

// registrationErrorDetail renders the RFC 7591 §3.2.2 error body, when the AS
// sent one, as a parenthesised suffix for the error message.
func registrationErrorDetail(resp *Response) string {
	code, _ := resp.JSON()["error"].(string)
	if code == "" {
		return ""
	}
	if desc, _ := resp.JSON()["error_description"].(string); desc != "" {
		return fmt.Sprintf(" %s: %s", code, desc)
	}
	return " " + code
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
