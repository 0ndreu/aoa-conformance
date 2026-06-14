package conformance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"

	"github.com/0ndreu/aoa-conformance/probe"
)

// CheckID is a dot-namespaced identifier, e.g. "rfc8693.delegation.act_nesting".
type CheckID string

type Profile string

const (
	ProfileCore     Profile = "mcp-core"
	ProfileExtended Profile = "mcp-agent-auth-extended"
)

type Severity string

const (
	SeverityMUST   Severity = "MUST"
	SeveritySHOULD Severity = "SHOULD"
	SeverityMAY    Severity = "MAY"
)

type Status string

const (
	StatusPass  Status = "pass"
	StatusFail  Status = "fail"
	StatusSkip  Status = "skip"
	StatusError Status = "error"
)

// Check is one conformance probe. Locked schema shape + Profile.
type Check struct {
	ID          CheckID
	Profile     Profile
	RFC         string // "RFC 8693"
	Section     string // "§2.1"
	Severity    Severity
	Description string
	// Precondition gates the check. Nil means always run. When it returns
	// false the runner records StatusSkip (capability/credential absent).
	Precondition func(*Target) bool
	// Run executes the probe against the target. It must never panic; a
	// transport/internal error is reported as StatusError.
	Run func(*Target) Result
}

// MarshalJSON serializes only the metadata fields of Check (func fields are omitted).
func (c Check) MarshalJSON() ([]byte, error) {
	type checkMeta struct {
		ID          CheckID  `json:"id"`
		Profile     Profile  `json:"profile"`
		RFC         string   `json:"rfc,omitempty"`
		Section     string   `json:"section,omitempty"`
		Severity    Severity `json:"severity,omitempty"`
		Description string   `json:"description,omitempty"`
	}
	return json.Marshal(checkMeta{
		ID:          c.ID,
		Profile:     c.Profile,
		RFC:         c.RFC,
		Section:     c.Section,
		Severity:    c.Severity,
		Description: c.Description,
	})
}

// Evaluate applies the precondition then runs the check.
func (c Check) Evaluate(t *Target) Result {
	if c.Precondition != nil && !c.Precondition(t) {
		return Result{Status: StatusSkip, Message: "precondition not met (capability or credential absent)"}
	}
	return c.Run(t)
}

// Result is the outcome of one check. Locked schema shape.
type Result struct {
	Status   Status        `json:"status"`
	Message  string        `json:"message"`
	Evidence []byte        `json:"evidence,omitempty"` // raw HTTP exchange / JSON for offline audit
	Duration time.Duration `json:"duration_ns"`
}

// Creds carries credentials supplied by the operator. Tier gating reads it.
type Creds struct {
	ClientID      string
	ClientSecret  string
	UsePostAuth   bool   // client_secret_post vs client_secret_basic
	PrivateKey    []byte // RFC 7523 private_key_jwt (PEM/JWK); optional
	PrivateKeyAlg string
	SubjectToken  string   // supplied Tier-2 user token
	Scopes        []string // scopes to request when obtaining a token (--scope)

	AuthCodeAvailable bool // true after an interactive auth_code flow; gates pkce.enforce.reject_plain
	PresentEnabled    bool // set by CLI --present; gates the smoke check
}

func (c Creds) hasClient() bool {
	return c.ClientID != "" && (c.ClientSecret != "" || c.PrivateKey != nil)
}
func (c Creds) hasSubject() bool { return c.SubjectToken != "" }

// AuthPlan is the single resolved decision set computed once after discovery.
// Precedence for every field is: explicit CLI value > discovered value >
// built-in default.
type AuthPlan struct {
	ClientID     string
	ClientSecret string
	Registered   bool // true when we DCR'd an ephemeral client

	TokenAuthMethod string // client_secret_post | client_secret_basic

	UsePAR      bool
	PAREndpoint string

	Scopes []string

	BearerMethod string // header | body | query
	DPoPRequired bool

	// RegistrationAccessToken / RegistrationClientURI are set only for a DCR'd
	// client, to delete it best-effort on exit (RFC 7591 §4).
	RegistrationAccessToken string
	RegistrationClientURI   string
}

func (p AuthPlan) hasClient() bool { return p.ClientID != "" && p.ClientSecret != "" }

// EffectiveScopes resolves which scopes to request when obtaining a token:
// an explicit --scope value wins, otherwise the scopes the resource advertises
// in its RFC 9728 PRM scopes_supported are used.
func EffectiveScopes(explicit, fromPRM []string) []string {
	if len(explicit) > 0 {
		return explicit
	}
	return fromPRM
}

// Discovered holds everything the discovery phase resolved.
type Discovered struct {
	Issuer                        string
	TokenEndpoint                 string
	AuthorizationEndpoint         string
	JWKSURI                       string
	GrantTypesSupported           []string
	CodeChallengeMethodsSupported []string
	DPoPSigningAlgValuesSupported []string
	// PRM is the RFC 9728 Protected Resource Metadata (only set in --target mode).
	PRMAuthorizationServers          []string
	PRMScopesSupported               []string
	PRMBearerMethodsSupported        []string
	PRMDPoPBoundAccessTokensRequired bool
	// raw metadata documents, kept for evidence.
	RawASMetadata []byte
	RawPRM        []byte

	RegistrationEndpoint               string
	TokenEndpointAuthMethodsSupported  []string
	PushedAuthorizationRequestEndpoint string
	RequirePushedAuthorizationRequests bool

	IntrospectionEndpoint                      string
	RevocationEndpoint                         string
	ResponseTypesSupported                     []string
	AuthorizationResponseIssParameterSupported bool
	SignedMetadata                             string
	TLSClientCertificateBoundAccessTokens      bool
	MTLSEndpointAliases                        map[string]string
}

func (d Discovered) advertisesTokenExchange() bool {
	for _, g := range d.GrantTypesSupported {
		if g == "urn:ietf:params:oauth:grant-type:token-exchange" {
			return true
		}
	}
	return false
}

func (d Discovered) advertisesDPoP() bool { return len(d.DPoPSigningAlgValuesSupported) > 0 }

func (d Discovered) advertisesS256() bool {
	for _, m := range d.CodeChallengeMethodsSupported {
		if m == "S256" {
			return true
		}
	}
	return false
}

// Target is the subject under test. Locked fields (Client, Hints) + additive
// entry-point, discovery, and credential fields.
type Target struct {
	MCPURL string // --target: walk the agent loop from here
	Issuer string // --issuer: enter directly at the AS

	Client *http.Client      // locked
	Hints  map[string]string // locked; carries discovered metadata for offline review

	Discovered Discovered // resolved during the discovery phase
	Creds      Creds
	Plan       AuthPlan // resolved after discovery (see resolve.go)

	ctx context.Context
}

// Context returns the target's context (defaults to Background).
func (t *Target) Context() context.Context {
	if t.ctx == nil {
		return context.Background()
	}
	return t.ctx
}

func (t *Target) httpClient() *http.Client {
	if t.Client != nil {
		return t.Client
	}
	return http.DefaultClient
}

// clientAuth applies the resolved client authentication method to a token
// request form and returns any headers to merge into the request (e.g. an
// Authorization: Basic header for client_secret_basic; nil for post).
func (t *Target) clientAuth(form url.Values) http.Header {
	return probe.ApplyClientAuth(form, t.Plan.TokenAuthMethod, t.Plan.ClientID, t.Plan.ClientSecret)
}
