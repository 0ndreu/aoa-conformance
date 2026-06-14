package conformance

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
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
	ClientID     string
	ClientSecret string
	UsePostAuth  bool   // client_secret_post vs client_secret_basic
	PrivateKey   []byte // RFC 7523 private_key_jwt (PEM/JWK); optional
	PrivateKeyAlg string
	SubjectToken string // supplied Tier-2 user token

	AuthCodeAvailable bool // true after an interactive auth_code flow; gates pkce.enforce.reject_plain
	PresentEnabled    bool // set by CLI --present; gates the smoke check
}

func (c Creds) hasClient() bool { return c.ClientID != "" && (c.ClientSecret != "" || c.PrivateKey != nil) }
func (c Creds) hasSubject() bool { return c.SubjectToken != "" }

// Discovered holds everything the discovery phase resolved.
type Discovered struct {
	Issuer                       string
	TokenEndpoint                string
	AuthorizationEndpoint        string
	JWKSURI                      string
	GrantTypesSupported          []string
	CodeChallengeMethodsSupported []string
	DPoPSigningAlgValuesSupported []string
	// PRM is the RFC 9728 Protected Resource Metadata (only set in --target mode).
	PRMAuthorizationServers []string
	// Raw metadata documents, kept for evidence.
	RawASMetadata  []byte
	RawPRM         []byte
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
