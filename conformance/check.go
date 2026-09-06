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
	// Profile2026_07 carries the authorization requirements the MCP 2026-07-28
	// specification made final: CIMD, issuer-bound credentials, iss validation,
	// application_type on DCR and the well-known suffix paths.
	Profile2026_07 Profile = "mcp-2026-07-28"
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

// SkipKind separates the two reasons a check produced no verdict. The
// distinction is the whole point of the report: "your server does not do this"
// is an answer, "we had no credential" is not.
type SkipKind string

const (
	// SkipUnsupported: the target does not advertise or offer the capability.
	// For the developer reading the report this IS the answer.
	SkipUnsupported SkipKind = "unsupported"
	// SkipUntested: a credential or flag the operator did not supply. Re-run
	// with it and the check will produce a verdict.
	SkipUntested SkipKind = "untested"
)

// SkipReason is what a precondition returns when it blocks a check: the kind
// of skip plus a sentence naming the missing capability or the missing flag.
type SkipReason struct {
	Kind SkipKind
	Text string
}

// Unsupported reports a capability the target does not offer. Text should name
// the metadata field or behaviour that is absent.
func Unsupported(text string) SkipReason { return SkipReason{Kind: SkipUnsupported, Text: text} }

// Untested reports an input the operator did not supply. Text should name the
// flag that would unlock the check.
func Untested(text string) SkipReason { return SkipReason{Kind: SkipUntested, Text: text} }

// satisfied is the zero SkipReason a gate returns when its requirement is met.
var satisfied = SkipReason{}

// gate is one requirement a check has of the target.
type gate func(*Target) SkipReason

// needs composes gates into a Precondition that reports the first unmet one.
// Order gates capability-first: when a check needs both a capability the server
// lacks and a credential the operator withheld, "not supported" is the answer
// worth printing.
func needs(gates ...gate) func(*Target) (bool, SkipReason) {
	return func(t *Target) (bool, SkipReason) {
		for _, g := range gates {
			if r := g(t); r.Text != "" {
				return false, r
			}
		}
		return true, satisfied
	}
}

// Check is one conformance probe. Locked schema shape + Profile.
type Check struct {
	ID          CheckID
	Profile     Profile
	RFC         string // "RFC 8693"
	Section     string // "§2.1"
	Severity    Severity
	Description string
	// Precondition gates the check. Nil means always run. When it returns
	// false the runner records StatusSkip carrying the returned SkipReason,
	// so the report says whether the capability is absent or untested.
	Precondition func(*Target) (bool, SkipReason)
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
	if c.Precondition != nil {
		if pass, why := c.Precondition(t); !pass {
			return Result{Status: StatusSkip, SkipKind: why.Kind, Message: why.Text}
		}
	}
	return c.Run(t)
}

// Result is the outcome of one check. Locked schema shape.
type Result struct {
	Status Status `json:"status"`
	// SkipKind is set only on StatusSkip and tells unsupported from untested.
	SkipKind SkipKind      `json:"skip_kind,omitempty"`
	Message  string        `json:"message"`
	Evidence []byte        `json:"evidence,omitempty"` // raw HTTP exchange / JSON for offline audit
	Duration time.Duration `json:"duration_ns"`
}

// Creds carries what the operator supplied that is not part of the resolved
// client identity: the client itself lives in AuthPlan, which is the single
// source every check reads.
type Creds struct {
	SubjectToken string   // a token the operator pasted in (--subject-token) or one an --auth-code round captured
	RefreshToken string   // captured from an interactive auth-code flow (SEP-2207)
	Scopes       []string // scopes to request when obtaining a token (--scope)

	AuthCodeAvailable bool // true after an interactive auth_code flow; gates pkce.enforce.reject_plain
	PresentEnabled    bool // set by CLI --present; gates the smoke check
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

	// RegisteredApplicationType is the application_type the AS echoed on DCR,
	// and RegistrationEvidence is the raw DCR exchange (SEP-837 / SEP-2352).
	RegisteredApplicationType string
	RegistrationEvidence      []byte
	// RegistrationError records why an attempted DCR failed. The runner turns
	// it into a first-class error entry: "we could not register" is a finding,
	// not something to leave the reader to infer from skipped checks.
	RegistrationError string
}

// hasClient reports whether the run has a client identity to act as. A public
// client — a client_id with no secret — counts: that is what real MCP servers
// issue, and OAuth 2.1 lets it drive authorization_code with PKCE.
func (p AuthPlan) hasClient() bool { return p.ClientID != "" }

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
	PRMResource                      string
	PRMAuthorizationServers          []string
	PRMScopesSupported               []string
	PRMBearerMethodsSupported        []string
	PRMDPoPBoundAccessTokensRequired bool
	// raw metadata documents, kept for evidence.
	RawASMetadata []byte
	RawPRM        []byte

	// MCPEra records whether the endpoint answered the unauthenticated MCP
	// call as a per-request-metadata ("modern") server, as an initialize-era
	// ("legacy") one, or never got far enough to say (an unauthenticated 401
	// arrives before the protocol layer).
	MCPEra               string
	MCPProtocolVersion   string
	MCPSupportedVersions []string

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
	ClientIDMetadataDocumentSupported          bool
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
