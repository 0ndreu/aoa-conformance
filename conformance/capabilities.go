package conformance

import "strings"

// CapabilityState is the three-valued answer the whole report exists to give:
// the server offers this, the server does not offer this, or we could not tell
// because the operator withheld a credential.
type CapabilityState string

const (
	CapSupported    CapabilityState = "supported"
	CapNotSupported CapabilityState = "not supported"
	CapNotTested    CapabilityState = "not tested"
)

// Capability is one row of the support matrix: the summary a third-party
// developer reads before any of the per-RFC tables.
type Capability struct {
	Key    string          `json:"key"`
	Title  string          `json:"title"`
	State  CapabilityState `json:"state"`
	Reason string          `json:"reason"`
}

// capabilitySpec binds a matrix row to the checks that answer for it. Matching
// is by check-ID prefix so the row stays in step with the ID namespace: a new
// rfc8707.* check joins the resource-indicators row without an edit here.
type capabilitySpec struct {
	key      string
	title    string
	prefixes []string
}

// capabilitySpecs is the curated list — the capabilities a developer wiring an
// MCP server into an agent actually has to decide about. Not every registered
// check belongs to one; the per-RFC tables below the matrix carry the rest.
var capabilitySpecs = []capabilitySpec{
	{"prm-discovery", "PRM discovery (RFC 9728)", []string{"rfc9728.", "mcp.prm.", "mcp.challenge."}},
	{"as-metadata", "AS metadata (RFC 8414)", []string{"rfc8414.", "discovery"}},
	{"pkce-s256", "PKCE S256", []string{"pkce."}},
	{"resource-indicators", "Resource indicators (RFC 8707)", []string{"rfc8707."}},
	{"token-hygiene", "Resource-server token validation hygiene", []string{"mcp.token."}},
	{"cimd", "Client ID Metadata Documents", []string{"cimd."}},
	{"dcr", "Dynamic client registration", []string{"registration", "sep837.", "sep2352."}},
	{"dpop", "DPoP sender-constrained tokens (RFC 9449)", []string{"dpop."}},
	{"introspection", "Token introspection (RFC 7662)", []string{"rfc7662."}},
	{"revocation", "Token revocation (RFC 7009)", []string{"rfc7009."}},
	{"refresh-scope", "Refresh-token scope semantics (SEP-2207)", []string{"sep2207."}},
	{"step-up", "Step-up authorization (SEP-2350)", []string{"sep2350."}},
	{"mtls", "mTLS-bound tokens (RFC 8705)", []string{"rfc8705."}},
}

// Capabilities derives the support matrix from a report's entries. It is pure:
// the same entries always yield the same matrix, and a capability whose checks
// never ran reports "not tested" rather than being silently absent.
func Capabilities(entries []Entry) []Capability {
	out := make([]Capability, 0, len(capabilitySpecs))
	for _, spec := range capabilitySpecs {
		out = append(out, spec.resolve(entries))
	}
	return out
}

func (spec capabilitySpec) matches(id CheckID) bool {
	for _, p := range spec.prefixes {
		if strings.HasPrefix(string(id), p) {
			return true
		}
	}
	return false
}

// resolve weighs the matching entries with the same severity-aware rule the
// agent-compatibility verdicts use. "not supported" therefore covers both an
// absent capability and one broken at MUST level — the reason line names the
// check that decided it, so the reader can tell which.
func (spec capabilitySpec) resolve(entries []Entry) Capability {
	var matched []Entry
	for _, e := range entries {
		if spec.matches(e.Check.ID) {
			matched = append(matched, e)
		}
	}
	ev := weighEntries(matched)
	c := Capability{Key: spec.key, Title: spec.title}
	switch ev.status {
	case "met":
		c.State = CapSupported
		c.Reason = capReason(ev.decidedBy, "advertised and verified")
		if ev.advisory {
			c.Reason += "; a SHOULD/MAY-level shortfall is listed in the tables below"
		}
	case "unmet":
		c.State = CapNotSupported
		c.Reason = capReason(ev.decidedBy, "no check found it")
	default:
		c.State = CapNotTested
		c.Reason = capReason(ev.decidedBy, "no check for this capability ran in the selected profiles")
	}
	return c
}

// capReason names the deciding check and quotes its message, so every row of
// the matrix is traceable to a line of the tables underneath it.
func capReason(e *Entry, fallback string) string {
	if e == nil {
		return fallback
	}
	if e.Result.Message == "" {
		return string(e.Check.ID) + ": " + fallback
	}
	return string(e.Check.ID) + ": " + e.Result.Message
}
