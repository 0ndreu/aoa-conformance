package fakeas

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/0ndreu/aoa-conformance/probe"
)

// RSViolations toggles resource-server discovery violations.
type RSViolations struct {
	OmitChallenge            bool // 401 without WWW-Authenticate resource_metadata
	OmitAuthorizationServers bool // PRM without authorization_servers
	AcceptAnyToken           bool // /mcp returns 200 for the --present smoke test
	MalformedPRM             bool // PRM document is invalid non-JSON
	UnresolvableAuthServer   bool // PRM lists an authorization server that does not resolve
	NoSuffixPRM              bool // do not serve the RFC 9728 suffix-inserted PRM path (SEP-2351)
	NonCanonicalResource     bool // PRM resource carries a fragment instead of the plain canonical URI
}

// RS is a fake MCP resource server: it emits the 401 + RFC 9728 PRM pointing at
// the given authorization server. It is intentionally hand-rolled (not aoa) so
// broken variants are possible; the real-aoa version lives in dogfood_test.go.
type RS struct {
	*httptest.Server
	asURL  string
	v      RSViolations
	Scopes []string // advertised in PRM scopes_supported (set before use)

	BearerMethods       []string // advertised in PRM bearer_methods_supported
	RequireBearerMethod string   // "" = accept any; else header|body|query
	RequireDPoP         bool     // advertise + enforce DPoP-bound presentation
	InsufficientScope   bool     // present path returns 403 instead of 200
}

func NewRS(asURL string, v RSViolations) *RS {
	rs := &RS{asURL: asURL, v: v}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", rs.handlePRM)
	if !v.NoSuffixPRM {
		// SEP-2351: PRM must also resolve at the suffix-inserted path for /mcp.
		mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", rs.handlePRM)
	}
	mux.HandleFunc("/mcp", rs.handleMCP)
	rs.Server = httptest.NewServer(mux)
	return rs
}

func (rs *RS) handlePRM(w http.ResponseWriter, _ *http.Request) {
	if rs.v.MalformedPRM {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("not json"))
		return
	}
	// the canonical resource identifier of an MCP server is the URI clients
	// call, path included — https://host/mcp, not the bare origin.
	resource := rs.URL + "/mcp"
	if rs.v.NonCanonicalResource {
		resource += "#mcp"
	}
	doc := map[string]any{"resource": resource}
	if !rs.v.OmitAuthorizationServers {
		as := rs.asURL
		if rs.v.UnresolvableAuthServer {
			as = "http://127.0.0.1:1" // closed port → RFC 8414 fetch yields no metadata
		}
		doc["authorization_servers"] = []string{as}
	}
	if len(rs.Scopes) > 0 {
		doc["scopes_supported"] = rs.Scopes
	}
	if len(rs.BearerMethods) > 0 {
		doc["bearer_methods_supported"] = rs.BearerMethods
	}
	if rs.RequireDPoP {
		doc["dpop_bound_access_tokens_required"] = true
	}
	writeJSON(w, 200, doc)
}

func (rs *RS) handleMCP(w http.ResponseWriter, r *http.Request) {
	token, ok := rs.extractToken(r)
	if !ok {
		rs.challenge(w, 401)
		return
	}
	// AcceptAnyToken models a resource that never validates what it is handed:
	// it authenticates a stranger's token exactly like one of its own.
	if !rs.v.AcceptAnyToken && !(rs.serves() && rs.issuedByOurAS(r, token)) {
		rs.challenge(w, 401)
		return
	}
	if rs.RequireDPoP && (r.Header.Get("DPoP") == "" || !strings.HasPrefix(r.Header.Get("Authorization"), "DPoP ")) {
		rs.challenge(w, 401)
		return
	}
	if rs.InsufficientScope {
		w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope"`)
		w.WriteHeader(403)
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// serves reports whether this RS is configured to behave like a working
// resource. An unconfigured RS rejects every request with 401.
func (rs *RS) serves() bool {
	return rs.RequireBearerMethod != "" || len(rs.BearerMethods) > 0 || rs.RequireDPoP || rs.InsufficientScope
}

// extractToken returns the token presented by the method this RS requires (or
// by any method when RequireBearerMethod is "").
func (rs *RS) extractToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if i := strings.IndexByte(header, ' '); i >= 0 {
		header = header[i+1:]
	}
	_ = r.ParseForm()
	body := r.PostForm.Get("access_token")
	query := r.URL.Query().Get("access_token")
	switch rs.RequireBearerMethod {
	case "header":
		return header, header != ""
	case "body":
		return body, body != ""
	case "query":
		return query, query != ""
	default:
		for _, t := range []string{header, body, query} {
			if t != "" {
				return t, true
			}
		}
		return "", false
	}
}

// issuedByOurAS is the check a real resource server performs and the reason a
// stranger's token gets a 401: the token must be signed by the authorization
// server this resource trusts, and must name it as issuer.
func (rs *RS) issuedByOurAS(r *http.Request, token string) bool {
	if probe.VerifyJWTWithJWKS(r.Context(), http.DefaultClient, token, rs.asURL+"/jwks") != nil {
		return false
	}
	iss, _ := probe.DecodeJWTPayload(token)["iss"].(string)
	return iss == rs.asURL
}

func (rs *RS) challenge(w http.ResponseWriter, code int) {
	if !rs.v.OmitChallenge {
		challenge := fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, rs.URL)
		if len(rs.Scopes) > 0 {
			challenge += fmt.Sprintf(`, scope="%s"`, strings.Join(rs.Scopes, " "))
		}
		w.Header().Set("WWW-Authenticate", challenge)
	}
	w.WriteHeader(code)
}
