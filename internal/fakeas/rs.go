package fakeas

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
)

// RSViolations toggles resource-server discovery violations.
type RSViolations struct {
	OmitChallenge            bool // 401 without WWW-Authenticate resource_metadata
	OmitAuthorizationServers bool // PRM without authorization_servers
	AcceptAnyToken           bool // /mcp returns 200 for the --present smoke test
	MalformedPRM             bool // PRM document is invalid non-JSON
	UnresolvableAuthServer   bool // PRM lists an authorization server that does not resolve
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
	doc := map[string]any{"resource": rs.URL}
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
	if rs.v.AcceptAnyToken && r.Header.Get("Authorization") != "" {
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	if rs.serves() && rs.extractToken(r) {
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
		return
	}
	rs.challenge(w, 401)
}

// serves reports whether this RS is configured to behave like a working
// resource. An unconfigured RS rejects every request with 401.
func (rs *RS) serves() bool {
	return rs.RequireBearerMethod != "" || len(rs.BearerMethods) > 0 || rs.RequireDPoP || rs.InsufficientScope
}

// extractToken reports whether a token was presented by the method this RS
// requires (or by any method when RequireBearerMethod is "").
func (rs *RS) extractToken(r *http.Request) bool {
	hasHeader := r.Header.Get("Authorization") != ""
	_ = r.ParseForm()
	hasBody := r.PostForm.Get("access_token") != ""
	hasQuery := r.URL.Query().Get("access_token") != ""
	switch rs.RequireBearerMethod {
	case "header":
		return hasHeader
	case "body":
		return hasBody
	case "query":
		return hasQuery
	default:
		return hasHeader || hasBody || hasQuery
	}
}

func (rs *RS) challenge(w http.ResponseWriter, code int) {
	if !rs.v.OmitChallenge {
		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource"`, rs.URL))
	}
	w.WriteHeader(code)
}
