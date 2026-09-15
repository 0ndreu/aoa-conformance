package fakeas

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"

	"github.com/0ndreu/aoa-conformance/probe"
)

// Violations toggles individual spec violations. Zero value = fully correct AS.
type Violations struct {
	IgnoreMayAct        bool // accept delegation even when actor not in may_act
	ForgeActChain       bool // do not nest the subject's existing act
	AcceptPlainPKCE     bool // advertise/accept plain instead of requiring S256
	SkipDPoPNonce       bool // never challenge use_dpop_nonce
	AcceptWrongHTU      bool // accept a DPoP proof whose htu != token endpoint
	MalformedDiscovery  bool // emit a discovery doc with the wrong issuer
	NoTokenExchange     bool // do not advertise/accept token-exchange (capability absent)
	NoDPoP              bool // do not advertise DPoP (capability absent)
	BadErrorShape       bool // emit non-RFC6749 error bodies
	IgnoreResourceParam bool // ignore RFC 8707 resource (don't reflect audience)
	NoCnfBinding        bool // issue a DPoP token without binding cnf.jkt

	AcceptUnknownGrant       bool // return a token for an unknown/unsupported grant_type
	RejectResource           bool // reject (invalid_target) any request carrying a resource
	ErrorOnMultipleResources bool // 500 when more than one resource param is present
	FailImpersonation        bool // reject impersonation (no actor_token) with 400
	RejectDelegation         bool // reject delegation (actor_token present) with 400
	OmitAct                  bool // omit the act claim entirely from a delegation token
	WidenScope               bool // echo a broader scope than requested
	AcceptBadSubject         bool // skip subject_token verification (accept garbage)
	RejectValidDPoP          bool // reject a valid DPoP proof with invalid_dpop_proof

	NoIntrospection    bool // do not advertise/serve introspection_endpoint
	IntrospectInactive bool // always report active:false (buggy AS)

	NoRevocation   bool // do not advertise/serve revocation_endpoint
	DeadRevocation bool // advertise a revocation_endpoint whose path 404s
	IgnoreRevoke   bool // accept the revoke request but keep the token active

	NoRegistration          bool // do not advertise/serve registration_endpoint
	RejectRegistration      bool // advertise registration_endpoint but reject every request
	RegistrationRequiresIAT bool // 401 unless an initial access token is presented
	MangleApplicationType   bool // echo a different application_type than requested (SEP-837)
	ForeignRegistrationURI  bool // return a registration_client_uri on a different origin than the issuer (SEP-2352)
	NoClientConfigEndpoint  bool // return neither registration_client_uri nor registration_access_token (both optional in RFC 7591)

	RequirePAR    bool // advertise require_pushed_authorization_requests
	NoPAREndpoint bool // advertise require_pushed_authorization_requests but omit the endpoint

	AdvertiseMTLS  bool // advertise tls_client_certificate_bound_access_tokens + aliases
	IncoherentMTLS bool // advertise the bound flag but omit mtls_endpoint_aliases

	EmitSignedMetadata bool // include a JWT signed_metadata in discovery
	BadSignedMetadata  bool // sign signed_metadata with a throwaway key (invalid)

	PublicClientsOnly      bool // advertise only token_endpoint_auth_method "none"; DCR issues no secret
	NoClientCredentials    bool // do not advertise, and reject, the client_credentials grant
	NoGrantTypesAdvertised bool // omit grant_types_supported from discovery entirely (RFC 8414 permits this; the AS may still not support client_credentials)

	IssParamSupported bool // advertise authorization_response_iss_parameter_supported

	AdvertiseCIMD    bool // advertise client_id_metadata_document_supported
	RejectCIMDClient bool // advertise CIMD but reject a URL client_id at /authorize
}

// AS is a controllable fake authorization server.
type AS struct {
	*httptest.Server
	v      Violations
	signer *probe.Signer

	mu               sync.Mutex
	minted           int // serial number handed to every issued token, so no two are byte-identical
	lastForm         url.Values
	lastClientAuth   string
	lastPARForm      url.Values
	lastRegistration map[string]any
	deletedClients   []string
	revoked          map[string]bool
}

// LastRegistration returns the JSON body of the most recent /register request,
// so tests can assert what the client asked to be registered as.
func (as *AS) LastRegistration() map[string]any {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.lastRegistration
}

// LastPARForm returns the form values of the most recent /par request, so tests
// can assert which parameters were pushed.
func (as *AS) LastPARForm() url.Values {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.lastPARForm
}

// LastClientAuthMethod reports how the most recent /token request authenticated
// the client: "client_secret_basic", "client_secret_post", or "" (none).
func (as *AS) LastClientAuthMethod() string {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.lastClientAuth
}

// LastTokenForm returns the form values of the most recent /token request, so
// tests can assert which parameters (e.g. scope) the client sent.
func (as *AS) LastTokenForm() url.Values {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.lastForm
}

func NewAS(v Violations) *AS {
	signer, err := probe.NewSigner()
	if err != nil {
		panic(err)
	}
	as := &AS{v: v, signer: signer, revoked: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", as.handleDiscovery)
	mux.HandleFunc("/jwks", as.handleJWKS)
	mux.HandleFunc("/token", as.handleToken)
	mux.HandleFunc("/register", as.handleRegister)
	mux.HandleFunc("/register/", as.handleClientConfig)
	mux.HandleFunc("/authorize", as.handleAuthorize)
	mux.HandleFunc("/par", as.handlePAR)
	mux.HandleFunc("/introspect", as.handleIntrospect)
	mux.HandleFunc("/revoke", as.handleRevoke)
	as.Server = httptest.NewServer(mux)
	return as
}

// MintToken signs a token with the AS's key (use it to build subject/actor tokens).
// Every token gets a distinct jti unless the caller pinned one: a real AS never
// hands out the same token string twice, and identical strings would let one
// check's revocation invalidate the token another check obtains later.
func (as *AS) MintToken(claims map[string]any) string {
	if claims["iss"] == nil {
		claims["iss"] = as.URL
	}
	if claims["jti"] == nil {
		as.mu.Lock()
		as.minted++
		claims["jti"] = fmt.Sprintf("tok-%d", as.minted)
		as.mu.Unlock()
	}
	t, err := as.signer.SignJWT(claims)
	if err != nil {
		panic(err)
	}
	return t
}

// SignerJWKS returns the AS signing key's public JWKS (for clients that must
// validate tokens this AS minted).
func (as *AS) SignerJWKS() []byte { return as.signer.PublicJWKS() }

func (as *AS) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	issuer := as.URL
	if as.v.MalformedDiscovery {
		issuer = "https://wrong-issuer.example" // violates RFC 8414 issuer-match
	}
	grants := []string{"authorization_code"}
	if !as.v.NoClientCredentials {
		grants = append(grants, "client_credentials")
	}
	if !as.v.NoTokenExchange {
		grants = append(grants, probe.GrantTokenExchange)
	}
	pkce := []string{"S256"}
	if as.v.AcceptPlainPKCE {
		pkce = []string{"plain", "S256"}
	}
	doc := map[string]any{
		"issuer":                           issuer,
		"token_endpoint":                   as.URL + "/token",
		"authorization_endpoint":           as.URL + "/authorize",
		"jwks_uri":                         as.URL + "/jwks",
		"code_challenge_methods_supported": pkce,
	}
	if !as.v.NoGrantTypesAdvertised {
		doc["grant_types_supported"] = grants
	}
	if !as.v.NoDPoP {
		doc["dpop_signing_alg_values_supported"] = []string{"ES256"}
	}
	if !as.v.NoRegistration {
		doc["registration_endpoint"] = as.URL + "/register"
	}
	doc["token_endpoint_auth_methods_supported"] = []string{"client_secret_basic", "client_secret_post"}
	if as.v.PublicClientsOnly {
		doc["token_endpoint_auth_methods_supported"] = []string{"none"}
	}
	if as.v.RequirePAR {
		doc["require_pushed_authorization_requests"] = true
		if !as.v.NoPAREndpoint {
			doc["pushed_authorization_request_endpoint"] = as.URL + "/par"
		}
	}
	if as.v.AdvertiseMTLS || as.v.IncoherentMTLS {
		doc["tls_client_certificate_bound_access_tokens"] = true
		if !as.v.IncoherentMTLS {
			doc["mtls_endpoint_aliases"] = map[string]any{"token_endpoint": as.URL + "/mtls/token"}
		}
	}
	if as.v.EmitSignedMetadata || as.v.BadSignedMetadata {
		signer := as.signer
		if as.v.BadSignedMetadata {
			signer, _ = probe.NewSigner() // different key than jwks_uri serves
		}
		sm, _ := signer.SignJWT(map[string]any{"issuer": issuer, "token_endpoint": as.URL + "/token"})
		doc["signed_metadata"] = sm
	}
	if !as.v.NoIntrospection {
		doc["introspection_endpoint"] = as.URL + "/introspect"
	}
	if !as.v.NoRevocation {
		doc["revocation_endpoint"] = as.URL + "/revoke"
	}
	if as.v.IssParamSupported {
		doc["authorization_response_iss_parameter_supported"] = true
	}
	if as.v.AdvertiseCIMD {
		doc["client_id_metadata_document_supported"] = true
	}
	writeJSON(w, 200, doc)
}

func (as *AS) handlePAR(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	as.mu.Lock()
	as.lastPARForm = r.Form
	as.mu.Unlock()
	writeJSON(w, 201, map[string]any{
		"request_uri": "urn:ietf:params:oauth:request_uri:fake-123",
		"expires_in":  90,
	})
}

func (as *AS) handleRegister(w http.ResponseWriter, r *http.Request) {
	if as.v.RegistrationRequiresIAT && r.Header.Get("Authorization") == "" {
		as.tokenError(w, 401, "invalid_token", "initial access token required")
		return
	}
	var req map[string]any
	if body, _ := io.ReadAll(r.Body); len(body) > 0 {
		_ = json.Unmarshal(body, &req)
	}
	as.mu.Lock()
	as.lastRegistration = req
	as.mu.Unlock()
	if as.v.RejectRegistration {
		as.tokenError(w, 400, "invalid_client_metadata", "registration refused")
		return
	}
	resp := map[string]any{
		"client_id":                  "dcr-client",
		"client_secret":              "dcr-secret",
		"registration_access_token":  "rat-123",
		"registration_client_uri":    as.URL + "/register/dcr-client",
		"token_endpoint_auth_method": "client_secret_post",
	}
	if as.v.PublicClientsOnly {
		delete(resp, "client_secret")
		resp["token_endpoint_auth_method"] = "none"
	}
	if at, ok := req["application_type"].(string); ok && at != "" {
		if as.v.MangleApplicationType {
			resp["application_type"] = "web" // buggy AS: rewrites the declared type
		} else {
			resp["application_type"] = at
		}
	}
	if as.v.ForeignRegistrationURI {
		resp["registration_client_uri"] = "https://evil.example/register/dcr-client"
	}
	if as.v.NoClientConfigEndpoint {
		delete(resp, "registration_client_uri")
		delete(resp, "registration_access_token")
	}
	writeJSON(w, 201, resp)
}

// handleClientConfig serves the RFC 7591 §4 client-configuration endpoint this
// AS hands out as registration_client_uri. Only DELETE is implemented: it is
// the cleanup a run performs on the ephemeral client it registered.
func (as *AS) handleClientConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.WriteHeader(405)
		return
	}
	if r.Header.Get("Authorization") != "Bearer rat-123" {
		w.WriteHeader(401)
		return
	}
	as.mu.Lock()
	as.deletedClients = append(as.deletedClients, strings.TrimPrefix(r.URL.Path, "/register/"))
	as.mu.Unlock()
	w.WriteHeader(204)
}

// DeletedClients returns the client ids deleted through the client-configuration
// endpoint, so a test can assert the run cleaned up after itself.
func (as *AS) DeletedClients() []string {
	as.mu.Lock()
	defer as.mu.Unlock()
	return append([]string(nil), as.deletedClients...)
}

// handleAuthorize is a minimal authorization endpoint. It accepts a URL
// client_id (CIMD) only when this AS advertises CIMD and can fetch the document;
// otherwise it redirects back with invalid_client. A conventional client_id is
// accepted unconditionally. It never renders a login page; it redirects.
func (as *AS) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirect := q.Get("redirect_uri")
	state := q.Get("state")
	if strings.HasPrefix(clientID, "http://") || strings.HasPrefix(clientID, "https://") {
		if !as.v.AdvertiseCIMD {
			redirectAuth(w, redirect, "error=invalid_client", state)
			return
		}
		resp, err := http.Get(clientID) // fetch the client-metadata document
		if err == nil {
			defer resp.Body.Close()
		}
		if err != nil || resp.StatusCode != 200 {
			redirectAuth(w, redirect, "error=invalid_client", state)
			return
		}
		if as.v.RejectCIMDClient {
			redirectAuth(w, redirect, "error=invalid_client", state)
			return
		}
	}
	redirectAuth(w, redirect, "code=fake-code", state)
}

// redirectAuth writes a 302 back to redirect with the given query fragment and state.
func redirectAuth(w http.ResponseWriter, redirect, kv, state string) {
	loc := redirect + "?" + kv + "&state=" + url.QueryEscape(state)
	w.Header().Set("Location", loc)
	w.WriteHeader(302)
}

func (as *AS) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(as.signer.PublicJWKS())
}

func (as *AS) handleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	method := ""
	if _, _, ok := r.BasicAuth(); ok {
		method = "client_secret_basic"
	} else if r.Form.Get("client_secret") != "" {
		method = "client_secret_post"
	}
	as.mu.Lock()
	as.lastForm = r.Form
	as.lastClientAuth = method
	as.mu.Unlock()

	// DPoP handling (RFC 9449): if a DPoP proof is present, run the nonce
	// challenge + htu verification and compute the cnf.jkt to bind.
	dpop := false
	jkt := ""
	if proof := r.Header.Get("DPoP"); proof != "" {
		dpop = true
		jktVal, ok := as.handleDPoP(w, r, proof)
		if !ok {
			return // handleDPoP already wrote the error / nonce challenge.
		}
		jkt = jktVal
	}

	switch r.Form.Get("grant_type") {
	case probe.GrantTokenExchange:
		as.handleExchange(w, r, dpop, jkt)
	case "client_credentials":
		if as.v.NoClientCredentials {
			as.tokenError(w, 400, "unsupported_grant_type", "client_credentials not supported")
			return
		}
		as.handleClientCredentials(w, r, dpop, jkt)
	case "refresh_token":
		as.handleRefresh(w, r, dpop, jkt)
	default:
		if as.v.AcceptUnknownGrant {
			writeJSON(w, 200, map[string]any{"access_token": as.MintToken(map[string]any{"sub": "unknown-grant"}), "token_type": "Bearer"})
			return
		}
		as.tokenError(w, 400, "unsupported_grant_type", "unsupported grant")
	}
}

// handleDPoP validates the DPoP proof for the token request. It returns the
// proof key's RFC 7638 thumbprint and ok=true on success; on failure (nonce
// challenge or invalid proof) it writes the response and returns ok=false.
func (as *AS) handleDPoP(w http.ResponseWriter, r *http.Request, proof string) (string, bool) {
	p, err := parseDPoPProof([]byte(proof))
	if err != nil {
		as.tokenError(w, 400, "invalid_dpop_proof", "cannot parse DPoP proof: "+err.Error())
		return "", false
	}

	// nonce challenge on first contact unless disabled.
	if !as.v.SkipDPoPNonce && p.nonce == "" {
		w.Header().Set("DPoP-Nonce", dpopNonce)
		as.tokenError(w, 400, "use_dpop_nonce", "authorization server requires nonce in DPoP proof")
		return "", false
	}

	// htu must match the token endpoint unless the violation disables the check.
	if !as.v.AcceptWrongHTU && p.htu != as.URL+"/token" {
		as.tokenError(w, 400, "invalid_dpop_proof", "htu mismatch")
		return "", false
	}

	// buggy AS: reject even a valid proof.
	if as.v.RejectValidDPoP {
		as.tokenError(w, 400, "invalid_dpop_proof", "DPoP proof rejected")
		return "", false
	}

	return p.jkt, true
}

func (as *AS) handleClientCredentials(w http.ResponseWriter, r *http.Request, dpop bool, jkt string) {
	if resources := r.Form["resource"]; len(resources) > 0 {
		if as.v.RejectResource {
			as.tokenError(w, 400, "invalid_target", "resource parameter rejected")
			return
		}
		if as.v.ErrorOnMultipleResources && len(resources) > 1 {
			as.tokenError(w, 500, "server_error", "cannot handle multiple resources")
			return
		}
	}
	claims := map[string]any{"sub": r.Form.Get("client_id")}
	// RFC 8707 resource reflection (unless the violation disables it).
	if resources := r.Form["resource"]; len(resources) > 0 && !as.v.IgnoreResourceParam {
		if len(resources) == 1 {
			claims["aud"] = resources[0]
		} else {
			claims["aud"] = resources
		}
	}
	as.bindCnf(claims, dpop, jkt)
	writeJSON(w, 200, map[string]any{"access_token": as.MintToken(claims), "token_type": as.tokenType(dpop)})
}

// handleRefresh issues a token for a refresh_token grant, echoing the requested
// scope. WidenScope makes it echo a broader scope than requested (a violation).
func (as *AS) handleRefresh(w http.ResponseWriter, r *http.Request, dpop bool, jkt string) {
	scope := r.Form.Get("scope")
	if as.v.WidenScope && scope != "" {
		scope = scope + " extra.scope"
	}
	claims := map[string]any{"sub": "refresh-sub"}
	as.bindCnf(claims, dpop, jkt)
	out := map[string]any{"access_token": as.MintToken(claims), "token_type": as.tokenType(dpop)}
	if scope != "" {
		out["scope"] = scope
	}
	writeJSON(w, 200, out)
}

// bindCnf binds the DPoP proof key thumbprint into the issued token's cnf.jkt,
// unless the NoCnfBinding violation is set.
func (as *AS) bindCnf(claims map[string]any, dpop bool, jkt string) {
	if dpop && !as.v.NoCnfBinding {
		claims["cnf"] = map[string]any{"jkt": jkt}
	}
}

func (as *AS) tokenType(dpop bool) string {
	if dpop {
		return "DPoP"
	}
	return "Bearer"
}

func (as *AS) handleExchange(w http.ResponseWriter, r *http.Request, dpop bool, jkt string) {
	if as.v.NoTokenExchange {
		as.tokenError(w, 400, "unsupported_grant_type", "token exchange not supported")
		return
	}
	actorTok := r.Form.Get("actor_token")
	// FailImpersonation: reject impersonation (no actor_token) outright.
	if as.v.FailImpersonation && actorTok == "" {
		as.tokenError(w, 400, "invalid_request", "impersonation refused")
		return
	}
	// RejectDelegation: reject delegation (actor_token present) outright.
	if as.v.RejectDelegation && actorTok != "" {
		as.tokenError(w, 400, "invalid_request", "delegation refused")
		return
	}

	subjectTok := r.Form.Get("subject_token")
	subject, err := as.signer.Verify(subjectTok)
	if err != nil && !as.v.AcceptBadSubject {
		as.tokenError(w, 400, "invalid_grant", "bad subject_token")
		return
	}
	sub := "alice"
	if subject != nil && subject["sub"] != nil {
		sub = subject["sub"].(string)
	}
	if subject == nil {
		subject = map[string]any{}
	}
	out := map[string]any{"sub": sub}

	if actorTok != "" {
		actor, err := as.signer.Verify(actorTok)
		if err != nil {
			as.tokenError(w, 400, "invalid_grant", "bad actor_token")
			return
		}
		// may_act enforcement (unless the violation disables it).
		if !as.v.IgnoreMayAct {
			if ma, ok := subject["may_act"].(map[string]any); ok {
				if ma["sub"] != actor["sub"] {
					as.tokenError(w, 400, "invalid_grant", "actor not permitted by may_act")
					return
				}
			}
		}
		// act-chain assembly (unless forged or omitted).
		switch {
		case as.v.OmitAct:
			// emit no act claim at all
		case as.v.ForgeActChain:
			out["act"] = map[string]any{"sub": actor["sub"]} // drops any existing act
		default:
			act := map[string]any{"sub": actor["sub"]}
			if existing, ok := subject["act"].(map[string]any); ok {
				act["act"] = existing
			}
			out["act"] = act
		}
	}

	// RFC 8707 resource reflection.
	if res := r.Form.Get("resource"); res != "" && !as.v.IgnoreResourceParam {
		out["aud"] = res
	}

	as.bindCnf(out, dpop, jkt)
	issued := as.MintToken(out)
	resp := map[string]any{
		"access_token":      issued,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":        as.tokenType(dpop),
	}
	// scope handling: a correct AS echoes the requested (possibly narrower)
	// scope. WidenScope buggily returns a broader scope than requested.
	if reqScope := r.Form.Get("scope"); reqScope != "" {
		if as.v.WidenScope {
			resp["scope"] = reqScope + " write admin"
		} else {
			resp["scope"] = reqScope
		}
	}
	writeJSON(w, 200, resp)
}

func (as *AS) handleIntrospect(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	tok := r.Form.Get("token")
	_, err := as.signer.Verify(tok)
	active := err == nil && !as.isRevoked(tok) && !as.v.IntrospectInactive
	writeJSON(w, 200, map[string]any{"active": active})
}

func (as *AS) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if as.v.DeadRevocation {
		w.WriteHeader(404) // advertised in metadata, never deployed
		return
	}
	_ = r.ParseForm()
	if !as.v.IgnoreRevoke {
		as.revoke(r.Form.Get("token"))
	}
	w.WriteHeader(200) // RFC 7009 §2.2: 200 regardless
}

func (as *AS) isRevoked(tok string) bool {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.revoked[tok]
}

func (as *AS) revoke(tok string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.revoked[tok] = true
}

func (as *AS) tokenError(w http.ResponseWriter, code int, errc, desc string) {
	if as.v.BadErrorShape {
		w.WriteHeader(code)
		fmt.Fprintf(w, "error: %s", errc) // not JSON, violates RFC 6749 §5.2
		return
	}
	writeJSON(w, code, map[string]any{"error": errc, "error_description": desc})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
