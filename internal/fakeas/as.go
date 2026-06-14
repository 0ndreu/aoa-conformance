package fakeas

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

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
}

// AS is a controllable fake authorization server.
type AS struct {
	*httptest.Server
	v      Violations
	signer *probe.Signer
}

func NewAS(v Violations) *AS {
	signer, err := probe.NewSigner()
	if err != nil {
		panic(err)
	}
	as := &AS{v: v, signer: signer}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-authorization-server", as.handleDiscovery)
	mux.HandleFunc("/jwks", as.handleJWKS)
	mux.HandleFunc("/token", as.handleToken)
	as.Server = httptest.NewServer(mux)
	return as
}

// MintToken signs a token with the AS's key (use it to build subject/actor tokens).
func (as *AS) MintToken(claims map[string]any) string {
	if claims["iss"] == nil {
		claims["iss"] = as.URL
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
	grants := []string{"authorization_code", "client_credentials"}
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
		"grant_types_supported":            grants,
		"code_challenge_methods_supported": pkce,
	}
	if !as.v.NoDPoP {
		doc["dpop_signing_alg_values_supported"] = []string{"ES256"}
	}
	writeJSON(w, 200, doc)
}

func (as *AS) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write(as.signer.PublicJWKS())
}

func (as *AS) handleToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()

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
		as.handleClientCredentials(w, r, dpop, jkt)
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
