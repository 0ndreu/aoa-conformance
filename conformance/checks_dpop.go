package conformance

import (
	"net/http"
	"strings"

	"github.com/0ndreu/aoa-conformance/probe"
)

func registerDPoP(r *Registry) {
	needsDPoP := func(t *Target) bool {
		return t.Discovered.advertisesDPoP() && t.Plan.hasClient()
	}
	mk := func(id, section, desc string, sev Severity, pre func(*Target) bool, run func(*Target) Result) Check {
		return Check{ID: CheckID(id), Profile: ProfileExtended, RFC: "RFC 9449", Section: section,
			Severity: sev, Description: desc, Precondition: pre, Run: run}
	}

	r.Add(
		mk("dpop.advertise.algs", "§5.1", "DPoP signing algorithms are advertised", SeverityMAY,
			func(t *Target) bool { return t.Discovered.advertisesDPoP() },
			func(t *Target) Result {
				return Result{Status: StatusPass,
					Message: "DPoP algs advertised: " + strings.Join(t.Discovered.DPoPSigningAlgValuesSupported, ", ")}
			}),

		mk("dpop.token.accepts_proof", "§5", "a valid DPoP proof yields a token", SeverityMUST, needsDPoP,
			func(t *Target) Result {
				res := dpopExchange(t)
				if res.err != nil {
					return Result{Status: StatusError, Message: res.err.Error()}
				}
				if res.resp.StatusCode == 200 && res.resp.JSON()["access_token"] != nil {
					return Result{Status: StatusPass, Message: "DPoP-bound token issued", Evidence: res.resp.Evidence}
				}
				return Result{Status: StatusFail, Message: "valid DPoP proof rejected", Evidence: res.resp.Evidence}
			}),

		mk("dpop.token.nonce_challenge", "§5", "first proof without nonce is challenged with use_dpop_nonce", SeveritySHOULD, needsDPoP,
			func(t *Target) Result {
				key, err := probe.NewProofKey()
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
				}
				proof, err := key.Proof(probe.ProofParams{HTM: "POST", HTU: t.Discovered.TokenEndpoint})
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
				}
				resp, err := dpopPost(t, proof)
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
				}
				if resp.StatusCode == 400 && resp.JSON()["error"] == "use_dpop_nonce" && resp.Header.Get("DPoP-Nonce") != "" {
					return Result{Status: StatusPass, Message: "use_dpop_nonce challenge issued", Evidence: resp.Evidence}
				}
				return Result{Status: StatusFail, Message: "no use_dpop_nonce challenge on first contact", Evidence: resp.Evidence}
			}),

		mk("dpop.token.binds_cnf_jkt", "§5", "issued token's cnf.jkt equals the proof key thumbprint", SeverityMUST, needsDPoP,
			func(t *Target) Result {
				res := dpopExchange(t)
				if res.err != nil {
					return Result{Status: StatusError, Message: res.err.Error()}
				}
				if res.resp.StatusCode != 200 {
					return Result{Status: StatusFail, Message: "DPoP token request failed", Evidence: res.resp.Evidence}
				}
				tok, _ := res.resp.JSON()["access_token"].(string)
				claims := probe.DecodeJWTPayload(tok)
				jkt := cnfJKT(claims)
				if jkt == "" {
					return Result{Status: StatusFail, Message: "issued token has no cnf.jkt", Evidence: res.resp.Evidence}
				}
				if jkt != res.thumbprint {
					return Result{Status: StatusFail, Message: "cnf.jkt does not match proof key thumbprint", Evidence: res.resp.Evidence}
				}
				return Result{Status: StatusPass, Message: "cnf.jkt bound to proof key", Evidence: res.resp.Evidence}
			}),

		mk("dpop.token.rejects_wrong_htu", "§4.2", "a proof with a wrong htu is rejected", SeverityMUST, needsDPoP,
			func(t *Target) Result {
				key, err := probe.NewProofKey()
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
				}
				// first obtain the nonce via a normal challenge, then send a
				// proof carrying a tampered htu.
				nonce := dpopNonceFor(t, key)
				proof, err := key.Proof(probe.ProofParams{
					HTM: "POST", HTU: t.Discovered.TokenEndpoint,
					TamperHTU: "https://evil.example/token", Nonce: nonce,
				})
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
				}
				resp, err := dpopPost(t, proof)
				if err != nil {
					return Result{Status: StatusError, Message: err.Error()}
				}
				if resp.StatusCode == 200 {
					return Result{Status: StatusFail, Message: "wrong-htu proof accepted", Evidence: resp.Evidence}
				}
				return Result{Status: StatusPass, Message: "wrong-htu proof rejected", Evidence: resp.Evidence}
			}),
	)
}

type dpopResult struct {
	resp       *probe.Response
	thumbprint string
	err        error
}

// dpopExchange performs a client_credentials request with a valid DPoP proof,
// handling the use_dpop_nonce challenge with a single retry.
func dpopExchange(t *Target) dpopResult {
	key, err := probe.NewProofKey()
	if err != nil {
		return dpopResult{err: err}
	}
	tp, err := key.Thumbprint()
	if err != nil {
		return dpopResult{err: err}
	}
	proof, err := key.Proof(probe.ProofParams{HTM: "POST", HTU: t.Discovered.TokenEndpoint})
	if err != nil {
		return dpopResult{err: err}
	}
	resp, err := dpopPost(t, proof)
	if err != nil {
		return dpopResult{err: err}
	}
	if resp.StatusCode == 400 && resp.JSON()["error"] == "use_dpop_nonce" {
		nonce := resp.Header.Get("DPoP-Nonce")
		retry, err := key.Proof(probe.ProofParams{HTM: "POST", HTU: t.Discovered.TokenEndpoint, Nonce: nonce})
		if err != nil {
			return dpopResult{err: err}
		}
		resp, err = dpopPost(t, retry)
		if err != nil {
			return dpopResult{err: err}
		}
	}
	return dpopResult{resp: resp, thumbprint: tp}
}

// dpopNonceFor sends an initial proof (no nonce) to harvest the DPoP-Nonce the
// AS challenges with; returns "" if no challenge is issued.
func dpopNonceFor(t *Target, key *probe.ProofKey) string {
	proof, err := key.Proof(probe.ProofParams{HTM: "POST", HTU: t.Discovered.TokenEndpoint})
	if err != nil {
		return ""
	}
	resp, err := dpopPost(t, proof)
	if err != nil {
		return ""
	}
	return resp.Header.Get("DPoP-Nonce")
}

func dpopPost(t *Target, proof string) (*probe.Response, error) {
	form := probe.FormString("grant_type", "client_credentials")
	h := t.clientAuth(form)
	if h == nil {
		h = http.Header{}
	}
	h.Set("DPoP", proof)
	return probe.PostForm(t.Context(), t.httpClient(), t.Discovered.TokenEndpoint, form, h)
}

func cnfJKT(claims map[string]any) string {
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		return ""
	}
	jkt, _ := cnf["jkt"].(string)
	return jkt
}
