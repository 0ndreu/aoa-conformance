package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
)

// ClientDoc is a locally hosted Client-ID Metadata Document. Under CIMD the
// client_id IS this document's URL; an AS that supports CIMD fetches it to learn
// the client instead of requiring prior registration.
type ClientDoc struct {
	URL     string
	fetched int32
	srv     *http.Server
}

// Fetched reports whether the document has been requested at least once.
func (d *ClientDoc) Fetched() bool { return atomic.LoadInt32(&d.fetched) == 1 }

// Close shuts down the hosting server.
func (d *ClientDoc) Close() {
	if d.srv != nil {
		_ = d.srv.Close()
	}
}

// HostClientDoc serves a minimal client-metadata document on a loopback address.
// redirectURI is declared in the document so an AS that validates redirect_uris
// against the fetched metadata accepts the probe's authorization request.
func HostClientDoc(redirectURI string) (*ClientDoc, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	d := &ClientDoc{}
	d.URL = fmt.Sprintf("http://%s/client-metadata.json", ln.Addr().String())
	body, _ := json.Marshal(map[string]any{
		"client_id":                  d.URL,
		"client_name":                "aoa-conform CIMD probe",
		"redirect_uris":              []string{redirectURI},
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/client-metadata.json", func(w http.ResponseWriter, _ *http.Request) {
		atomic.StoreInt32(&d.fetched, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	})
	d.srv = &http.Server{Handler: mux}
	go d.srv.Serve(ln)
	return d, nil
}

// CIMDResult classifies an AS's immediate response to a URL (CIMD) client_id.
type CIMDResult struct {
	Rejected bool // AS returned invalid_client / unauthorized_client
	Status   int
	Evidence []byte
}

// ProbeCIMDAuthorize sends an authorization request whose client_id is the CIMD
// document URL and classifies the immediate (non-followed) response. A response
// carrying invalid_client / unauthorized_client is a rejection; anything else
// (a redirect to login or an issued code) means the AS accepted the URL client_id.
func ProbeCIMDAuthorize(ctx context.Context, c *http.Client, authorizationEndpoint, clientDocURL, redirectURI string) (CIMDResult, error) {
	_, challenge := NewPKCE()
	q := url.Values{}
	q.Set("client_id", clientDocURL)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", "openid")
	q.Set("state", randHex(16))
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	full := authorizationEndpoint + "?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return CIMDResult{}, err
	}
	nc := *c
	nc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := nc.Do(req)
	if err != nil {
		return CIMDResult{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	loc := resp.Header.Get("Location")
	hay := string(body) + " " + loc
	rejected := strings.Contains(hay, "invalid_client") || strings.Contains(hay, "unauthorized_client")
	ev := []byte(fmt.Sprintf("GET %s\nHTTP %d\nLocation: %s\nbody: %s", full, resp.StatusCode, loc, body))
	return CIMDResult{Rejected: rejected, Status: resp.StatusCode, Evidence: ev}, nil
}
